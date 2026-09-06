#!/usr/bin/env python3
"""Publish the release binary identified by the CI commit SHA to Forgejo."""

import hashlib
import json
import os
import re
import sys
import tomllib
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

API = "https://git.home.arpa/api/v1"
OWNER = "HOMESERVERSLTD"
REPO = "caduceus"
SCHEMA = "caduceus.forgejo-release-publish.v2"
PROFILES = ("homeserver", "console", "tv", "probe")
LEGACY_ASSETS = frozenset({REPO + "-x86_64", REPO + "-x86_64.sha256"})


class ReleaseError(RuntimeError):
    pass


def request(method, path, token, *, body=None, data=None, query=None, binary=False):
    url = API + path
    if query:
        url += "?" + urlencode(query)
    headers = {
        "Accept": "application/octet-stream" if binary else "application/json",
        "Authorization": "token " + token,
    }
    payload = data
    if body is not None:
        payload = json.dumps(body, separators=(",", ":")).encode()
        headers["Content-Type"] = "application/json"
    elif data is not None:
        headers["Content-Type"] = "application/octet-stream"
    try:
        with urlopen(Request(url, data=payload, headers=headers, method=method), timeout=60) as response:
            content = response.read()
            if binary:
                return response.status, content
            if not content:
                return response.status, None
            try:
                return response.status, json.loads(content)
            except json.JSONDecodeError as exc:
                raise ReleaseError("forgejo-invalid-json-response") from exc
    except HTTPError as exc:
        return exc.code, None
    except (OSError, URLError, TimeoutError) as exc:
        raise ReleaseError("forgejo-transport-" + type(exc).__name__) from exc


def download(url, token):
    if not isinstance(url, str):
        raise ReleaseError("asset-download-url-invalid")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "git.home.arpa":
        raise ReleaseError("asset-download-url-invalid")
    try:
        with urlopen(
            Request(url, headers={
                "Accept": "application/octet-stream",
                "Authorization": "token " + token,
            }),
            timeout=60,
        ) as response:
            return response.status, response.read()
    except HTTPError as exc:
        return exc.code, None
    except (OSError, URLError, TimeoutError) as exc:
        raise ReleaseError("forgejo-transport-" + type(exc).__name__) from exc


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_identity(root, profile):
    try:
        metadata = json.loads((root / ".release" / profile / "cargo-metadata.json").read_text())
        cargo = tomllib.loads((root / "Cargo.toml").read_text())
    except (OSError, json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ReleaseError("build-metadata-read-" + type(exc).__name__) from exc

    package = cargo.get("package")
    toml_bins = cargo.get("bin")
    if not isinstance(package, dict) or not isinstance(toml_bins, list) or len(toml_bins) != 1:
        raise ReleaseError("cargo-toml-must-declare-one-binary")
    toml_bin = toml_bins[0]
    cargo_version = package.get("version")
    binary_name = toml_bin.get("name") if isinstance(toml_bin, dict) else None
    if not isinstance(cargo_version, str) or not cargo_version:
        raise ReleaseError("cargo-version-missing")
    if not isinstance(binary_name, str) or not binary_name:
        raise ReleaseError("cargo-binary-name-missing")

    packages = metadata.get("packages")
    target_directory = metadata.get("target_directory")
    if not isinstance(packages, list) or len(packages) != 1 or not isinstance(target_directory, str):
        raise ReleaseError("cargo-metadata-package-shape-invalid")
    metadata_package = packages[0]
    targets = metadata_package.get("targets", []) if isinstance(metadata_package, dict) else []
    binaries = [
        target for target in targets
        if isinstance(target, dict) and "bin" in target.get("kind", [])
    ]
    if (
        not isinstance(metadata_package, dict)
        or metadata_package.get("version") != cargo_version
        or len(binaries) != 1
        or binaries[0].get("name") != binary_name
    ):
        raise ReleaseError("cargo-metadata-does-not-match-one-binary")

    artifact = root / ".release" / f"caduceus-{profile}-x86_64"
    if not artifact.is_file():
        raise ReleaseError("release-binary-missing")
    return cargo_version, binary_name, artifact


def read_artifacts(root):
    expected = {}
    versions = set()
    for profile in PROFILES:
        cargo_version, binary_name, artifact = read_identity(root, profile)
        if binary_name != REPO:
            raise ReleaseError("cargo-binary-name-mismatch")
        versions.add(cargo_version)
        artifact_name = f"{REPO}-{profile}-x86_64"
        digest = sha256(artifact)
        expected[artifact_name] = {
            "profile": profile,
            "digest": digest,
            "content": artifact.read_bytes(),
        }
        expected[artifact_name + ".sha256"] = {
            "profile": profile,
            "digest": digest,
            "content": (digest + "  " + artifact_name + "\n").encode(),
        }
    if len(versions) != 1:
        raise ReleaseError("cargo-versions-differ-between-profiles")
    return versions.pop(), expected


def tag_target(tag):
    if not isinstance(tag, dict):
        return None
    commit = tag.get("commit")
    if isinstance(commit, dict):
        return commit.get("sha") or commit.get("id")
    return tag.get("sha") or tag.get("id") or tag.get("target")


def assets_by_name(assets):
    if not isinstance(assets, list):
        raise ReleaseError("release-assets-invalid")
    named = {}
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise ReleaseError("release-assets-invalid")
        name = asset["name"]
        if name in named:
            raise ReleaseError("release-assets-duplicate")
        named[name] = asset
    return named


def fetch_asset(asset, token):
    url = asset.get("browser_download_url") or asset.get("url")
    status, content = download(url, token)
    if status != 200 or not isinstance(content, bytes):
        raise ReleaseError("asset-download-failed")
    return content


def verify_asset_content(name, asset, wanted, token):
    content = fetch_asset(asset, token)
    if name.endswith(".sha256"):
        if content != wanted["content"]:
            raise ReleaseError("release-sidecar-mismatch")
    elif content != wanted["content"] or hashlib.sha256(content).hexdigest() != wanted["digest"]:
        raise ReleaseError("existing-release-digest-conflict")


def verify_present_assets(assets, expected, token):
    named = assets_by_name(assets)
    allowed = set(expected) | LEGACY_ASSETS | {"release.flag"}
    if not set(named) <= allowed:
        raise ReleaseError("release-assets-shape-mismatch")
    for name in set(named).intersection(expected):
        verify_asset_content(name, named[name], expected[name], token)
    return named


def verify_assets(assets, expected, token):
    named = verify_present_assets(assets, expected, token)
    if set(named) - {"release.flag"} != set(expected):
        raise ReleaseError("release-assets-shape-mismatch")
    return named


def release_assets(release_id, token):
    asset_status, assets = request(
        "GET", f"/repos/{quote(OWNER, safe='')}/{quote(REPO, safe='')}/releases/{release_id}/assets", token
    )
    if asset_status != 200:
        raise ReleaseError("release-assets-read-failed")
    return assets


def upload_asset(release_id, name, item, token):
    base = "/repos/" + quote(OWNER, safe="") + "/" + quote(REPO, safe="")
    status, _ = request(
        "POST", base + f"/releases/{release_id}/assets", token,
        data=item["content"], query={"name": name},
    )
    if status in (200, 201):
        return
    if status != 409:
        raise ReleaseError("asset-upload-failed")

    assets = release_assets(release_id, token)
    named = assets_by_name(assets)
    existing = named.get(name)
    if existing is None:
        raise ReleaseError("asset-upload-conflict-missing")
    if fetch_asset(existing, token) != item["content"]:
        raise ReleaseError("existing-release-digest-conflict")


def upload_assets(release_id, expected, token, present=None):
    names = set() if present is None else set(present)
    changed = False
    for name, item in expected.items():
        if name in names:
            continue
        upload_asset(release_id, name, item, token)
        names.add(name)
        changed = True
    return changed


def delete_legacy_assets(release_id, named, token):
    base = "/repos/" + quote(OWNER, safe="") + "/" + quote(REPO, safe="")
    changed = False
    for name in sorted(LEGACY_ASSETS):
        asset = named.get(name)
        if asset is None:
            continue
        asset_id = asset.get("id")
        if asset_id is None:
            raise ReleaseError("legacy-asset-id-invalid")
        status, _ = request(
            "DELETE", base + f"/releases/{release_id}/assets/{quote(str(asset_id), safe='')}", token,
        )
        if status not in (200, 204):
            raise ReleaseError("legacy-asset-delete-failed")
        changed = True
    return changed


def verify_release_identity(release, commit, release_name):
    if not isinstance(release, dict) or release.get("id") is None:
        raise ReleaseError("release-read-failed")
    if (
        release.get("tag_name") != commit
        or release.get("name") != release_name
        or release.get("target_commitish") != commit
    ):
        raise ReleaseError("release-identity-mismatch")


def publish(root, token):
    if os.environ.get("CI_REPO") not in (None, OWNER + "/" + REPO):
        raise ReleaseError("CI_REPO-mismatch")
    commit = os.environ.get("CI_COMMIT_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("CI_COMMIT_SHA-missing-or-invalid")
    if not token:
        raise ReleaseError("FORGEJO_TOKEN-missing")

    cargo_version, expected = read_artifacts(root)
    release_name = f"{REPO} {commit[:8]}"
    base = "/repos/" + quote(OWNER, safe="") + "/" + quote(REPO, safe="")
    encoded_tag = quote(commit, safe="")

    status, release = request("GET", base + "/releases/tags/" + encoded_tag, token)
    changed = False
    if status == 200:
        verify_release_identity(release, commit, release_name)
        tag_status, tag = request("GET", base + "/tags/" + encoded_tag, token)
        if tag_status != 200 or tag_target(tag) != commit:
            raise ReleaseError("tag-target-mismatch")
        release_id = release["id"]
        assets = release_assets(release_id, token)
        named = verify_present_assets(assets, expected, token)
        changed = upload_assets(release_id, expected, token, named)
        assets = release_assets(release_id, token)
        named = verify_present_assets(assets, expected, token)
        if not set(expected) <= set(named):
            raise ReleaseError("release-assets-shape-mismatch")
        changed = delete_legacy_assets(release_id, named, token) or changed
    elif status == 404:
        tag_status, tag = request("GET", base + "/tags/" + encoded_tag, token)
        if tag_status == 200:
            if tag_target(tag) != commit:
                raise ReleaseError("tag-conflicts-with-source-head")
        elif tag_status == 404:
            tag_status, _ = request(
                "POST", base + "/tags", token,
                body={"tag_name": commit, "target": commit},
            )
            if tag_status not in (200, 201):
                raise ReleaseError("tag-create-failed")
        else:
            raise ReleaseError("tag-read-failed")

        tag_status, tag = request("GET", base + "/tags/" + encoded_tag, token)
        if tag_status != 200 or tag_target(tag) != commit:
            raise ReleaseError("tag-target-mismatch-after-create")

        release_status, release = request(
            "POST", base + "/releases", token,
            body={
                "tag_name": commit,
                "name": release_name,
                "body": "caduceus release for " + commit,
                "target_commitish": commit,
                "draft": False,
                "prerelease": False,
            },
        )
        if release_status not in (200, 201):
            raise ReleaseError("release-create-failed")
        verify_release_identity(release, commit, release_name)
        release_id = release["id"]
        changed = upload_assets(release_id, expected, token)
    else:
        raise ReleaseError("release-read-failed")

    reread_status, reread_release = request(
        "GET", base + "/releases/tags/" + encoded_tag, token
    )
    if reread_status != 200:
        raise ReleaseError("release-reread-failed")
    verify_release_identity(reread_release, commit, release_name)
    tag_status, tag = request("GET", base + "/tags/" + encoded_tag, token)
    if tag_status != 200 or tag_target(tag) != commit:
        raise ReleaseError("tag-target-mismatch-after-upload")
    assets = release_assets(reread_release["id"], token)
    verify_assets(assets, expected, token)
    return {
        "schema": SCHEMA,
        "repository": OWNER + "/" + REPO,
        "cargo_version": cargo_version,
        "tag": commit,
        "name": release_name,
        "target_commitish": commit,
        "assets": list(expected),
        "sha256": {name: expected[name]["digest"] for name in expected if not name.endswith(".sha256")},
        "status": "published" if changed else "no-op",
        "changed": changed,
    }


def main():
    try:
        receipt = publish(
            Path(os.environ.get("CI_WORKSPACE", ".")).resolve(),
            os.environ.get("FORGEJO_TOKEN", ""),
        )
        code = 0
    except (OSError, ValueError, ReleaseError) as exc:
        receipt = {
            "schema": SCHEMA,
            "repository": OWNER + "/" + REPO,
            "status": "error",
            "changed": False,
            "error": str(exc),
        }
        code = 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
