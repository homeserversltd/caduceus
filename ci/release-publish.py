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
SCHEMA = "caduceus.forgejo-release-publish.v1"


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


def read_identity(root):
    try:
        metadata = json.loads((root / ".release/cargo-metadata.json").read_text())
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

    artifact = root / target_directory / "release" / binary_name
    if not artifact.is_file():
        raise ReleaseError("release-binary-missing")
    return cargo_version, binary_name, artifact


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
    return {
        asset.get("name"): asset
        for asset in assets
        if isinstance(asset, dict) and isinstance(asset.get("name"), str)
    }


def verify_assets(assets, artifact_name, sidecar_name, token, expected_digest=None):
    named = assets_by_name(assets)
    if artifact_name not in named or sidecar_name not in named:
        raise ReleaseError("release-assets-incomplete")

    def fetch(asset):
        url = asset.get("browser_download_url") or asset.get("url")
        status, content = download(url, token)
        if status != 200 or not isinstance(content, bytes):
            raise ReleaseError("asset-download-failed")
        return content

    remote_digest = hashlib.sha256(fetch(named[artifact_name])).hexdigest()
    if expected_digest is not None and remote_digest != expected_digest:
        raise ReleaseError("release-binary-digest-mismatch")
    expected_sidecar = (remote_digest + "  " + artifact_name + "\n").encode()
    if fetch(named[sidecar_name]) != expected_sidecar:
        raise ReleaseError("release-sidecar-mismatch")
    return remote_digest


def publish(root, token):
    if os.environ.get("CI_REPO") not in (None, OWNER + "/" + REPO):
        raise ReleaseError("CI_REPO-mismatch")
    commit = os.environ.get("CI_COMMIT_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("CI_COMMIT_SHA-missing-or-invalid")
    if not token:
        raise ReleaseError("FORGEJO_TOKEN-missing")

    cargo_version, binary_name, artifact = read_identity(root)
    artifact_name = binary_name + "-x86_64"
    sidecar_name = artifact_name + ".sha256"
    expected_digest = sha256(artifact)
    release_name = f"{binary_name} {commit[:8]}"
    base = "/repos/" + quote(OWNER, safe="") + "/" + quote(REPO, safe="")
    encoded_tag = quote(commit, safe="")

    status, release = request("GET", base + "/releases/tags/" + encoded_tag, token)
    if status == 200:
        if not isinstance(release, dict) or release.get("id") is None:
            raise ReleaseError("release-read-failed")
        tag_status, tag = request("GET", base + "/tags/" + encoded_tag, token)
        if tag_status != 200 or tag_target(tag) != commit:
            raise ReleaseError("tag-target-mismatch")
        if (
            release.get("tag_name") != commit
            or release.get("name") != release_name
            or release.get("target_commitish") != commit
        ):
            raise ReleaseError("release-identity-mismatch")
        asset_status, assets = request(
            "GET", base + f"/releases/{release['id']}/assets", token
        )
        if asset_status != 200:
            raise ReleaseError("release-assets-read-failed")
        remote_digest = verify_assets(assets, artifact_name, sidecar_name, token)
        if remote_digest != expected_digest:
            raise ReleaseError("existing-release-digest-conflict")
        return {
            "schema": SCHEMA,
            "repository": OWNER + "/" + REPO,
            "cargo_version": cargo_version,
            "tag": commit,
            "name": release_name,
            "target_commitish": commit,
            "assets": [artifact_name, sidecar_name],
            "sha256": remote_digest,
            "status": "no-op",
            "changed": False,
        }
    if status != 404:
        raise ReleaseError("release-read-failed")

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
    if release_status not in (200, 201) or not isinstance(release, dict) or release.get("id") is None:
        raise ReleaseError("release-create-failed")
    release_id = release["id"]

    for name, content in (
        (artifact_name, artifact.read_bytes()),
        (sidecar_name, (expected_digest + "  " + artifact_name + "\n").encode()),
    ):
        upload_status, _ = request(
            "POST", base + f"/releases/{release_id}/assets", token,
            data=content, query={"name": name},
        )
        if upload_status not in (200, 201):
            raise ReleaseError("asset-upload-failed")

    reread_status, reread_release = request(
        "GET", base + "/releases/tags/" + encoded_tag, token
    )
    if (
        reread_status != 200
        or not isinstance(reread_release, dict)
        or reread_release.get("id") is None
    ):
        raise ReleaseError("release-reread-failed")
    if (
        reread_release.get("tag_name") != commit
        or reread_release.get("name") != release_name
        or reread_release.get("target_commitish") != commit
    ):
        raise ReleaseError("release-identity-mismatch-after-upload")
    tag_status, tag = request("GET", base + "/tags/" + encoded_tag, token)
    if tag_status != 200 or tag_target(tag) != commit:
        raise ReleaseError("tag-target-mismatch-after-upload")
    asset_status, assets = request(
        "GET", base + f"/releases/{reread_release['id']}/assets", token
    )
    if asset_status != 200:
        raise ReleaseError("release-assets-reread-failed")
    verify_assets(assets, artifact_name, sidecar_name, token, expected_digest)
    return {
        "schema": SCHEMA,
        "repository": OWNER + "/" + REPO,
        "cargo_version": cargo_version,
        "tag": commit,
        "name": release_name,
        "target_commitish": commit,
        "assets": [artifact_name, sidecar_name],
        "sha256": expected_digest,
        "status": "published",
        "changed": True,
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
