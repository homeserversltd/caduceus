#!/usr/bin/env python3
"""Publish the release binary identified by the CI commit SHA to Forgejo."""

import hashlib
import json
import os
import re
import sys
import tomllib
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

API = "https://git.home.arpa/api/v1"
OWNER = "HOMESERVERSLTD"
REPO = "caduceus"
SCHEMA = "caduceus.forgejo-release-publish.v2"
PROFILES = ("homeserver", "homeconsole", "tv", "probe")
LEGACY_ASSETS = frozenset({REPO + "-x86_64", REPO + "-x86_64.sha256"})
RELEASE_RETENTION_KEEP = 20


class ReleaseError(RuntimeError):
    pass


class ReleaseRetentionError(ReleaseError):
    def __init__(self, message, deleted, current=None):
        super().__init__(message)
        self.deleted = list(deleted)
        self.current = current


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


def release_tag(commit):
    """Return the release tag for a validated full commit SHA."""
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ReleaseError("CI_COMMIT_SHA-missing-or-invalid")
    return "sha-" + commit


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
        release.get("tag_name") != release_tag(commit)
        or release.get("name") != release_name
        or release.get("target_commitish") != commit
    ):
        raise ReleaseError("release-identity-mismatch")


def _release_created_at(release):
    value = release.get("created_at")
    if not isinstance(value, str):
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if result.tzinfo is None:
        return None
    return result


def eligible_release(release):
    """Accept only published sha releases whose target is that exact commit."""
    if not isinstance(release, dict) or release.get("draft") is not False:
        return False
    release_id = release.get("id")
    tag = release.get("tag_name")
    target = release.get("target_commitish")
    if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id < 0:
        return False
    if not isinstance(tag, str) or not re.fullmatch(r"sha-([0-9a-f]{40})", tag):
        return False
    if target != tag[4:] or _release_created_at(release) is None:
        return False
    return True


def list_all_releases(token):
    """Read every release with Forgejo's 50-item page cap and short-page stop."""
    base = "/repos/" + quote(OWNER, safe="") + "/" + quote(REPO, safe="")
    page = 1
    releases = []
    seen_ids = set()
    while True:
        status, batch = request(
            "GET", base + "/releases", token,
            query={"limit": 50, "page": page},
        )
        if status != 200 or not isinstance(batch, list):
            raise ReleaseError("release-retention-list-failed")
        for release in batch:
            if isinstance(release, dict):
                release_id = release.get("id")
                if isinstance(release_id, int) and not isinstance(release_id, bool):
                    if release_id in seen_ids:
                        raise ReleaseError("release-retention-page-duplicate")
                    seen_ids.add(release_id)
            releases.append(release)
        if len(batch) < 50:
            return releases
        page += 1


def _retention_plan_records(protected_release_id, token):
    """Return the public plan and private release records needed to execute it."""
    all_releases = list_all_releases(token)
    eligible = [release for release in all_releases if eligible_release(release)]
    eligible.sort(key=lambda release: (_release_created_at(release), release["id"]), reverse=True)
    by_id = {release["id"]: release for release in eligible}
    protected = by_id.get(protected_release_id)
    if protected is None:
        raise ReleaseError("release-retention-protected-release-ineligible")
    kept_ids = {release["id"] for release in eligible[:RELEASE_RETENTION_KEEP]}
    kept_ids.add(protected_release_id)
    kept = [release for release in eligible if release["id"] in kept_ids]
    deleted = [release for release in eligible if release["id"] not in kept_ids]
    plan = {
        "eligible_count": len(eligible),
        "kept_count": len(kept),
        "deleted_count": len(deleted),
        "kept": [{"id": release["id"], "tag": release["tag_name"]} for release in kept],
        "deleted": [{"id": release["id"], "tag": release["tag_name"]} for release in deleted],
    }
    return plan, deleted


def retention_plan(protected_release_id, token):
    """Return a read-only retention plan with no executable/private records."""
    plan, _ = _retention_plan_records(protected_release_id, token)
    return plan


def delete_release_and_tag(release, token, progress):
    """Delete only the eligible exact sha release and then prove its ref is gone."""
    release_id = release["id"]
    tag = release["tag_name"]
    commit = tag[4:]
    base = "/repos/" + quote(OWNER, safe="") + "/" + quote(REPO, safe="")
    tag_read_status, tag_record = request(
        "GET", base + "/tags/" + quote(tag, safe=""), token
    )
    progress["tag_precheck_status"] = tag_read_status
    if tag_read_status != 200 or tag_target(tag_record) != commit:
        raise ReleaseError("release-retention-tag-target-mismatch:" + tag)
    progress["tag_api_present"] = True
    progress["release_delete_attempted"] = True
    status, _ = request("DELETE", base + f"/releases/{release_id}", token)
    progress["release_delete_status"] = status
    if status not in (200, 204):
        raise ReleaseError("release-retention-release-delete-failed:" + tag)
    progress["release_deleted"] = True

    progress["tag_delete_attempted"] = True
    tag_delete_status, _ = request(
        "DELETE", base + "/tags/" + quote(tag, safe=""), token
    )
    progress["tag_delete_status"] = tag_delete_status
    if tag_delete_status not in (204, 404):
        raise ReleaseError("release-retention-tag-delete-failed:" + tag)
    ref_status, _ = request(
        "GET", base + "/git/refs/tags/" + quote(tag, safe=""), token
    )
    progress["tag_ref_read_status"] = ref_status
    if ref_status == 200:
        raise ReleaseError("release-retention-tag-ref-survives:" + tag)
    if ref_status != 404:
        raise ReleaseError("release-retention-tag-ref-readback-failed:" + tag)


def retain_releases(protected_release_id, token):
    plan, deleted_records = _retention_plan_records(protected_release_id, token)
    deleted = []
    current = None
    if deleted_records:
        try:
            for release in deleted_records:
                current = {
                    "id": release["id"],
                    "tag": release["tag_name"],
                    "release_delete_attempted": False,
                    "release_deleted": False,
                    "tag_precheck_status": None,
                    "release_delete_status": None,
                    "tag_delete_attempted": False,
                    "tag_delete_status": None,
                    "tag_ref_read_status": None,
                }
                delete_release_and_tag(release, token, current)
                deleted.append({"id": release["id"], "tag": release["tag_name"]})
                current = None
        except ReleaseError as exc:
            raise ReleaseRetentionError(str(exc), deleted, current) from exc
    return plan


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
    tag_name = release_tag(commit)
    encoded_tag = quote(tag_name, safe="")

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
                body={"tag_name": tag_name, "target": commit},
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
                "tag_name": tag_name,
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
        "tag": tag_name,
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
        if isinstance(exc, ReleaseRetentionError):
            receipt["retention"] = {
                "status": "partial",
                "deleted": exc.deleted,
                "deleted_count": len(exc.deleted),
                "current": exc.current,
            }
        code = 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
