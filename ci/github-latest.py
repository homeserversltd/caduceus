#!/usr/bin/env python3
"""Mirror the verified current Caduceus Forgejo Release to GitHub's latest tag."""

import argparse
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

FORGEJO_API = "https://git.home.arpa/api/v1"
FORGEJO_GIT_REMOTE = "https://git.home.arpa/HOMESERVERSLTD/caduceus.git"
GITHUB_API = "https://api.github.com"
GITHUB_UPLOADS = "https://uploads.github.com"
OWNER = "HOMESERVERSLTD"
REPO = "caduceus"
PROFILES = ("homeserver", "homeconsole", "tv", "probe")
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
GITHUB_ASSET_HOSTS = frozenset({
    "github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com",
})
MIRROR_TIMEOUT_SECONDS = 180
MIRROR_POLL_SECONDS = 3
REQUEST_TIMEOUT_SECONDS = 90


class PublishError(RuntimeError):
    """A source Release or remote API response violates this publisher's contract."""


def reject_duplicate_keys(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise PublishError("duplicate-json-key")
        record[key] = value
    return record


def decode_json(raw, label):
    try:
        return json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublishError(label + "-invalid-json") from exc


def valid_sha(value, pattern=HEX40):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def checked_https_url(url, allowed_hosts):
    if not isinstance(url, str):
        raise PublishError("asset-download-url-invalid")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise PublishError("asset-download-url-invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        raise PublishError("asset-download-url-invalid")
    return parsed


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubAssetRedirect(HTTPRedirectHandler):
    """Follow only HTTPS GitHub asset redirects, dropping auth across origins."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed_new = checked_https_url(newurl, GITHUB_ASSET_HOSTS)
        parsed_old = urlsplit(req.full_url)
        same_origin = (
            parsed_old.scheme == parsed_new.scheme
            and parsed_old.hostname == parsed_new.hostname
            and parsed_old.port in (None, 443)
            and parsed_new.port in (None, 443)
        )
        safe_headers = {
            key: value for key, value in req.headers.items()
            if key.lower() not in {"cookie", "proxy-authorization"}
            and (key.lower() != "authorization" or same_origin)
        }
        return Request(newurl, headers=safe_headers, method="GET")


def open_response(opener, request, label, timeout=60):
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(), response.headers
    except HTTPError as exc:
        return exc.code, b"", exc.headers
    except (OSError, URLError, TimeoutError) as exc:
        raise PublishError(label + "-transport-" + type(exc).__name__) from exc


class Clients:
    def __init__(self, forgejo_token, github_token):
        context = ssl.create_default_context()
        self.forgejo_token = forgejo_token
        self.github_token = github_token
        self.forgejo_push_mirrors_sync_http_status = None
        self.forgejo_opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
        self.github_opener = build_opener(NoRedirect(), HTTPSHandler(context=context))
        self.github_asset_opener = build_opener(
            GitHubAssetRedirect(), HTTPSHandler(context=context)
        )

    @staticmethod
    def _url(base, path, query=None):
        url = base + path
        if query:
            url += "?" + urlencode(query)
        return url

    def forgejo(self, method, path, *, body=None, binary=None):
        headers = {
            "Accept": "application/octet-stream" if binary else "application/json",
            "Authorization": "token " + self.forgejo_token,
            "User-Agent": "caduceus-github-latest/1.0",
        }
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(FORGEJO_API + path, data=payload, headers=headers, method=method)
        status, raw, _headers = open_response(self.forgejo_opener, request, "forgejo-api")
        value = raw if binary else (decode_json(raw, "forgejo-api") if raw and 200 <= status < 300 else None)
        return status, value

    def forgejo_asset(self, url):
        checked_https_url(url, frozenset({"git.home.arpa"}))
        request = Request(
            url,
            headers={
                "Accept": "application/octet-stream",
                "Authorization": "token " + self.forgejo_token,
                "User-Agent": "caduceus-github-latest/1.0",
            },
            method="GET",
        )
        status, raw, _headers = open_response(self.forgejo_opener, request, "forgejo-asset")
        if status != 200:
            raise PublishError("forgejo-asset-download-http-" + str(status))
        return raw

    def github(self, method, path, *, body=None, query=None, binary=None):
        headers = {
            "Accept": "application/vnd.github+json" if not binary else "application/octet-stream",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "caduceus-github-latest/1.0",
        }
        if self.github_token:
            headers["Authorization"] = "Bearer " + self.github_token
        payload = None
        if body is not None:
            payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(
            self._url(GITHUB_API, path, query), data=payload, headers=headers, method=method
        )
        status, raw, _headers = open_response(self.github_opener, request, "github-api")
        value = raw if binary else (decode_json(raw, "github-api") if raw and 200 <= status < 300 else None)
        return status, value

    def github_upload(self, release_id, name, content):
        path = f"/repos/{OWNER}/{REPO}/releases/{release_id}/assets"
        request = Request(
            self._url(GITHUB_UPLOADS, path, {"name": name}),
            data=content,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self.github_token,
                "Content-Type": "application/octet-stream",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "caduceus-github-latest/1.0",
            },
            method="POST",
        )
        status, raw, _headers = open_response(self.github_opener, request, "github-upload")
        value = decode_json(raw, "github-upload") if raw and 200 <= status < 300 else None
        return status, value

    def github_asset(self, asset):
        url = asset.get("browser_download_url") if isinstance(asset, dict) else None
        parsed = checked_https_url(url, frozenset({"github.com"}))
        headers = {
            "Accept": "application/octet-stream",
            "User-Agent": "caduceus-github-latest/1.0",
        }
        if self.github_token:
            headers["Authorization"] = "Bearer " + self.github_token
        request = Request(
            parsed.geturl(),
            headers=headers,
            method="GET",
        )
        status, raw, _headers = open_response(
            self.github_asset_opener, request, "github-asset"
        )
        if status == 404:
            return None
        if status != 200:
            raise PublishError("github-asset-download-http-" + str(status))
        return raw


def repo_path(suffix):
    return "/repos/" + quote(OWNER, safe="") + "/" + quote(REPO, safe="") + suffix


def github_release_asset_path(asset_id):
    return repo_path(f"/releases/assets/{asset_id}")


def forgejo_main_sha(clients):
    status, ref = clients.forgejo("GET", repo_path("/git/refs/heads/main"))
    if status != 200:
        raise PublishError("forgejo-main-ref-http-" + str(status))
    if isinstance(ref, list):
        matches = [
            item for item in ref
            if isinstance(item, dict) and item.get("ref") == "refs/heads/main"
        ]
        if len(matches) != 1:
            raise PublishError("forgejo-main-ref-invalid")
        ref = matches[0]
    value = ref.get("object") if isinstance(ref, dict) else None
    ref_name = ref.get("ref") if isinstance(ref, dict) else None
    if ref_name not in (None, "refs/heads/main") or not isinstance(value, dict) or value.get("type") != "commit":
        raise PublishError("forgejo-main-ref-invalid")
    sha = value.get("sha")
    if not isinstance(sha, str) or not valid_sha(sha):
        raise PublishError("forgejo-main-ref-invalid")
    return sha


def ref_record(clients, service, path):
    status, ref = clients.forgejo("GET", path) if service == "forgejo" else clients.github("GET", path)
    if status == 404:
        return None
    if status != 200:
        raise PublishError(service + "-git-ref-http-" + str(status))
    if isinstance(ref, list):
        wanted = "refs/tags/latest"
        matches = [item for item in ref if isinstance(item, dict) and item.get("ref") == wanted]
        if len(matches) != 1:
            raise PublishError(service + "-git-ref-shape-invalid")
        ref = matches[0]
    if (
        not isinstance(ref, dict)
        or ref.get("ref") not in (None, "refs/tags/latest")
        or not isinstance(ref.get("object"), dict)
    ):
        raise PublishError(service + "-git-ref-shape-invalid")
    return ref


def resolve_tag_object(clients, service, ref):
    if ref is None:
        return None
    value = ref.get("object")
    if not isinstance(value, dict):
        raise PublishError(service + "-git-ref-object-invalid")
    sha = value.get("sha")
    kind = value.get("type")
    for _depth in range(5):
        if not isinstance(sha, str) or not valid_sha(sha):
            raise PublishError(service + "-tag-object-sha-invalid")
        if kind == "commit":
            return sha
        if kind != "tag":
            raise PublishError(service + "-tag-object-type-invalid")
        path = repo_path("/git/tags/" + quote(sha, safe=""))
        status, record = clients.forgejo("GET", path) if service == "forgejo" else clients.github("GET", path)
        if status != 200 or not isinstance(record, dict):
            raise PublishError(service + "-annotated-tag-read-failed")
        target = record.get("object")
        if not isinstance(target, dict):
            raise PublishError(service + "-annotated-tag-target-invalid")
        sha, kind = target.get("sha"), target.get("type")
    raise PublishError(service + "-annotated-tag-depth-exceeded")


def forgejo_latest_ref(clients):
    path = repo_path("/git/refs/tags/latest")
    ref = ref_record(clients, "forgejo", path)
    return ref, resolve_tag_object(clients, "forgejo", ref)


def ensure_no_forgejo_latest_release(clients):
    status, release = clients.forgejo("GET", repo_path("/releases/tags/latest"))
    if status == 404:
        return
    if status == 200 and isinstance(release, dict):
        raise PublishError("forgejo-latest-release-must-not-exist")
    raise PublishError("forgejo-latest-release-guard-http-" + str(status))


def github_latest_ref(clients):
    path = repo_path("/git/ref/tags/latest")
    ref = ref_record(clients, "github", path)
    return ref, resolve_tag_object(clients, "github", ref)


def release_tag(commit):
    return "sha-" + commit


def read_forgejo_release(clients, commit):
    tag = release_tag(commit)
    encoded = quote(tag, safe="")
    status, release = clients.forgejo("GET", repo_path("/releases/tags/" + encoded))
    if status == 404:
        return None
    if status != 200 or not isinstance(release, dict):
        raise PublishError("forgejo-release-read-http-" + str(status))
    release_id = release.get("id")
    if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id <= 0:
        raise PublishError("forgejo-release-id-invalid")
    if (
        release.get("tag_name") != tag
        or release.get("name") != "caduceus " + commit[:8]
        or release.get("target_commitish") != commit
        or release.get("draft") is not False
        or release.get("prerelease") is not False
    ):
        raise PublishError("forgejo-release-identity-mismatch")
    tag_status, tag_record = clients.forgejo("GET", repo_path("/tags/" + encoded))
    if tag_status != 200 or not isinstance(tag_record, dict):
        raise PublishError("forgejo-native-tag-read-http-" + str(tag_status))
    target = tag_record.get("commit")
    target_sha = target.get("sha") if isinstance(target, dict) else None
    if target_sha != commit:
        raise PublishError("forgejo-native-tag-target-mismatch")
    return release


def assets_by_name(assets, service):
    if not isinstance(assets, list):
        raise PublishError(service + "-release-assets-invalid")
    named = {}
    ids = set()
    for asset in assets:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str):
            raise PublishError(service + "-release-assets-invalid")
        name = asset["name"]
        if name in named:
            raise PublishError(service + "-release-assets-duplicate-name")
        asset_id = asset.get("id")
        if isinstance(asset_id, bool) or not isinstance(asset_id, int) or asset_id <= 0:
            raise PublishError(service + "-release-asset-id-invalid")
        if asset_id in ids:
            raise PublishError(service + "-release-assets-duplicate-id")
        ids.add(asset_id)
        named[name] = asset
    return named


def fetch_forgejo_assets(clients, release_id):
    path = repo_path(f"/releases/{release_id}/assets")
    status, assets = clients.forgejo("GET", path)
    if status != 200:
        raise PublishError("forgejo-release-assets-http-" + str(status))
    named = assets_by_name(assets, "forgejo")
    result = {}
    for name, asset in named.items():
        url = asset.get("browser_download_url") or asset.get("url")
        result[name] = clients.forgejo_asset(url)
    return result


def validate_flag(raw, commit):
    flag = decode_json(raw, "release-flag")
    if not isinstance(flag, dict):
        raise PublishError("release-flag-not-object")
    required = ("schema", "component", "source_sha", "flagged_at", "pipeline_url", "sha256")
    if any(not isinstance(flag.get(key), str) or not flag[key] for key in required):
        raise PublishError("release-flag-required-field-invalid")
    if (
        flag.get("schema") != "estate.release-flag.v1"
        or flag.get("component") != REPO
        or flag.get("source_sha") != commit
        or not valid_sha(flag.get("sha256"), HEX64)
    ):
        raise PublishError("release-flag-identity-mismatch")
    if "env_sha" in flag and not valid_sha(flag["env_sha"], HEX64):
        raise PublishError("release-flag-env-sha-invalid")
    if "rustc_version" in flag and (
        not isinstance(flag["rustc_version"], str) or not flag["rustc_version"]
    ):
        raise PublishError("release-flag-rustc-version-invalid")
    return flag


def validate_manifest(raw, profile, commit, digest):
    manifest = decode_json(raw, "release-manifest")
    if not isinstance(manifest, dict):
        raise PublishError("release-manifest-not-object")
    if (
        manifest.get("schema") != "estate.artifact.manifest.v1"
        or manifest.get("component") != REPO
        or manifest.get("source_sha") != commit
        or manifest.get("target") != "x86_64-unknown-linux-gnu"
        or manifest.get("sha256") != digest
        or not valid_sha(manifest.get("env_sha"), HEX64)
        or not isinstance(manifest.get("rustc_version"), str)
        or not manifest["rustc_version"]
    ):
        raise PublishError("release-manifest-identity-mismatch-" + profile)
    return manifest


def expected_source_assets(clients, release, commit):
    assets = fetch_forgejo_assets(clients, release["id"])
    required = {"release.flag"}
    for profile in PROFILES:
        binary_name = f"{REPO}-{profile}-x86_64"
        required.add(binary_name)
        required.add(binary_name + ".sha256")
    manifest_names = {f"{REPO}-{profile}-x86_64.manifest.json" for profile in PROFILES}
    present_manifests = set(assets).intersection(manifest_names)
    if present_manifests and present_manifests != manifest_names:
        raise PublishError("forgejo-release-manifests-mixed")
    expected_names = required | present_manifests
    if set(assets) != expected_names:
        raise PublishError("forgejo-release-assets-shape-mismatch")

    digests = {}
    expected_sidecars = {}
    for profile in PROFILES:
        name = f"{REPO}-{profile}-x86_64"
        digest = hashlib.sha256(assets[name]).hexdigest()
        digests[profile] = digest
        expected_sidecars[name + ".sha256"] = (digest + "  " + name + "\n").encode("utf-8")
    for name, content in expected_sidecars.items():
        if assets[name] != content:
            raise PublishError("forgejo-release-sidecar-mismatch-" + name)

    flag = validate_flag(assets["release.flag"], commit)
    ordered_map = {profile: digests[profile] for profile in PROFILES}
    aggregate = hashlib.sha256(
        json.dumps(ordered_map, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    if flag["sha256"] != aggregate:
        raise PublishError("release-flag-aggregate-digest-mismatch")

    manifests = []
    if present_manifests:
        for profile in PROFILES:
            name = f"{REPO}-{profile}-x86_64.manifest.json"
            manifests.append(validate_manifest(assets[name], profile, commit, digests[profile]))
        env_shas = {item["env_sha"] for item in manifests}
        rustc_versions = {item["rustc_version"] for item in manifests}
        if len(env_shas) != 1 or len(rustc_versions) != 1:
            raise PublishError("forgejo-release-manifest-evidence-disagrees")
        if flag.get("env_sha") != next(iter(env_shas)):
            raise PublishError("release-flag-env-sha-mismatch")
        if flag.get("rustc_version") != next(iter(rustc_versions)):
            raise PublishError("release-flag-rustc-version-mismatch")

    receipts = [
        {"name": name, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}
        for name, content in assets.items()
    ]
    return assets, receipts, ordered_map, flag


def read_github_release(clients):
    status, release = clients.github(
        "GET", repo_path("/releases/tags/latest")
    )
    if status == 404:
        return None
    if status != 200 or not isinstance(release, dict):
        raise PublishError("github-latest-release-read-http-" + str(status))
    release_id = release.get("id")
    if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id <= 0:
        raise PublishError("github-latest-release-id-invalid")
    if release.get("tag_name") != "latest":
        raise PublishError("github-latest-release-tag-mismatch")
    return release


def github_release_count(clients):
    latest = []
    seen_ids = set()
    for page in range(1, 101):
        status, batch = clients.github(
            "GET", repo_path("/releases"), query={"per_page": 100, "page": page}
        )
        if status != 200 or not isinstance(batch, list):
            raise PublishError("github-release-list-http-" + str(status))
        for release in batch:
            if not isinstance(release, dict):
                raise PublishError("github-release-list-invalid")
            release_id = release.get("id")
            if isinstance(release_id, int) and not isinstance(release_id, bool):
                if release_id in seen_ids:
                    raise PublishError("github-release-list-duplicate-id")
                seen_ids.add(release_id)
            if release.get("tag_name") == "latest":
                latest.append(release)
        if len(batch) < 100:
            return latest
    raise PublishError("github-release-list-page-bound-exceeded")


def read_github_assets(clients, release_id):
    named = {}
    ids = set()
    for page in range(1, 101):
        status, assets = clients.github(
            "GET",
            repo_path(f"/releases/{release_id}/assets"),
            query={"per_page": 100, "page": page},
        )
        if status != 200 or not isinstance(assets, list):
            raise PublishError("github-release-assets-http-" + str(status))
        batch = assets_by_name(assets, "github")
        for name, asset in batch.items():
            if name in named or asset["id"] in ids:
                raise PublishError("github-release-assets-duplicate")
            named[name] = asset
            ids.add(asset["id"])
        if len(assets) < 100:
            return named
    raise PublishError("github-release-assets-page-bound-exceeded")


def body_for(commit):
    return "Caduceus rolling release mirrored from Forgejo.\n\nSource SHA: " + commit + "\n"


def github_release_request(release, commit):
    body = {
        "name": "Caduceus latest",
        "body": body_for(commit),
        "target_commitish": commit,
        "draft": False,
        "prerelease": False,
        "make_latest": "true",
    }
    if release is None:
        body["tag_name"] = "latest"
        return {"method": "POST", "path": repo_path("/releases"), "body": body}
    return {
        "method": "PATCH",
        "path": repo_path(f"/releases/{release['id']}"),
        "body": body,
    }


def source_digest_map_from_assets(assets):
    return {
        profile: hashlib.sha256(assets[f"{REPO}-{profile}-x86_64"]).hexdigest()
        for profile in PROFILES
    }


def verify_github_asset_bytes(clients, named, expected):
    if set(named) != set(expected):
        return False
    for name, content in expected.items():
        if clients.github_asset(named[name]) != content:
            return False
    digests = source_digest_map_from_assets(expected)
    for profile in PROFILES:
        name = f"{REPO}-{profile}-x86_64"
        sidecar = (digests[profile] + "  " + name + "\n").encode("utf-8")
        if expected[name + ".sha256"] != sidecar:
            raise PublishError("github-asset-sidecar-does-not-match-binary-" + profile)
    return True


def assess_github_release(clients, release, expected, commit):
    if release is None:
        return "missing", None
    named = read_github_assets(clients, release["id"])
    if (
        release.get("draft") is not False
        or release.get("prerelease") is not False
        or release.get("name") != "Caduceus latest"
        or release.get("body") != body_for(commit)
        or release.get("target_commitish") != commit
    ):
        return "replace", named
    if set(named) != set(expected):
        return "replace", named
    if verify_github_asset_bytes(clients, named, expected):
        return "exact", named
    return "replace", named


def planned_tag_move(current_sha, commit):
    if current_sha == commit:
        action = "no-op"
    elif current_sha is None:
        action = "create"
    else:
        action = "force-update"
    return {
        "tag": "latest",
        "current_sha": current_sha,
        "target_sha": commit,
        "action": action,
        "force": action == "force-update",
        "api": f"git push --force --no-follow-tags {FORGEJO_GIT_REMOTE} {commit}:refs/tags/latest",
        "guard": "Forgejo refs/heads/main must still equal target_sha immediately before push",
    }


def plan(clients, commit):
    main_sha = forgejo_main_sha(clients)
    if main_sha != commit:
        return {
            "status": "no-op-superseded",
            "source_sha": commit,
            "forgejo_main_sha": main_sha,
            "mutation": "none",
        }
    ensure_no_forgejo_latest_release(clients)
    release = read_forgejo_release(clients, commit)
    if release is None:
        return {
            "status": "no-op-missing-forgejo-release",
            "source_sha": commit,
            "forgejo_main_sha": main_sha,
            "forgejo_release_tag": release_tag(commit),
            "forgejo_latest_release": "absent",
            "mutation": "none",
        }
    source_assets, asset_rows, profile_digests, flag = expected_source_assets(
        clients, release, commit
    )
    _fj_ref, forgejo_tag_sha = forgejo_latest_ref(clients)
    _gh_ref, github_tag_sha = github_latest_ref(clients)
    github_release = read_github_release(clients)
    listed_latest = github_release_count(clients)
    if len(listed_latest) > 1:
        raise PublishError("github-has-multiple-latest-releases")
    if (github_release is None) != (len(listed_latest) == 0):
        raise PublishError("github-latest-release-lookup-inconsistent")
    if github_release is not None and listed_latest[0].get("id") != github_release.get("id"):
        raise PublishError("github-latest-release-lookup-inconsistent")
    github_assessment, _named = assess_github_release(
        clients, github_release, source_assets, commit
    )
    ref_ready = github_tag_sha == commit
    planned_latest_tag = planned_tag_move(forgejo_tag_sha, commit)
    sync_needed = planned_latest_tag["action"] != "no-op" or not ref_ready
    return {
        "status": "plan",
        "source_sha": commit,
        "forgejo_main_sha": main_sha,
        "forgejo_release": {"tag": release_tag(commit), "id": release["id"], "verified": True},
        "forgejo_latest_release": "absent",
        "profile_digests": profile_digests,
        "release_flag_source_sha": flag["source_sha"],
        "assets": asset_rows,
        "forgejo_latest_tag": planned_latest_tag,
        "github_latest_ref": {
            "status": "matched" if ref_ready else ("missing" if github_tag_sha is None else "mismatch"),
            "resolved_sha": github_tag_sha,
            "required_sha": commit,
            "action": "no-op" if ref_ready else "request-forgejo-push-mirror-sync",
            "route": "GET /repos/HOMESERVERSLTD/caduceus/git/ref/tags/latest; Forgejo mirror readback only",
            "mutation": "none (no direct GitHub ref write)",
            "ready_for_release_write": ref_ready,
        },
        "forgejo_push_mirrors_sync": {
            "method": "POST",
            "path": "/repos/HOMESERVERSLTD/caduceus/push_mirrors-sync",
            "condition": "Forgejo latest tag moved, or tag was a no-op and GitHub latest ref differs from source_sha",
            "status": "planned" if sync_needed else "not-needed",
        },
        "github_latest_release": {
            "status": github_assessment,
            "id": github_release.get("id") if github_release else None,
            "target_commitish": github_release.get("target_commitish") if github_release else None,
            "expected_target_commitish": commit,
            "commitish_mismatch": (
                {
                    "field": "target_commitish",
                    "current": github_release.get("target_commitish"),
                    "expected": commit,
                }
                if github_release is not None and github_release.get("target_commitish") != commit
                else None
            ),
            "would_write_release": github_assessment != "exact",
            "request": (
                {**github_release_request(github_release, commit), "executed": False}
                if github_assessment != "exact"
                else None
            ),
        },
        "publication": "ready" if ref_ready else "waiting-for-forgejo-mirror-tag",
        "mutation": "none (GET-only plan)",
    }


def ensure_current_main(clients, commit):
    current = forgejo_main_sha(clients)
    return current == commit, current


def move_forgejo_latest(clients, commit):
    current, _main_sha = ensure_current_main(clients, commit)
    if not current:
        return "superseded"
    ensure_no_forgejo_latest_release(clients)
    _ref, current_sha = forgejo_latest_ref(clients)
    if current_sha == commit:
        return "no-op"
    current, _current_sha_main = ensure_current_main(clients, commit)
    if not current:
        return "superseded"
    git_env = os.environ.copy()
    git_env.pop("FORGEJO_TOKEN", None)
    git_env["GIT_CONFIG_COUNT"] = "1"
    git_env["GIT_CONFIG_KEY_0"] = "http.https://git.home.arpa/.extraheader"
    git_env["GIT_CONFIG_VALUE_0"] = f"Authorization: token {clients.forgejo_token}"
    git_env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        result = subprocess.run(
            [
                "git", "push", "--force", "--no-follow-tags",
                FORGEJO_GIT_REMOTE, f"{commit}:refs/tags/latest",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=REQUEST_TIMEOUT_SECONDS,
            check=False,
            env=git_env,
        )
    except subprocess.TimeoutExpired:
        raise PublishError("forgejo-latest-tag-push-timeout") from None
    except OSError as exc:
        raise PublishError("forgejo-latest-tag-push-could-not-start-" + type(exc).__name__) from None
    if result.returncode != 0:
        _ref, observed_sha = forgejo_latest_ref(clients)
        if observed_sha != commit:
            raise PublishError("forgejo-latest-tag-push-failed-git-exit-" + str(result.returncode))
    _readback, readback_sha = forgejo_latest_ref(clients)
    if readback_sha != commit:
        raise PublishError("forgejo-latest-tag-readback-mismatch")
    return "created" if current_sha is None else "force-updated"


def wait_for_github_latest_tag(clients, commit):
    latest_sha = None
    deadline = time.monotonic() + MIRROR_TIMEOUT_SECONDS
    while True:
        current, _main_sha = ensure_current_main(clients, commit)
        if not current:
            return False
        _ref, latest_sha = github_latest_ref(clients)
        if latest_sha == commit:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PublishError("github-latest-tag-not-mirrored-to-source-sha-within-180s")
        time.sleep(min(MIRROR_POLL_SECONDS, remaining))


def require_publish_ready(clients, commit):
    current, current_sha = ensure_current_main(clients, commit)
    if not current:
        return False, current_sha
    _ref, mirrored_sha = github_latest_ref(clients)
    if mirrored_sha != commit:
        raise PublishError("github-latest-tag-not-mirrored-to-source-sha")
    return True, current_sha


def delete_github_assets(clients, release_id, named):
    for asset in named.values():
        asset_id = asset["id"]
        status, _ = clients.github(
            "DELETE", github_release_asset_path(asset_id)
        )
        if status == 404:
            reread = read_github_assets(clients, release_id)
            if any(asset["id"] == asset_id for asset in reread.values()):
                raise PublishError("github-latest-old-asset-delete-http-404")
        elif status not in (200, 204):
            raise PublishError("github-latest-old-asset-delete-http-" + str(status))
    reread = read_github_assets(clients, release_id)
    if reread:
        raise PublishError("github-latest-assets-not-empty-after-delete")


def write_github_release(clients, release, commit):
    request = github_release_request(release, commit)
    if release is None:
        status, created = clients.github(
            request["method"], request["path"], body=request["body"]
        )
        if status not in (200, 201) or not isinstance(created, dict):
            raise PublishError("github-latest-release-create-http-" + str(status))
        release_id = created.get("id")
    else:
        release_id = release["id"]
        status, updated = clients.github(
            request["method"], request["path"], body=request["body"]
        )
        if status != 200 or not isinstance(updated, dict):
            raise PublishError("github-latest-release-update-http-" + str(status))
    if isinstance(release_id, bool) or not isinstance(release_id, int) or release_id <= 0:
        raise PublishError("github-latest-release-id-invalid")
    return release_id


def upload_github_assets(clients, release_id, expected):
    for name, content in expected.items():
        status, response = clients.github_upload(release_id, name, content)
        if status not in (200, 201) or not isinstance(response, dict) or response.get("name") != name:
            raise PublishError("github-latest-asset-upload-failed-" + str(status))


def verify_github_readback(clients, release_id, expected, commit):
    release_status, release = clients.github("GET", repo_path(f"/releases/{release_id}"))
    if release_status != 200 or not isinstance(release, dict):
        raise PublishError("github-latest-release-readback-http-" + str(release_status))
    if (
        release.get("tag_name") != "latest"
        or release.get("name") != "Caduceus latest"
        or release.get("body") != body_for(commit)
        or release.get("target_commitish") != commit
        or release.get("draft") is not False
        or release.get("prerelease") is not False
    ):
        raise PublishError("github-latest-release-identity-readback-mismatch")
    tag_release = read_github_release(clients)
    latest_records = github_release_count(clients)
    if (
        tag_release is None
        or tag_release.get("id") != release_id
        or len(latest_records) != 1
        or latest_records[0].get("id") != release_id
    ):
        raise PublishError("github-latest-release-tag-readback-mismatch")
    named = read_github_assets(clients, release_id)
    if set(named) != set(expected):
        raise PublishError("github-latest-assets-shape-readback-mismatch")
    if not verify_github_asset_bytes(clients, named, expected):
        raise PublishError("github-latest-assets-byte-readback-mismatch")
    return named


def publish(clients, commit):
    main_sha = forgejo_main_sha(clients)
    if main_sha != commit:
        return {"status": "no-op-superseded", "source_sha": commit, "forgejo_main_sha": main_sha}
    ensure_no_forgejo_latest_release(clients)
    release = read_forgejo_release(clients, commit)
    if release is None:
        return {
            "status": "no-op-missing-forgejo-release",
            "source_sha": commit,
            "forgejo_main_sha": main_sha,
            "forgejo_release_tag": release_tag(commit),
        }
    expected, asset_rows, profile_digests, flag = expected_source_assets(clients, release, commit)

    tag_action = move_forgejo_latest(clients, commit)
    if tag_action == "superseded":
        return {
            "status": "no-op-superseded",
            "source_sha": commit,
            "forgejo_main_sha": forgejo_main_sha(clients),
            "forgejo_latest_tag": "moved-before-supersession-check",
        }
    sync_status = None
    should_sync = tag_action in ("created", "force-updated")
    if tag_action == "no-op":
        _ref, github_tag_sha = github_latest_ref(clients)
        should_sync = github_tag_sha != commit
    if should_sync:
        sync_status, _response = clients.forgejo(
            "POST", repo_path("/push_mirrors-sync")
        )
        clients.forgejo_push_mirrors_sync_http_status = sync_status
        if not 200 <= sync_status < 300:
            raise PublishError("forgejo-push-mirrors-sync-http-" + str(sync_status))
    mirrored = wait_for_github_latest_tag(clients, commit)
    if not mirrored:
        return {
            "status": "no-op-superseded",
            "source_sha": commit,
            "forgejo_main_sha": forgejo_main_sha(clients),
            "forgejo_push_mirrors_sync_http_status": sync_status,
        }
    ready, current_sha = require_publish_ready(clients, commit)
    if not ready:
        return {
            "status": "no-op-superseded",
            "source_sha": commit,
            "forgejo_main_sha": current_sha,
            "forgejo_push_mirrors_sync_http_status": sync_status,
        }

    github_release = read_github_release(clients)
    listed_latest = github_release_count(clients)
    if len(listed_latest) > 1:
        raise PublishError("github-has-multiple-latest-releases")
    if (github_release is None) != (len(listed_latest) == 0):
        raise PublishError("github-latest-release-lookup-inconsistent")
    if github_release is not None and listed_latest[0].get("id") != github_release.get("id"):
        raise PublishError("github-latest-release-lookup-inconsistent")

    assessment, named = assess_github_release(clients, github_release, expected, commit)
    if assessment == "exact" and github_release is not None:
        return {
            "status": "no-op",
            "source_sha": commit,
            "github_release_id": github_release["id"],
            "asset_count": len(expected),
            "asset_sha256": {row["name"]: row["sha256"] for row in asset_rows},
            "forgejo_latest_tag": tag_action,
            "forgejo_push_mirrors_sync_http_status": sync_status,
        }

    ready, current_sha = require_publish_ready(clients, commit)
    if not ready:
        return {
            "status": "no-op-superseded",
            "source_sha": commit,
            "forgejo_main_sha": current_sha,
            "forgejo_push_mirrors_sync_http_status": sync_status,
        }
    if github_release is not None:
        delete_github_assets(clients, github_release["id"], named or {})

    ready, current_sha = require_publish_ready(clients, commit)
    if not ready:
        return {
            "status": "no-op-superseded",
            "source_sha": commit,
            "forgejo_main_sha": current_sha,
            "forgejo_push_mirrors_sync_http_status": sync_status,
        }
    release_id = write_github_release(clients, github_release, commit)
    upload_github_assets(clients, release_id, expected)
    verify_github_readback(clients, release_id, expected, commit)

    ready, current_sha = require_publish_ready(clients, commit)
    if not ready:
        raise PublishError("forgejo-main-superseded-during-github-publication")
    return {
        "status": "published",
        "source_sha": commit,
        "github_release_id": release_id,
        "asset_count": len(expected),
        "profile_digests": profile_digests,
        "asset_sha256": {row["name"]: row["sha256"] for row in asset_rows},
        "forgejo_latest_tag": tag_action,
        "forgejo_push_mirrors_sync_http_status": sync_status,
        "release_flag_source_sha": flag["source_sha"],
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", action="store_true", help="GET-only source verification and mirror plan")
    parser.add_argument("--commit-sha", required=True, help="full source commit SHA to mirror")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    if not valid_sha(args.commit_sha):
        print(json.dumps({"status": "error", "error": "commit-sha-must-be-full-lowercase-40-hex"}, separators=(",", ":")))
        return 2
    forgejo_token = os.environ.get("FORGEJO_TOKEN", "")
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not forgejo_token or (not args.plan and not github_token):
        missing = []
        if not forgejo_token:
            missing.append("FORGEJO_TOKEN")
        if not args.plan and not github_token:
            missing.append("GITHUB_TOKEN")
        print(json.dumps({"status": "error", "error": "missing-secret-environment:" + ",".join(missing)}, separators=(",", ":")))
        return 1
    clients = None
    result: dict = {}
    try:
        clients = Clients(forgejo_token, github_token)
        result = plan(clients, args.commit_sha) if args.plan else publish(clients, args.commit_sha)
        code = 0
    except PublishError as exc:
        result = {"status": "error", "error": str(exc)}
        code = 1
    except Exception as exc:
        # Do not stringify unexpected exceptions: they can carry request data.
        result = {"status": "error", "error": "internal-error-" + type(exc).__name__}
        code = 1
    sync_status = getattr(clients, "forgejo_push_mirrors_sync_http_status", None)
    if type(sync_status) is int and 100 <= sync_status <= 599:
        result["forgejo_push_mirrors_sync_http_status"] = sync_status
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
