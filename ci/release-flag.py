#!/usr/bin/env python3
"""Verify Caduceus Forgejo release assets and immutably publish release.flag."""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import build_opener, install_opener, urlopen


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schema" / "estate.release-flag.v1.json"
SCHEMA_ID = "estate.release-flag.v1"
# This producer emits these fields; the shared seat alone declares the kernel.
EMITTED_FIELDS = (
    "schema", "component", "source_sha", "env_sha", "sha256", "flagged_at", "pipeline_url"
)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def reject_duplicate_keys(pairs):
    """Reject ambiguous identity keys while retaining distinct unknown keys."""
    record = {}
    for key, value in pairs:
        if key in record:
            raise FlagError("duplicate JSON key: " + str(key))
        record[key] = value
    return record


class FlagError(RuntimeError):
    """A release flag or its release evidence is not contract-valid."""


class FlagConflict(FlagError):
    """An immutable existing release.flag differs from the candidate."""

    def __init__(self, fields):
        self.differing_fields = tuple(fields)
        super().__init__(
            "release.flag conflict in fields: " + ", ".join(self.differing_fields)
        )


def load_schema(path=SCHEMA_PATH):
    """Load and structurally gate the local schema before any network access."""
    try:
        schema = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FlagError("release-flag-schema-read-" + type(exc).__name__) from exc
    if not isinstance(schema, dict):
        raise FlagError("release-flag-schema-not-object")
    for field in (
        "schema",
        "authority",
        "description",
        "required",
        "field_types",
        "schema_version",
        "role",
    ):
        if field not in schema:
            raise FlagError("release-flag-schema-missing-" + field)
    if schema["schema"] != SCHEMA_ID:
        raise FlagError("release-flag-schema-foreign-id")
    required = schema["required"]
    field_types = schema["field_types"]
    if (
        not isinstance(required, list)
        or not required
        or any(not isinstance(field, str) for field in required)
        or len(set(required)) != len(required)
        or not isinstance(field_types, dict)
        or any(field not in field_types for field in required)
    ):
        raise FlagError("release-flag-schema-required-fields-invalid")
    return schema


def validate_flag_record(record, schema):
    """Return declared fields while skipping unknown fields in the raw record."""
    if not isinstance(record, dict):
        raise FlagError("release.flag is not a JSON object")
    if record.get("schema") != schema["schema"]:
        raise FlagError("release.flag has foreign schema id")
    required = schema["required"]
    missing = [field for field in required if field not in record]
    if missing:
        raise FlagError("release.flag missing required fields: " + ", ".join(missing))
    wrong_type = [
        field
        for field in EMITTED_FIELDS
        if field in record
        if not isinstance(record[field], str)
        or (
            schema["field_types"].get(field) == "literal:" + schema["schema"]
            and record[field] != schema["schema"]
        )
    ]
    if wrong_type:
        raise FlagError("release.flag non-string declared fields: " + ", ".join(wrong_type))
    return {field: record[field] for field in EMITTED_FIELDS if field in record}


def compare_existing_flag(existing, candidate, schema=None):
    """Compare all declared fields; unknown existing fields remain untouched.

    This function is intentionally public so a caller can exercise immutable
    conflict handling with an in-memory hypothetical existing flag.
    """
    schema = load_schema() if schema is None else schema
    existing_declared = validate_flag_record(existing, schema)
    candidate_declared = validate_flag_record(candidate, schema)
    differing = [
        field
        for field in EMITTED_FIELDS
        if existing_declared.get(field) != candidate_declared.get(field)
    ]
    if differing:
        raise FlagConflict(differing)
    return {
        "status": "no-op",
        "differing_fields": [],
        "unknown_fields_preserved": [
            field for field in existing if field not in EMITTED_FIELDS
        ],
    }


def _publisher():
    path = Path(__file__).with_name("release-publish.py")
    spec = importlib.util.spec_from_file_location("caduceus_release_publish", path)
    if spec is None or spec.loader is None:
        raise FlagError("release-publisher-import-failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PUBLISHER = _publisher()
PROFILES = PUBLISHER.PROFILES


def package_url(commit, name):
    return (
        "https://git.home.arpa/api/packages/HOMESERVERSLTD/generic/caduceus/"
        + quote(commit, safe="")
        + "/"
        + quote(name, safe="")
    )


def install_house_ca():
    """Install the existing house CA for every later urllib HTTPS request."""
    try:
        with urlopen("http://192.168.123.1:7100/v1/trust/ca-bundle") as response:
            bundle = response.read()
        if not bundle:
            raise FlagError("house-ca-bootstrap-empty")
        ca_path = Path("/tmp/house-ca.pem")
        ca_path.write_bytes(bundle)
        os.environ["SSL_CERT_FILE"] = str(ca_path)
        install_opener(build_opener())
    except OSError as exc:
        raise FlagError("house-ca-bootstrap-" + type(exc).__name__) from exc


def package_get(commit, name, token):
    try:
        return PUBLISHER.download(package_url(commit, name), token)
    except PUBLISHER.ReleaseError as exc:
        message = str(exc)
        prefix = "forgejo-transport-"
        if message.startswith(prefix):
            message = "generic-package-transport-" + message[len(prefix):]
        raise FlagError(message) from exc


def error_with_transport_reason(exc, token):
    """Append the deepest transport reason without exposing credential data."""
    current = exc
    deepest = exc
    reason = None
    transport = False
    seen = set()
    while isinstance(current, BaseException) and id(current) not in seen:
        seen.add(id(current))
        deepest = current
        message = str(current)
        if isinstance(current, (URLError, TimeoutError)) or message.startswith(
            ("generic-package-transport-", "forgejo-transport-")
        ):
            transport = True
        if isinstance(current, URLError):
            reason = current.reason
        current = current.__cause__ or current.__context__

    error = str(exc)
    if token:
        error = error.replace(token, "[REDACTED]")
    if not transport:
        return error

    reason = deepest if reason is None else reason
    reason_text = str(reason)
    if token:
        reason_text = reason_text.replace(token, "[REDACTED]")
    reason_text = " ".join(reason_text.split()) or "<empty>"
    return error + "; reason=" + type(reason).__name__ + ": " + reason_text


def fetch_manifest(commit, token):
    status, raw = package_get(commit, "manifest.json", token)
    if status != 200:
        raise FlagError("manifest-GET-failed-HTTP-" + str(status))
    try:
        manifest = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FlagError("manifest-json-invalid") from exc
    if not isinstance(manifest, dict):
        raise FlagError("manifest-json-not-object")
    missing = [field for field in ("source_sha", "env_sha", "sha256") if field not in manifest]
    if missing:
        raise FlagError("manifest-missing-fields: " + ", ".join(missing))
    source_sha = manifest["source_sha"]
    env_sha = manifest["env_sha"]
    manifest_sha256 = manifest["sha256"]
    if not isinstance(source_sha, str) or not HEX40.fullmatch(source_sha):
        raise FlagError("manifest-source-sha-invalid")
    if source_sha != commit:
        raise FlagError("manifest-source-sha-does-not-equal-CI_COMMIT_SHA")
    if not isinstance(env_sha, str) or not HEX64.fullmatch(env_sha):
        raise FlagError("manifest-env-sha-invalid")
    if not isinstance(manifest_sha256, str) or not HEX64.fullmatch(manifest_sha256):
        raise FlagError("manifest-sha256-invalid")
    return {
        "source_sha": source_sha,
        "env_sha": env_sha,
        "sha256": manifest_sha256,
    }


def release_base():
    return "/repos/HOMESERVERSLTD/caduceus"


def read_release(commit, token):
    encoded = quote(commit, safe="")
    status, release = PUBLISHER.request(
        "GET", release_base() + "/releases/tags/" + encoded, token
    )
    if status != 200:
        raise FlagError("release-GET-failed-HTTP-" + str(status))
    release_name = "caduceus " + commit[:8]
    try:
        PUBLISHER.verify_release_identity(release, commit, release_name)
    except PUBLISHER.ReleaseError as exc:
        raise FlagError(str(exc)) from exc
    tag_status, tag = PUBLISHER.request(
        "GET", release_base() + "/tags/" + encoded, token
    )
    if tag_status != 200 or PUBLISHER.tag_target(tag) != commit:
        raise FlagError("tag-target-mismatch")
    release_id = release.get("id") if isinstance(release, dict) else None
    if release_id is None:
        raise FlagError("release-id-missing")
    assets = get_release_assets(release_id, token)
    return release_id, assets


def get_release_assets(release_id, token):
    status, assets = PUBLISHER.request(
        "GET", release_base() + "/releases/" + str(release_id) + "/assets", token
    )
    if status != 200:
        raise FlagError("release-assets-GET-failed-HTTP-" + str(status))
    try:
        return PUBLISHER.assets_by_name(assets)
    except PUBLISHER.ReleaseError as exc:
        raise FlagError(str(exc)) from exc


def fetch_release_asset(asset, token):
    try:
        return PUBLISHER.fetch_asset(asset, token)
    except PUBLISHER.ReleaseError as exc:
        raise FlagError(str(exc)) from exc


def verify_release_assets(named, token):
    expected = {
        f"caduceus-{profile}-x86_64{suffix}"
        for profile in PROFILES
        for suffix in ("", ".sha256")
    }
    missing = sorted(expected - set(named))
    if missing:
        raise FlagError("release-assets-missing: " + ", ".join(missing))

    profile_digest_map = {}
    for profile in PROFILES:
        binary_name = f"caduceus-{profile}-x86_64"
        sidecar_name = binary_name + ".sha256"
        binary = fetch_release_asset(named[binary_name], token)
        digest = hashlib.sha256(binary).hexdigest()
        expected_sidecar = (digest + "  " + binary_name + "\n").encode("utf-8")
        sidecar = fetch_release_asset(named[sidecar_name], token)
        if sidecar != expected_sidecar:
            raise FlagError("release-sidecar-mismatch: " + sidecar_name)
        profile_digest_map[profile] = digest

    serialized = json.dumps(profile_digest_map, separators=(",", ":")).encode("utf-8")
    aggregate = hashlib.sha256(serialized).hexdigest()
    return profile_digest_map, serialized, aggregate


def make_flag(commit, env_sha, aggregate, flagged_at, pipeline_url, schema):
    if not HEX40.fullmatch(commit):
        raise FlagError("CI_COMMIT_SHA-missing-or-invalid")
    if not HEX64.fullmatch(env_sha) or not HEX64.fullmatch(aggregate):
        raise FlagError("release-flag-digest-invalid")
    if not isinstance(flagged_at, str) or not flagged_at:
        raise FlagError("flagged_at-missing")
    if not isinstance(pipeline_url, str) or not pipeline_url:
        raise FlagError("CI_PIPELINE_URL-missing")
    values = {
        "schema": schema["schema"],
        "component": "caduceus",
        "source_sha": commit,
        "env_sha": env_sha,
        "sha256": aggregate,
        "flagged_at": flagged_at,
        "pipeline_url": pipeline_url,
    }
    return {
        field: values[field]
        for field in EMITTED_FIELDS
        if field in values
    }


def flag_bytes(flag):
    return (json.dumps(flag, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def existing_flag(named, token, schema):
    asset = named.get("release.flag")
    if asset is None:
        return None
    raw = fetch_release_asset(asset, token)
    try:
        record = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FlagError("existing-release.flag-json-invalid") from exc
    if not isinstance(record, dict):
        raise FlagError("existing-release.flag-not-object")
    return record


def upload_flag(release_id, body, token, schema, named):
    validate_flag_record(body, schema)
    current = existing_flag(named, token, schema)
    if current is not None:
        return compare_existing_flag(current, body, schema)

    status, _ = PUBLISHER.request(
        "POST",
        release_base() + "/releases/" + str(release_id) + "/assets",
        token,
        data=flag_bytes(body),
        query={"name": "release.flag"},
    )
    if status == 409:
        raced = get_release_assets(release_id, token)
        current = existing_flag(raced, token, schema)
        if current is None:
            raise FlagError("release.flag-upload-conflict-without-existing-asset")
        return compare_existing_flag(current, body, schema)
    if status not in (200, 201):
        raise FlagError("release.flag-upload-failed-HTTP-" + str(status))

    reread = get_release_assets(release_id, token)
    current = existing_flag(reread, token, schema)
    if current is None:
        raise FlagError("release.flag-upload-readback-missing")
    result = compare_existing_flag(current, body, schema)
    result["status"] = "published"
    return result


def run(args, schema):
    commit = args.commit_sha or os.environ.get("CI_COMMIT_SHA", "")
    pipeline_url = args.pipeline_url or os.environ.get("CI_PIPELINE_URL", "")
    flagged_at = args.flagged_at or os.environ.get("CI_FLAGGED_AT", "")
    if not flagged_at:
        flagged_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    token = os.environ.get("FORGEJO_TOKEN", "")
    if not token:
        raise FlagError("FORGEJO_TOKEN-missing")
    if not HEX40.fullmatch(commit):
        raise FlagError("CI_COMMIT_SHA-missing-or-invalid")

    manifest = fetch_manifest(commit, token)
    release_id, named = read_release(commit, token)
    profile_digest_map, serialized, aggregate = verify_release_assets(named, token)
    body = make_flag(
        commit,
        manifest["env_sha"],
        aggregate,
        flagged_at,
        pipeline_url,
        schema,
    )
    validate_flag_record(body, schema)

    current = existing_flag(named, token, schema)
    comparison = None
    if current is not None:
        try:
            comparison = compare_existing_flag(current, body, schema)
        except FlagConflict as exc:
            comparison = {
                "status": "conflict",
                "differing_fields": list(exc.differing_fields),
                "reason": str(exc),
            }
            if not args.dry_run:
                raise

    if args.dry_run:
        return {
            "status": "dry-run",
            "verified_profiles": list(PROFILES),
            "profile_digest_map": profile_digest_map,
            "aggregate_serialization": serialized.decode("utf-8"),
            "aggregate_sha256": aggregate,
            "flag": body,
            "existing_flag": "present" if current is not None else "absent",
            "comparison": comparison,
        }

    result = upload_flag(release_id, body, token, schema, named)
    return {
        "status": result["status"],
        "verified_profiles": list(PROFILES),
        "aggregate_sha256": aggregate,
        "flag": body,
        "comparison": result,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="GET-only verification and flag preview")
    parser.add_argument("--house-ca", action="store_true", help="GET the house CA bundle and write it for SSL_CERT_FILE trust")
    parser.add_argument("--commit-sha", help="deterministic replacement for CI_COMMIT_SHA")
    parser.add_argument("--pipeline-url", help="deterministic replacement for CI_PIPELINE_URL")
    parser.add_argument("--flagged-at", help="deterministic replacement for the flag timestamp")
    return parser.parse_args(argv)


def main(argv=None):
    # This is deliberately the first operation in the execution path.
    schema = load_schema()
    args = parse_args(argv)
    try:
        if args.house_ca:
            install_house_ca()
        result = run(args, schema)
        code = 0
    except (FlagError, PUBLISHER.ReleaseError, OSError, ValueError) as exc:
        result = {
            "status": "error",
            "error": error_with_transport_reason(
                exc, os.environ.get("FORGEJO_TOKEN", "")
            ),
        }
        code = 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return code


if __name__ == "__main__":
    sys.exit(main())
