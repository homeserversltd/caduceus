"""Keyman-backed Ed25519 household capability signer for Caduceus."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Sequence

from .skeleton_sha import skeleton_sha_receipt

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SERVICE_NAME = "caduceus_household"
KEYMAN_NEWKEY = Path("/vault/keyman/newkey.sh")
KEYMAN_EXPORTKEY = Path("/vault/keyman/exportkey.sh")
KEYMAN_KEY = Path("/vault/.keys/caduceus_household.key")
KEYMAN_EXCHANGE = Path("/mnt/keyexchange/caduceus_household")
PROFILE_PATH = Path("/etc/caduceus/profile.yaml")
DEFAULT_TTL_SECONDS = 60


def _path(env: str, default: Path) -> Path:
    return Path(os.environ.get(env, str(default)))


def _run(command: list[str], *, discard_stdout: bool = False) -> None:
    subprocess.run(
        command,
        check=True,
        text=True,
        stdout=subprocess.DEVNULL if discard_stdout else None,
    )


def _public_hex(seed: bytes) -> str:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    ).hex()


def _new_seed() -> bytes:
    return os.urandom(32)


def _write_profile_key(public_hex: str) -> None:
    path = _path("CADUCEUS_PROFILE_PATH", PROFILE_PATH)
    text = path.read_text(encoding="utf-8") if path.is_file() else "schema: caduceus.profile.v1\n"
    lines = text.splitlines()
    capability_index = next((i for i, line in enumerate(lines) if line.strip() == "capability:" and not line.startswith((" ", "\t"))), None)
    if capability_index is None:
        insert_at = next((i for i, line in enumerate(lines) if line.startswith("mode:")), len(lines))
        lines[insert_at:insert_at] = ["capability:", f"  household_verifying_key: {public_hex}", f"  default_ttl_seconds: {DEFAULT_TTL_SECONDS}"]
    else:
        end = capability_index + 1
        while end < len(lines) and (not lines[end].strip() or lines[end].startswith((" ", "\t"))):
            end += 1
        key_index = next((i for i in range(capability_index + 1, end) if lines[i].lstrip().startswith("household_verifying_key:")), None)
        if key_index is None:
            lines.insert(capability_index + 1, f"  household_verifying_key: {public_hex}")
        else:
            lines[key_index] = f"  household_verifying_key: {public_hex}"
        if not any(lines[i].lstrip().startswith("default_ttl_seconds:") for i in range(capability_index + 1, end)):
            lines.insert(capability_index + 2, f"  default_ttl_seconds: {DEFAULT_TTL_SECONDS}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _store_seed(seed: bytes) -> str:
    newkey = _path("CADUCEUS_KEYMAN_NEWKEY", KEYMAN_NEWKEY)
    _run([str(newkey), SERVICE_NAME, "signing", seed.hex()])
    public_hex = _public_hex(seed)
    _write_profile_key(public_hex)
    return public_hex


def ensure_signing_key() -> dict[str, Any]:
    key_path = _path("CADUCEUS_KEYMAN_KEY", KEYMAN_KEY)
    if key_path.is_file():
        public_hex = _public_hex(_read_exported_seed())
        profile_changed = _profile_key() != public_hex
        if profile_changed:
            _write_profile_key(public_hex)
        return {
            "ok": True,
            "service": SERVICE_NAME,
            "changed": profile_changed,
            **status(),
        }
    public_hex = _store_seed(_new_seed())
    return {"ok": True, "service": SERVICE_NAME, "changed": True, "public_key": public_hex}


def _read_exported_seed() -> bytes:
    exportkey = _path("CADUCEUS_KEYMAN_EXPORTKEY", KEYMAN_EXPORTKEY)
    exchange = _path("CADUCEUS_KEYMAN_EXCHANGE", KEYMAN_EXCHANGE)
    # exportkey reports acquisition on stdout. The signer stdout is a machine
    # envelope, so helper diagnostics must never share that channel.
    _run([str(exportkey), SERVICE_NAME], discard_stdout=True)
    return _parse_exported_seed(exchange.read_bytes())


def _parse_exported_seed(value: bytes) -> bytes:
    """Extract the 32-byte seed from the Keyman export format.

    Keyman exports may be the raw seed, a bare 64-character hexadecimal seed,
    or a username/password record whose password is quoted or unquoted.  The
    password is the seed; usernames are intentionally not used as key
    material.
    """
    if len(value) == 32:
        return value

    try:
        text = value.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ValueError("caduceus-household-exported-seed-invalid") from exc

    password_match = re.search(
        r"(?im)^\s*password\s*[:=]\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s]+))\s*$",
        text,
    )
    candidate = next(
        (group for group in (password_match.groups() if password_match else ()) if group is not None),
        text,
    )
    if len(candidate) == 64 and re.fullmatch(r"[0-9a-fA-F]{64}", candidate):
        return bytes.fromhex(candidate)
    raise ValueError("caduceus-household-exported-seed-invalid")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def sign_capability(action: str, target: str, actor: str = "coronatio", ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    ensure_signing_key()
    seed = _read_exported_seed()
    payload = json.dumps(
        {"actor": actor, "action": action, "target": target, "exp": int(time.time()) + ttl_seconds},
        separators=(",", ":"),
    ).encode("utf-8")
    signature = Ed25519PrivateKey.from_private_bytes(seed).sign(payload)
    return f"{_b64url(payload)}.{_b64url(signature)}"


def rotate_signing_key() -> dict[str, Any]:
    public_hex = _store_seed(_new_seed())
    return {"ok": True, "service": SERVICE_NAME, "changed": True, "rotated": True, "public_key": public_hex}


def _profile_key() -> str | None:
    path = _path("CADUCEUS_PROFILE_PATH", PROFILE_PATH)
    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("household_verifying_key:"):
            return line.split(":", 1)[1].strip() or None
    return None


def status() -> dict[str, Any]:
    try:
        key_exists = _path("CADUCEUS_KEYMAN_KEY", KEYMAN_KEY).is_file()
    except OSError:
        key_exists = False
    profile_key = _profile_key()
    public_key = None
    if key_exists:
        try:
            public_key = _public_hex(_read_exported_seed())
        except (OSError, ValueError, subprocess.CalledProcessError):
            public_key = None
    return {
        "ok": True,
        "firstMissingSignal": "none",
        "key_exists": key_exists,
        "public_key": public_key,
        "public_fingerprint": hashlib.sha256(bytes.fromhex(public_key)).hexdigest() if public_key else None,
        "profile_key": profile_key,
        "profile_match": bool(public_key and profile_key == public_key),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-household-capability")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ensure")
    sign = commands.add_parser("sign")
    sign.add_argument("--action", required=True)
    sign.add_argument("--target", required=True)
    sign.add_argument("--actor", default="coronatio")
    sign.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    commands.add_parser("rotate")
    commands.add_parser("status")
    commands.add_parser("skeleton-sha")
    args = parser.parse_args(argv)
    if args.command == "skeleton-sha":
        print(json.dumps(skeleton_sha_receipt(), sort_keys=True))
        return 0
    if args.command == "sign":
        try:
            token = sign_capability(args.action, args.target, args.actor, args.ttl_seconds)
        except Exception as exc:
            print(json.dumps({"ok": False, "firstMissingSignal": str(exc) or "caduceus-household-capability-sign-failed"}, sort_keys=True))
            return 1
        print(json.dumps({"ok": True, "capability": token, "firstMissingSignal": "none"}, sort_keys=True))
    else:
        result = {"ensure": ensure_signing_key, "rotate": rotate_signing_key, "status": status}[args.command]()
        print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
