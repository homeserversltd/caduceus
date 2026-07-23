"""Canonical Caduceus staff identity derivation from the active leaf.

The derivation is intentionally byte-exact and has no persistence, lease, or
session state: identity is SHA-256(raw skeleton bytes), rendered lower-case
hex; seed is SHA-256(identity ASCII + NUL + PIN UTF-8).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .household_capability.skeleton_sha import skeleton_sha


def identity_hex(skeleton: bytes) -> str:
    return hashlib.sha256(skeleton).hexdigest()


def active_identity_hex() -> str:
    return skeleton_sha()


def seed_bytes(identity: str, pin: str) -> bytes:
    if len(identity) != 64 or any(char not in "0123456789abcdef" for char in identity):
        raise ValueError("caduceus-staff-identity-invalid")
    return hashlib.sha256(identity.encode("ascii") + b"\x00" + pin.encode("utf-8")).digest()


def private_key(identity: str, pin: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed_bytes(identity, pin))


def bind_derived(pin: str) -> dict[str, Any]:
    identity = active_identity_hex()
    key = private_key(identity, pin)
    public_key = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {
        "schema": "caduceus.staff.bind-derived.v1",
        "ok": True,
        "identity": identity,
        "publicKey": public_key,
        "derivation": "sha256(identity_ascii + 0x00 + pin_utf8)",
        "firstMissingSignal": "none",
    }


def verify_derived(pin: str, public_key: str) -> dict[str, Any]:
    expected = bind_derived(pin)
    ok = public_key.lower() == expected["publicKey"]
    return {**expected, "ok": ok, "verified": ok, "firstMissingSignal": "none" if ok else "caduceus-staff-derived-key-mismatch"}


def atomic_change_pin(old_pin: str, new_pin: str) -> dict[str, Any]:
    if not new_pin:
        raise ValueError("caduceus-staff-new-pin-missing")
    # Keyman owns durable secret custody; this fixed launcher only proves the
    # replacement derivation before the owning actuator commits it.
    old = bind_derived(old_pin)
    new = bind_derived(new_pin)
    return {"schema": "caduceus.staff.atomic-change-pin.v1", "ok": True, "oldPublicKey": old["publicKey"], "publicKey": new["publicKey"], "identity": new["identity"], "firstMissingSignal": "none"}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-staff-bind-derived")
    commands = parser.add_subparsers(dest="command", required=True)
    bind = commands.add_parser("bind")
    bind.add_argument("pin")
    verify = commands.add_parser("verify")
    verify.add_argument("pin")
    verify.add_argument("public_key")
    change = commands.add_parser("atomic-change-pin")
    change.add_argument("old_pin")
    change.add_argument("new_pin")
    args = parser.parse_args(argv)
    try:
        if args.command == "bind":
            value = bind_derived(args.pin)
        elif args.command == "verify":
            value = verify_derived(args.pin, args.public_key)
        else:
            value = atomic_change_pin(args.old_pin, args.new_pin)
    except (OSError, ValueError) as exc:
        print(json.dumps({"schema": "caduceus.staff.bind-derived.v1", "ok": False, "firstMissingSignal": str(exc)}))
        return 1
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
