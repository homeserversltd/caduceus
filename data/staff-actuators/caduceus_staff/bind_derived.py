"""Caduceus SacredCredential bind and PIN verification launcher.

The fixed Keyman credential ``/vault/.keys/caduceus.key`` is the sole PIN
truth.  Its username is the SHA-256 identity of raw skeleton bytes and its
password is the operator PIN.  Binding reads the current Keyman credential as
root, holds the Ed25519 signer only in staff memory, and projects public data.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from typing import Any, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import sacred_credential

_BOUND: sacred_credential.DerivedCaduceusSigner | None = None


def identity_hex(skeleton: bytes) -> str:
    """Lowercase SHA-256 identity of the raw skeleton bytes."""
    return hashlib.sha256(skeleton).hexdigest()


def seed_bytes(identity: str, pin: str) -> bytes:
    if len(identity) != 64 or any(char not in "0123456789abcdef" for char in identity):
        raise ValueError("caduceus-staff-identity-invalid")
    return hashlib.sha256(identity.encode("ascii") + b"\x00" + pin.encode("utf-8")).digest()


def private_key(identity: str, pin: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed_bytes(identity, pin))


def _unbound_signal(exc: Exception) -> str:
    signal = str(exc) or "caduceus-derived-unbound"
    if signal in {"caduceus-key-unavailable", "caduceus-key-malformed", "caduceus-key-corrupt"}:
        return "caduceus-pin-not-yet-provisioned"
    return signal


def _project(signer: sacred_credential.DerivedCaduceusSigner, *, operation: str) -> dict[str, Any]:
    return {
        "schema": "caduceus.staff.sacred-credential.v1",
        "ok": True,
        "operation": operation,
        "posture": "DERIVED_BOUND",
        "identity": signer.identity_sha256,
        "publicKey": signer.public_key_hex,
        "epoch": signer.signer_epoch,
        "derivation": "sha256(identity_ascii + 0x00 + pin_utf8)",
        "firstMissingSignal": "none",
    }


def bind_derived() -> dict[str, Any]:
    """Read current Keyman custody and replace the in-memory signing seat."""
    global _BOUND
    try:
        fresh = sacred_credential.bind_derived_caduceus()
    except sacred_credential.CaduceusAccessRefused as exc:
        if _BOUND is not None:
            _BOUND.close()
            _BOUND = None
        return {
            "schema": "caduceus.staff.sacred-credential.v1",
            "ok": False,
            "operation": "bind",
            "posture": "UNBOUND",
            "firstMissingSignal": _unbound_signal(exc),
        }
    if _BOUND is not None:
        _BOUND.close()
    _BOUND = fresh
    return _project(fresh, operation="bind")


def verify_derived(pin: str) -> dict[str, Any]:
    """Verify a presented PIN against the currently bound Keyman truth."""
    if _BOUND is None:
        return {
            "schema": "caduceus.staff.sacred-credential.v1",
            "ok": False,
            "operation": "verify",
            "posture": "UNBOUND",
            "verified": False,
            "firstMissingSignal": "caduceus-derived-unbound",
        }
    try:
        candidate = sacred_credential.verify_and_derive_caduceus(pin)
    except sacred_credential.CaduceusAccessRefused as exc:
        return {
            "schema": "caduceus.staff.sacred-credential.v1",
            "ok": False,
            "operation": "verify",
            "posture": "DERIVED_BOUND",
            "verified": False,
            "firstMissingSignal": _unbound_signal(exc),
        }
    try:
        verified = hmac.compare_digest(candidate.public_key_hex, _BOUND.public_key_hex)
        return {
            **_project(_BOUND, operation="verify"),
            "ok": verified,
            "verified": verified,
            "firstMissingSignal": "none" if verified else "caduceus-staff-derived-key-mismatch",
        }
    finally:
        candidate.close()


def atomic_change_pin(old_pin: str, new_pin: str) -> dict[str, Any]:
    """Verify old PIN, atomically rotate Keyman credential password, then rebind."""
    if not new_pin:
        return {
            "schema": "caduceus.staff.sacred-credential.v1",
            "ok": False,
            "operation": "atomic-change-pin",
            "posture": "DERIVED_BOUND" if _BOUND else "UNBOUND",
            "firstMissingSignal": "caduceus-staff-new-pin-missing",
        }
    verified = verify_derived(old_pin)
    if not verified.get("ok"):
        return {**verified, "operation": "atomic-change-pin"}
    try:
        sacred_credential.change_caduceus_pin(old_pin, new_pin)
    except sacred_credential.CaduceusAccessRefused as exc:
        return {
            "schema": "caduceus.staff.sacred-credential.v1",
            "ok": False,
            "operation": "atomic-change-pin",
            "posture": "STALE_DERIVED",
            "firstMissingSignal": _unbound_signal(exc),
        }
    rebound = bind_derived()
    if not rebound.get("ok"):
        return {**rebound, "operation": "atomic-change-pin", "posture": "STALE_DERIVED"}
    return {**rebound, "operation": "atomic-change-pin", "rotated": True}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-sacred-credential")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("bind")
    verify = commands.add_parser("verify")
    verify.add_argument("pin")
    change = commands.add_parser("atomic-change-pin")
    change.add_argument("old_pin")
    change.add_argument("new_pin")
    args = parser.parse_args(argv)
    if args.command == "bind":
        value = bind_derived()
    elif args.command == "verify":
        value = verify_derived(args.pin)
    else:
        value = atomic_change_pin(args.old_pin, args.new_pin)
    print(json.dumps(value, sort_keys=True))
    return 0 if value.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
