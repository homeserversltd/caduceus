"""Bounded direct-file Unbound local A-record actuator.

The configured Unbound file is the only durable state. This module does not
reload a daemon; it only applies typed record intent.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable, Sequence

SCHEMA = "caduceus.network.dns.receipt.v2"
DEFAULT_CONFIG = Path("/etc/unbound/unbound.conf")
MAX_CONFIG_BYTES = 4 * 1024 * 1024
MAX_NAME_BYTES = 253
MAX_LABEL_BYTES = 63
_RECORD = re.compile(rb'^(?P<prefix>[ \t]*local-data:[ \t]*)"(?P<body>[^"\r\n]+)"(?P<suffix>[ \t]*(?:#.*)?)$')
_LOCAL_ZONE = re.compile(rb'^(?P<prefix>[ \t]*)local-zone:[ \t]*')
_TOP_LEVEL = re.compile(rb'^[A-Za-z][A-Za-z0-9-]*:[ \t]*(?:#.*)?$')


class DnsRefused(ValueError):
    pass


def _receipt(action: str, *, ok: bool, changed: bool, name: str | None = None,
             address: str | None = None, error: str = "none", **extra: Any) -> dict[str, Any]:
    return {"schema": SCHEMA, "ok": ok, "action": action, "changed": changed,
            "record": ({"name": name, **({"address": address} if address else {})} if name else None),
            "serviceAction": "not-owned", "error": error, **extra}


def normalize_name(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8", "ignore")) > MAX_NAME_BYTES:
        raise DnsRefused("dns-name-invalid")
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or any(char in value for char in '\"\\/;:*'):
        raise DnsRefused("dns-name-invalid")
    name = value.lower()
    if name.endswith("."):
        name = name[:-1]
    if not name.endswith(".home.arpa") or name == "home.arpa":
        raise DnsRefused("dns-name-outside-home-arpa")
    labels = name.split(".")
    if any(not label or len(label.encode("ascii", "ignore")) > MAX_LABEL_BYTES or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        raise DnsRefused("dns-name-invalid")
    return name + "."


def admit_private_ipv4(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 15:
        raise DnsRefused("dns-address-invalid")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise DnsRefused("dns-address-invalid") from exc
    if not isinstance(address, ipaddress.IPv4Address) or not address.is_private or address.is_unspecified or address.is_loopback or address.is_multicast or address.is_link_local or int(address) == 0xffffffff:
        raise DnsRefused("dns-address-not-admitted")
    return str(address)


def _identity(stat_result: os.stat_result) -> tuple[int, int, int, int]:
    return (stat_result.st_dev, stat_result.st_ino, stat_result.st_uid, stat_result.st_gid)


def _identity_matches(path: Path, expected: tuple[int, int, int, int]) -> bool:
    try:
        observed = os.lstat(path)
    except OSError:
        return False
    return stat.S_ISREG(observed.st_mode) and not stat.S_ISLNK(observed.st_mode) and _identity(observed) == expected


def _open_locked_parent(path: Path) -> int:
    parent = path.parent
    try:
        before = os.lstat(parent)
        if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
            raise DnsRefused("dns-config-parent-refused")
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    except DnsRefused:
        raise
    except OSError as exc:
        raise DnsRefused("dns-config-parent-open-refused") from exc
    try:
        after = os.fstat(descriptor)
        if not stat.S_ISDIR(after.st_mode) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise DnsRefused("dns-config-parent-identity-refused")
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def _read_config(path: Path) -> tuple[bytes, os.stat_result, tuple[int, int, int, int]]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise DnsRefused("dns-config-open-refused") from exc
    try:
        file_stat = os.fstat(descriptor)
        path_stat = os.lstat(path)
        if not stat.S_ISREG(file_stat.st_mode) or stat.S_ISLNK(path_stat.st_mode) or _identity(file_stat) != _identity(path_stat):
            raise DnsRefused("dns-config-identity-refused")
        if file_stat.st_size > MAX_CONFIG_BYTES:
            raise DnsRefused("dns-config-too-large")
        chunks: list[bytes] = []
        total = 0
        while True:
            part = os.read(descriptor, 65536)
            if not part:
                break
            total += len(part)
            if total > MAX_CONFIG_BYTES:
                raise DnsRefused("dns-config-too-large")
            chunks.append(part)
        return b"".join(chunks), file_stat, _identity(file_stat)
    finally:
        os.close(descriptor)


def _newline_style(data: bytes) -> bytes:
    has_crlf = b"\r\n" in data
    remaining = data.replace(b"\r\n", b"")
    if has_crlf and b"\n" in remaining:
        raise DnsRefused("dns-config-mixed-newlines")
    return b"\r\n" if has_crlf else b"\n"


def _segments(data: bytes):
    position = 0
    for line in data.splitlines(keepends=True):
        yield position, position + len(line), line
        position += len(line)


def _server_bounds(data: bytes) -> tuple[int, int]:
    sections = []
    for start, end, raw in _segments(data):
        if _TOP_LEVEL.fullmatch(raw.rstrip(b"\r\n")):
            sections.append((start, end, raw.split(b":", 1)[0]))
    servers = [(start, end) for start, end, name in sections if name == b"server"]
    if len(servers) != 1:
        raise DnsRefused("dns-server-section-ambiguous")
    start = servers[0][1]
    later = [section_start for section_start, _, _ in sections if section_start >= start]
    return start, min(later) if later else len(data)


def _server_records(data: bytes, target: str | None = None) -> tuple[list[tuple[int, int, bytes, re.Match[bytes]]], list[dict[str, str]], int, int]:
    section_start, section_end = _server_bounds(data)
    target_b = target.encode("ascii") if target else None
    matches: list[tuple[int, int, bytes, re.Match[bytes]]] = []
    records: list[dict[str, str]] = []
    last_local_data: tuple[int, int, bytes, re.Match[bytes]] | None = None
    last_local_zone: tuple[int, int, bytes] | None = None
    for start, end, raw in _segments(data):
        if start < section_start or end > section_end:
            continue
        body = raw.rstrip(b"\r\n")
        record = _RECORD.fullmatch(body)
        if record:
            last_local_data = (start, end, raw, record)
            fields = record.group("body").split()
            same_name = bool(target_b and fields and fields[0].lower() == target_b)
            if same_name:
                if len(fields) != 3 or fields[1] != b"A":
                    raise DnsRefused("dns-target-record-ambiguous")
                try:
                    admit_private_ipv4(fields[2].decode("ascii"))
                except (UnicodeDecodeError, DnsRefused) as exc:
                    raise DnsRefused("dns-target-record-ambiguous") from exc
                matches.append((start, end, raw, record))
            if len(fields) == 3 and fields[1] == b"A":
                try:
                    name = normalize_name(fields[0].decode("ascii"))
                    address = admit_private_ipv4(fields[2].decode("ascii"))
                except (UnicodeDecodeError, DnsRefused):
                    pass
                else:
                    records.append({"name": name, "address": address})
        elif _LOCAL_ZONE.match(body):
            last_local_zone = (start, end, raw)
        elif target_b and body.lstrip().startswith(b"local-data:") and target_b in body.lower():
            raise DnsRefused("dns-target-record-ambiguous")
    if len(matches) > 1:
        raise DnsRefused("dns-target-record-ambiguous")
    insertion = section_end
    indent = b""
    if last_local_data:
        insertion = last_local_data[1]
        indent = last_local_data[3].group("prefix").split(b"local-data:", 1)[0]
    elif last_local_zone:
        insertion = last_local_zone[1]
        indent = _LOCAL_ZONE.match(last_local_zone[2].rstrip(b"\r\n")).group("prefix")
    return matches, records, insertion, section_end if insertion == section_end else insertion


def _candidate(data: bytes, action: str, name: str | None, address: str | None) -> tuple[bytes, list[dict[str, str]]]:
    newline = _newline_style(data)
    entries, records, insertion, section_end = _server_records(data, name if action != "status" else None)
    if action == "status":
        return data, records
    assert name is not None
    if action == "remove":
        if not entries:
            return data, records
        start, end, _, _ = entries[0]
        return data[:start] + data[end:], records
    assert address is not None
    if entries:
        start, end, raw, match = entries[0]
        prefix = match.group("prefix")
        suffix = match.group("suffix")
        rendered = prefix + f'"{name} A {address}"'.encode("ascii") + suffix + newline
        return data[:start] + rendered + data[end:], records
    if data and not data.endswith((b"\n", b"\r")):
        raise DnsRefused("dns-config-final-newline-required")
    _, _, last_insertion, _ = _server_records(data, name)
    anchor = data[:last_insertion].splitlines(keepends=True)[-1] if last_insertion else b""
    match = _RECORD.fullmatch(anchor.rstrip(b"\r\n"))
    zone_match = _LOCAL_ZONE.match(anchor.rstrip(b"\r\n"))
    if match:
        indent = match.group("prefix").split(b"local-data:", 1)[0]
    elif zone_match:
        indent = zone_match.group("prefix")
    else:
        indent = b""
    rendered = indent + f'local-data: "{name} A {address}"'.encode("ascii") + newline
    return data[:last_insertion] + rendered + data[last_insertion:], records


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("dns-config-short-write")
        view = view[written:]


def _checkconf(path: Path) -> tuple[bool, str]:
    binary = os.environ.get("CADUCEUS_UNBOUND_CHECKCONF", "unbound-checkconf")
    try:
        result = subprocess.run([binary, str(path)], text=True, capture_output=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return False, "dns-checkconf-unavailable"
    return result.returncode == 0, "" if result.returncode == 0 else "dns-checkconf-refused"


def _write_staged(path: Path, prefix: str, payload: bytes, metadata: os.stat_result) -> Path:
    descriptor, temporary = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    staged = Path(temporary)
    try:
        os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode))
        os.fchown(descriptor, metadata.st_uid, metadata.st_gid)
        _write_all(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return staged


def _stage_validate(path: Path, candidate: bytes, metadata: os.stat_result, checkconf: Callable[[Path], tuple[bool, str]]) -> tuple[bool, str]:
    staged = _write_staged(path, ".caduceus-unbound-", candidate, metadata)
    try:
        return checkconf(staged)
    finally:
        staged.unlink(missing_ok=True)


def _fsync_parent(path: Path) -> None:
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _install(path: Path, payload: bytes, metadata: os.stat_result, identity: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    if not _identity_matches(path, identity):
        raise DnsRefused("dns-config-identity-changed")
    staged = _write_staged(path, ".caduceus-unbound-", payload, metadata)
    try:
        if not _identity_matches(path, identity):
            raise DnsRefused("dns-config-identity-changed")
        os.replace(staged, path)
        _fsync_parent(path)
        installed = os.lstat(path)
        if not stat.S_ISREG(installed.st_mode) or stat.S_ISLNK(installed.st_mode):
            raise DnsRefused("dns-config-identity-changed")
        return _identity(installed)
    finally:
        staged.unlink(missing_ok=True)


def _restore(path: Path, original: bytes, metadata: os.stat_result, installed_identity: tuple[int, int, int, int]) -> None:
    if not _identity_matches(path, installed_identity):
        raise DnsRefused("dns-config-identity-changed")
    staged = _write_staged(path, ".caduceus-unbound-rollback-", original, metadata)
    try:
        if not _identity_matches(path, installed_identity):
            raise DnsRefused("dns-config-identity-changed")
        os.replace(staged, path)
        _fsync_parent(path)
    finally:
        staged.unlink(missing_ok=True)


def dispatch(intent: Any, *, config_path: Path = DEFAULT_CONFIG,
             checkconf: Callable[[Path], tuple[bool, str]] = _checkconf) -> dict[str, Any]:
    action = intent.get("action") if isinstance(intent, dict) else "invalid"
    name = address = None
    parent_descriptor: int | None = None
    try:
        if not isinstance(intent, dict) or set(intent) - {"action", "name", "address"}:
            raise DnsRefused("dns-intent-invalid")
        if action not in {"status", "ensure-local-data", "remove"}:
            raise DnsRefused("dns-intent-action-invalid")
        if action == "status":
            if set(intent) != {"action"}:
                raise DnsRefused("dns-intent-invalid")
        else:
            name = normalize_name(intent.get("name"))
            if action == "ensure-local-data":
                address = admit_private_ipv4(intent.get("address"))
            elif set(intent) != {"action", "name"}:
                raise DnsRefused("dns-intent-invalid")
        path = Path(config_path)
        parent_descriptor = _open_locked_parent(path)
        original, metadata, identity = _read_config(path)
        candidate, records = _candidate(original, action, name, address)
        before = hashlib.sha256(original).hexdigest()
        after = hashlib.sha256(candidate).hexdigest()
        if action == "status":
            valid, error = checkconf(path)
            return _receipt(action, ok=valid, changed=False, records=records, beforeSha256=before, afterSha256=after,
                            error=error or "none", validation="installed-validated" if valid else "installed-refused", rollback="not-needed")
        if candidate == original:
            valid, error = _stage_validate(path, candidate, metadata, checkconf)
            return _receipt(action, ok=valid, changed=False, name=name, address=address, error=error or "none", beforeSha256=before, afterSha256=after, validation="validated-noop", rollback="not-needed")
        valid, error = _stage_validate(path, candidate, metadata, checkconf)
        if not valid:
            return _receipt(action, ok=False, changed=False, name=name, address=address, error=error, beforeSha256=before, afterSha256=before, validation="candidate-refused", rollback="not-needed")
        installed_identity = _install(path, candidate, metadata, identity)
        valid, error = checkconf(path)
        if valid:
            return _receipt(action, ok=True, changed=True, name=name, address=address, beforeSha256=before, afterSha256=after, validation="installed-validated", rollback="not-needed")
        try:
            _restore(path, original, metadata, installed_identity)
            restored, restore_error = checkconf(path)
            return _receipt(action, ok=False, changed=False, name=name, address=address, error=error, beforeSha256=before, afterSha256=before, validation="installed-refused", rollback="restored" if restored else "restore-validation-failed", rollbackError=restore_error or "none")
        except DnsRefused as exc:
            return _receipt(action, ok=False, changed=False, name=name, address=address, error=error, beforeSha256=before, afterSha256=after, validation="installed-refused", rollback="refused-identity-changed", rollbackError=str(exc))
        except OSError:
            return _receipt(action, ok=False, changed=False, name=name, address=address, error=error, beforeSha256=before, afterSha256=after, validation="installed-refused", rollback="failed")
    except (DnsRefused, OSError) as exc:
        return _receipt(str(action), ok=False, changed=False, name=name, address=address, error=str(exc), validation="not-run", rollback="not-needed")
    finally:
        if parent_descriptor is not None:
            os.close(parent_descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-network-dns")
    parser.parse_args(argv)
    try:
        intent = json.load(__import__("sys").stdin)
    except json.JSONDecodeError:
        intent = {"action": "invalid"}
    value = dispatch(intent)
    print(json.dumps(value, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
