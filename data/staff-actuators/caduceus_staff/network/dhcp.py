"""Typed, public-safe Kea DHCP readbacks for the Caduceus staff lane."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
from pathlib import Path
from typing import Any

SCHEMA_ROOT = "caduceus.network.dhcp"


def _path(env_name: str, default: str) -> Path:
    return Path(os.environ.get(env_name, default))


def _config_path() -> Path:
    return _path("CADUCEUS_KEA_CONFIG", "/etc/kea/kea-dhcp4.conf")


def _leases_path() -> Path:
    return _path("CADUCEUS_KEA_LEASES", "/var/lib/kea/kea-leases4.csv")


def _load_config() -> dict[str, Any]:
    with _config_path().open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict) or not isinstance(value.get("Dhcp4"), dict):
        raise ValueError("Kea config has no Dhcp4 object")
    return value


def _envelope(kind: str, **payload: Any) -> dict[str, Any]:
    return {
        "schema": f"{SCHEMA_ROOT}.{kind}.v1",
        "ok": True,
        "execution": "caduceus_staff.network.dhcp",
        "mutationPerformed": False,
        "firstMissingSignal": "none",
        **payload,
    }


def status() -> dict[str, Any]:
    config_valid = True
    error = None
    try:
        config = _load_config()
        subnet_count = len(config["Dhcp4"].get("subnet4", []))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        config_valid = False
        subnet_count = 0
        error = str(exc)

    service_active: bool | None = None
    systemctl = os.environ.get("CADUCEUS_SYSTEMCTL", "systemctl")
    try:
        result = subprocess.run(
            [systemctl, "is-active", "--quiet", "kea-dhcp4-server.service"],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        service_active = result.returncode == 0
    except OSError:
        pass
    return _envelope(
        "status",
        configPath=str(_config_path()),
        leasesPath=str(_leases_path()),
        configValid=config_valid,
        serviceActive=service_active,
        subnetCount=subnet_count,
        configError=error,
    )


def leases() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    with _leases_path().open(newline="", encoding="utf-8") as stream:
        for row in csv.DictReader(stream):
            address = row.get("address", "").strip()
            if not address:
                continue
            rows.append(
                {
                    "ip": address,
                    "mac": row.get("hwaddr", "").strip().lower(),
                    "hostname": row.get("hostname", "").strip(),
                    "expiresAt": _integer(row.get("expire")),
                    "validLifetime": _integer(row.get("valid_lifetime")),
                    "subnetId": _integer(row.get("subnet_id")),
                    "state": _integer(row.get("state")),
                }
            )
    rows.sort(key=lambda item: _ip_key(item["ip"]))
    return _envelope("leases", count=len(rows), leases=rows)


def reservations() -> dict[str, Any]:
    config = _load_config()
    rows: list[dict[str, Any]] = []
    for subnet in config["Dhcp4"].get("subnet4", []):
        if not isinstance(subnet, dict):
            continue
        for reservation in subnet.get("reservations", []):
            if not isinstance(reservation, dict):
                continue
            rows.append(
                {
                    "ip": reservation.get("ip-address"),
                    "mac": reservation.get("hw-address"),
                    "hostname": reservation.get("hostname"),
                    "subnet": subnet.get("subnet"),
                    "subnetId": subnet.get("id"),
                }
            )
    rows.sort(key=lambda item: _ip_key(str(item.get("ip") or "")))
    return _envelope("reservations", count=len(rows), reservations=rows)


def _integer(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _ip_key(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return (999, 999, 999, 999)


def intent(method: str, route: str, metadata: dict[str, Any]) -> dict[str, Any]:
    if method in {"GET", "HEAD"} and route.rstrip("/").endswith("/leases"):
        return leases()
    if method in {"GET", "HEAD"} and route.rstrip("/").endswith("/reservations"):
        return reservations()
    if method in {"GET", "HEAD"} and route.rstrip("/").endswith("/status"):
        return status()
    raise ValueError("caduceus-network-dhcp-intent-not-admitted")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="caduceus-network-dhcp")
    parser.add_argument("command", choices=("status", "leases", "reservations", "intent"))
    parser.add_argument("method", nargs="?")
    parser.add_argument("route", nargs="?")
    parser.add_argument("--metadata-json", default="{}")
    args = parser.parse_args(argv)
    try:
        if args.command == "status":
            result = status()
        elif args.command == "leases":
            result = leases()
        elif args.command == "reservations":
            result = reservations()
        else:
            if not args.method or not args.route:
                raise ValueError("caduceus-network-dhcp-intent-shape")
            metadata = json.loads(args.metadata_json)
            if not isinstance(metadata, dict):
                raise ValueError("caduceus-network-dhcp-metadata-invalid")
            result = intent(args.method.upper(), args.route, metadata)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "schema": f"{SCHEMA_ROOT}.error.v1",
            "ok": False,
            "firstMissingSignal": str(exc),
            "mutationPerformed": False,
        }, sort_keys=True))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
