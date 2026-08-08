"""Caduceus Keyman door callers.

This is deliberately only a redacting transport and strategy membrane around the
standing Vault scripts and cryptsetup.  It never reads or rewrites Keyman files,
SSH material, lan.key, or authorized_keys.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Sequence

SCHEMA = "caduceus.keyman.door.v1"
MAX_INPUT_BYTES = 64 * 1024
VAULT_NEWKEY = "/vault/keyman/newkey.sh"
EXPORT_NAS = "/vault/scripts/exportNAS.sh"
EXPORT_SUITE = "/vault/scripts/exportServiceSuite.sh"
CHANGE_SUITE = "/vault/keyman/change_service_suite_key.sh"
CRYPTSETUP = "/usr/sbin/cryptsetup"
CHPASSWD = "/usr/sbin/chpasswd"
SMBPASSWD = "/usr/bin/smbpasswd"
SYSTEMCTL = "/usr/bin/systemctl"
SYSTEMD_RUN = "/usr/bin/systemd-run"
SSHD = "/usr/sbin/sshd"
SSH_CONFIG = Path("/etc/ssh/sshd_config")
SSH_UNITS = ("ssh.service", "sshd.service")
SAMBA_UNITS = ("smbd.service", "nmbd.service", "avahi-daemon.service", "wsdd2.service")
PASSWORD_AUTH_LINE = re.compile(r"^(?P<prefix>\s*)PasswordAuthentication\s+(?:yes|no)\s*(?:#.*)?$", re.IGNORECASE)


class Refusal(ValueError):
    pass


def _receipt(action: str, ok: bool, *, planned: bool, commands: list[list[str]], signal: str = "none", **extra: Any) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "ok": ok,
        "action": action,
        "planned": planned,
        "mutationPerformed": False if planned else ok,
        "commands": commands,
        "firstMissingSignal": signal,
        **extra,
    }


def _redacted(argv: Sequence[str]) -> list[str]:
    redacted = list(argv)
    if redacted[:3] == ["sudo", "-n", VAULT_NEWKEY]:
        redacted[-1] = "[REDACTED]"
    elif redacted[:4] == ["sudo", "-n", CHANGE_SUITE, "--non-interactive"]:
        redacted[-2:] = ["[REDACTED]", "[REDACTED]"]
    return redacted


def _run(argv: list[str], *, secret_input: str | None = None) -> subprocess.CompletedProcess[str]:
    # Secrets go only to the child's stdin or its required script arguments; neither
    # argv nor child output is serialized into a Caduceus receipt or log record.
    return subprocess.run(argv, input=secret_input, text=True, capture_output=True, check=False)


def _required(payload: dict[str, Any], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise Refusal(f"caduceus-keyman-{name}-required")
    return value


def _device(value: Any) -> str:
    if not isinstance(value, str) or not value.startswith("/dev/") or "\x00" in value:
        raise Refusal("caduceus-keyman-device-invalid")
    return value


def _strategy(payload: dict[str, Any]) -> str:
    value = payload.get("strategy")
    if value not in {"replace_primary", "safe_rotation", "flexible_addition"}:
        raise Refusal("caduceus-keyman-strategy-invalid")
    return str(value)


def _sudo(argv: list[str]) -> list[str]:
    return ["sudo", "-n", *argv]


def _luks_dump(device: str, *, planned: bool) -> tuple[list[list[str]], str]:
    command = _sudo([CRYPTSETUP, "luksDump", device])
    commands = [_redacted(command)]
    if planned:
        return commands, ""
    result = _run(command)
    if result.returncode != 0:
        raise Refusal("caduceus-keyman-luks-status-refused")
    return commands, result.stdout


def _enabled_slots(luks_dump: str) -> set[int]:
    slots: set[int] = set()
    for line in luks_dump.splitlines():
        candidate = line.strip().split(":", 1)
        if len(candidate) == 2 and candidate[0].isdigit() and "luks" in candidate[1].lower():
            slots.add(int(candidate[0]))
    return slots


def _apply_strategy(device: str, strategy: str, current_password: str, new_password: str, *, flexible_option: Any, key_slot: Any, planned: bool) -> list[list[str]]:
    status_commands, dump = _luks_dump(device, planned=planned)
    commands = status_commands
    slots = _enabled_slots(dump)
    if strategy == "replace_primary":
        # OG's safe primary replacement stages slot 1, then settles slot 0.
        if 1 in slots:
            commands.append(_redacted(_sudo([CRYPTSETUP, "luksKillSlot", device, "1"])))
        commands.append(_redacted(_sudo([CRYPTSETUP, "luksAddKey", device, "--key-slot", "1"])))
        for slot in sorted(slots - {1}):
            commands.append(_redacted(_sudo([CRYPTSETUP, "luksKillSlot", device, str(slot)])))
        commands.append(_redacted(_sudo([CRYPTSETUP, "luksAddKey", device, "--key-slot", "0"])))
        commands.append(_redacted(_sudo([CRYPTSETUP, "luksKillSlot", device, "1"])))
        if not planned:
            _execute_primary(device, slots, current_password, new_password)
        return commands
    if strategy == "safe_rotation":
        if 1 in slots:
            commands.append(_redacted(_sudo([CRYPTSETUP, "luksKillSlot", device, "1"])))
            if not planned:
                _must(_run(_sudo([CRYPTSETUP, "luksKillSlot", device, "1"]), secret_input=current_password), "caduceus-keyman-slot-remove-refused")
        commands.append(_redacted(_sudo([CRYPTSETUP, "luksAddKey", device, "--key-slot", "1"])))
        if not planned:
            _must(_run(_sudo([CRYPTSETUP, "luksAddKey", device, "--key-slot", "1"]), secret_input=f"{current_password}\n{new_password}\n{new_password}\n"), "caduceus-keyman-slot-add-refused")
        return commands
    if not isinstance(flexible_option, str) or flexible_option not in {"manual", "random"}:
        raise Refusal("caduceus-keyman-flexible-option-required")
    if flexible_option == "manual":
        if not isinstance(key_slot, int) or not 1 <= key_slot <= 31:
            raise Refusal("caduceus-keyman-slot-invalid")
        slot = key_slot
    else:
        candidates = sorted(slots - {0})
        if not candidates:
            raise Refusal("caduceus-keyman-flexible-slot-unavailable")
        slot = candidates[0]
    commands.append(_redacted(_sudo([CRYPTSETUP, "luksKillSlot", device, str(slot)])))
    commands.append(_redacted(_sudo([CRYPTSETUP, "luksAddKey", device, "--key-slot", str(slot)])))
    if not planned:
        _must(_run(_sudo([CRYPTSETUP, "luksKillSlot", device, str(slot)]), secret_input=current_password), "caduceus-keyman-slot-remove-refused")
        _must(_run(_sudo([CRYPTSETUP, "luksAddKey", device, "--key-slot", str(slot)]), secret_input=f"{current_password}\n{new_password}\n{new_password}\n"), "caduceus-keyman-slot-add-refused")
    return commands


def _execute_primary(device: str, slots: set[int], current_password: str, new_password: str) -> None:
    if 1 in slots:
        _must(_run(_sudo([CRYPTSETUP, "luksKillSlot", device, "1"]), secret_input=current_password), "caduceus-keyman-slot-remove-refused")
    _must(_run(_sudo([CRYPTSETUP, "luksAddKey", device, "--key-slot", "1"]), secret_input=f"{current_password}\n{new_password}\n{new_password}\n"), "caduceus-keyman-slot-add-refused")
    for slot in sorted(slots - {1}):
        _must(_run(_sudo([CRYPTSETUP, "luksKillSlot", device, str(slot)]), secret_input=new_password), "caduceus-keyman-slot-remove-refused")
    _must(_run(_sudo([CRYPTSETUP, "luksAddKey", device, "--key-slot", "0"]), secret_input=f"{new_password}\n{new_password}\n{new_password}\n"), "caduceus-keyman-slot-add-refused")
    _must(_run(_sudo([CRYPTSETUP, "luksKillSlot", device, "1"]), secret_input=new_password), "caduceus-keyman-slot-remove-refused")


def _must(result: subprocess.CompletedProcess[str], signal: str) -> None:
    if result.returncode != 0:
        raise Refusal(signal)


def _export_nas(*, planned: bool) -> tuple[list[list[str]], str]:
    command = _sudo([EXPORT_NAS])
    commands = [_redacted(command)]
    if planned:
        return commands, ""
    result = _run(command)
    _must(result, "caduceus-keyman-nas-export-refused")
    secret = result.stdout.strip()
    if not secret:
        raise Refusal("caduceus-keyman-nas-export-empty")
    return commands, secret


def create(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    target = payload.get("target")
    if target not in {"vault", "external", "both"}:
        raise Refusal("caduceus-keyman-target-invalid")
    strategy = _strategy(payload)
    password = _required(payload, "password")
    devices = payload.get("devices")
    if not isinstance(devices, list) or not devices:
        raise Refusal("caduceus-keyman-devices-required")
    devices = [_device(item) for item in devices]
    commands: list[list[str]] = []
    if target in {"vault", "both"}:
        vault_password = _required(payload, "vaultPassword")
        commands.extend(_apply_strategy(devices[0], strategy, vault_password, password, flexible_option=payload.get("flexibleOption"), key_slot=payload.get("keySlot"), planned=planned))
    if target in {"external", "both"}:
        newkey = _sudo([VAULT_NEWKEY, "nas", "admin", password])
        commands.append(_redacted(newkey))
        if not planned:
            _must(_run(newkey), "caduceus-keyman-nas-create-refused")
        export_commands, nas_password = _export_nas(planned=planned)
        commands.extend(export_commands)
        passwords = payload.get("devicePasswords", {})
        if not isinstance(passwords, dict):
            raise Refusal("caduceus-keyman-device-passwords-invalid")
        for device in devices:
            if target == "both" and device == devices[0]:
                continue
            current = passwords.get(device)
            if not isinstance(current, str) or not current:
                raise Refusal("caduceus-keyman-device-password-required")
            commands.extend(_apply_strategy(device, strategy, current, nas_password, flexible_option=payload.get("flexibleOption"), key_slot=payload.get("keySlot"), planned=planned))
    return _receipt("create-key", True, planned=planned, commands=commands, target=target, strategy=strategy)


def update(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    device = _device(payload.get("device"))
    strategy = _strategy(payload)
    current = _required(payload, "currentPassword")
    verify = _sudo([CRYPTSETUP, "open", "--test-passphrase", device])
    commands = [_redacted(verify)]
    if not planned:
        _must(_run(verify, secret_input=current), "caduceus-keyman-current-password-invalid")
    export_commands, nas_password = _export_nas(planned=planned)
    commands.extend(export_commands)
    commands.extend(_apply_strategy(device, strategy, current, nas_password, flexible_option=payload.get("flexibleOption"), key_slot=payload.get("keySlot"), planned=planned))
    return _receipt("update-key", True, planned=planned, commands=commands, device=device, strategy=strategy)


def admin_password(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    old = _required(payload, "oldPassword")
    new = _required(payload, "newPassword")
    samba_user = payload.get("sambaUser", "admin")
    if not isinstance(samba_user, str) or not samba_user or any(not (part.isalnum() or part in "_-.") for part in samba_user):
        raise Refusal("caduceus-keyman-samba-user-invalid")
    export = _sudo([EXPORT_SUITE])
    rotate = _sudo([CHANGE_SUITE, "--non-interactive", old, new])
    rollback = _sudo([CHANGE_SUITE, "--non-interactive", new, old])
    chpasswd = _sudo([CHPASSWD])
    smbpwd = _sudo([SMBPASSWD, "-s", samba_user])
    ssh = _sudo([SYSTEMCTL, "restart", "ssh.service"])
    sshd = _sudo([SYSTEMCTL, "restart", "sshd.service"])
    smbd = _sudo([SYSTEMCTL, "restart", "smbd.service"])
    commands = [_redacted(export), _redacted(rotate), _redacted(chpasswd), _redacted(smbpwd), _redacted(ssh), _redacted(sshd), _redacted(smbd)]
    if planned:
        return _receipt("admin-password", True, planned=True, commands=commands, rollbackCommand=_redacted(rollback), sambaUser=samba_user)
    exported = _run(export)
    _must(exported, "caduceus-keyman-service-suite-export-refused")
    if exported.stdout.strip() != old:
        raise Refusal("caduceus-keyman-current-password-invalid")
    _must(_run(rotate), "caduceus-keyman-service-suite-rotate-refused")
    owner = _run(chpasswd, secret_input=f"owner:{new}\n")
    if owner.returncode != 0:
        reverted = _run(rollback)
        signal = "caduceus-keyman-owner-password-refused" if reverted.returncode == 0 else "caduceus-keyman-owner-password-and-rollback-refused"
        return _receipt("admin-password", False, planned=False, commands=commands, rollbackCommand=_redacted(rollback), signal=signal, serviceSuiteRolledBack=reverted.returncode == 0)
    _must(_run(smbpwd, secret_input=f"{new}\n{new}\n"), "caduceus-keyman-samba-password-refused")
    # OG restarts ssh then falls back to sshd, and does not make a restart failure a false password failure.
    if _run(ssh).returncode != 0:
        _run(sshd)
    _run(smbd)
    return _receipt("admin-password", True, planned=False, commands=commands, sambaUser=samba_user)


def key_status(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    device = _device(payload.get("device"))
    commands, dump = _luks_dump(device, planned=planned)
    return _receipt("key-status", True, planned=planned, commands=commands, device=device, status="not-run" if planned else "read", enabledSlots=sorted(_enabled_slots(dump)) if not planned else [])


def _unit_state(unit: str) -> tuple[dict[str, Any], list[list[str]]]:
    commands = [
        [SYSTEMCTL, "is-active", unit],
        [SYSTEMCTL, "is-enabled", unit],
        [SYSTEMCTL, "show", "--property=LoadState", "--value", unit],
    ]
    active, enabled, load = (_run(command) for command in commands)
    load_state = load.stdout.strip() or "not-found"
    present = load.returncode == 0 and load_state != "not-found"
    return {
        "unit": unit,
        "present": present,
        "active": active.stdout.strip() == "active",
        "enabled": enabled.stdout.strip() == "enabled",
        "activeState": active.stdout.strip() or "unknown",
        "enabledState": enabled.stdout.strip() or "unknown",
        "loadState": load_state,
    }, commands


def _units_status(units: Sequence[str]) -> tuple[list[dict[str, Any]], list[list[str]]]:
    states: list[dict[str, Any]] = []
    commands: list[list[str]] = []
    for unit in units:
        state, observed = _unit_state(unit)
        states.append(state)
        commands.extend(observed)
    return states, commands


def ssh_password_authentication_status(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    del payload, planned
    command = _sudo([SSHD, "-T"])
    result = _run(command)
    _must(result, "caduceus-service-ssh-config-read-refused")
    value = next((line.split(None, 1)[1] for line in result.stdout.splitlines() if line.lower().startswith("passwordauthentication ")), None)
    if value not in {"yes", "no"}:
        raise Refusal("caduceus-service-ssh-password-authentication-missing")
    return _receipt("ssh-password-authentication-status", True, planned=False, commands=[_redacted(command)], passwordAuthentication=value, enabled=value == "yes")


def _desired_enabled(payload: dict[str, Any]) -> bool:
    value = payload.get("enabled")
    if not isinstance(value, bool):
        raise Refusal("caduceus-service-enabled-required")
    return value


def ssh_password_authentication_toggle(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    enabled = _desired_enabled(payload)
    desired = "yes" if enabled else "no"
    script = f"s/^[[:space:]]*PasswordAuthentication[[:space:]]+(yes|no)[[:space:]]*(#.*)?$/PasswordAuthentication {desired}/I"
    edit = _sudo(["/usr/bin/sed", "-i", "-E", script, str(SSH_CONFIG)])
    validate = _sudo([SSHD, "-t"])
    reload_commands = [_sudo([SYSTEMCTL, "reload", unit]) for unit in SSH_UNITS]
    commands = [_redacted(edit), _redacted(validate), *(_redacted(command) for command in reload_commands)]
    if planned:
        return _receipt("ssh-password-authentication-toggle", True, planned=True, commands=commands, enabled=enabled)
    try:
        lines = SSH_CONFIG.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise Refusal("caduceus-service-ssh-config-read-refused") from exc
    if sum(1 for line in lines if PASSWORD_AUTH_LINE.fullmatch(line)) != 1:
        raise Refusal("caduceus-service-ssh-password-authentication-line-ambiguous")
    _must(_run(edit), "caduceus-service-ssh-password-authentication-write-refused")
    _must(_run(validate), "caduceus-service-ssh-config-invalid")
    if all(_run(command).returncode != 0 for command in reload_commands):
        raise Refusal("caduceus-service-ssh-reload-refused")
    return _receipt("ssh-password-authentication-toggle", True, planned=False, commands=commands, enabled=enabled)


def service_status(payload: dict[str, Any], *, planned: bool, action: str) -> dict[str, Any]:
    del payload, planned
    units = SSH_UNITS if action == "ssh-service-status" else SAMBA_UNITS
    states, commands = _units_status(units)
    return _receipt(action, True, planned=False, commands=commands, services=states)


def service_toggle(payload: dict[str, Any], *, planned: bool, action: str) -> dict[str, Any]:
    enabled = _desired_enabled(payload)
    units = SSH_UNITS if action == "ssh-service-toggle" else SAMBA_UNITS
    states, observed = _units_status(units)
    present_units = [state["unit"] for state in states if state["present"]]
    if not present_units:
        raise Refusal("caduceus-service-unit-missing")
    command_action = "enable" if enabled else "disable"
    commands = [_redacted(_sudo([SYSTEMCTL, command_action, "--now", unit])) for unit in present_units]
    if planned:
        return _receipt(action, True, planned=True, commands=[*observed, *commands], enabled=enabled, services=states)
    failures = [_run(_sudo([SYSTEMCTL, command_action, "--now", unit])).returncode for unit in present_units]
    if any(failures):
        raise Refusal("caduceus-service-control-refused")
    states, observed = _units_status(units)
    return _receipt(action, True, planned=False, commands=[*commands, *observed], enabled=enabled, services=states)


def system_power(payload: dict[str, Any], *, planned: bool, action: str) -> dict[str, Any]:
    del payload
    verb = "reboot" if action == "system-restart" else "poweroff"
    command = _sudo([SYSTEMCTL, verb])
    if planned:
        return _receipt(action, True, planned=True, commands=[_redacted(command)])
    _must(_run(command), "caduceus-service-system-power-refused")
    return _receipt(action, True, planned=False, commands=[_redacted(command)])


def website_hard_reset(payload: dict[str, Any], *, planned: bool) -> dict[str, Any]:
    del payload
    commands = [
        _redacted(_sudo([SYSTEMD_RUN, "--no-block", "--on-active=2", SYSTEMCTL, "restart", "coronatio.service"])),
        _redacted(_sudo([SYSTEMD_RUN, "--no-block", "--on-active=2", SYSTEMCTL, "restart", "nginx.service"])),
    ]
    if planned:
        return _receipt("website-hard-reset", True, planned=True, commands=commands, delayedSeconds=2)
    # systemd schedules both restarts after the HTTP handler has returned.
    for command in commands:
        _must(_run(command), "caduceus-service-hard-reset-refused")
    return _receipt("website-hard-reset", True, planned=False, commands=commands, delayedSeconds=2)


def dispatch(payload: dict[str, Any]) -> dict[str, Any]:
    if set(payload) - {"actuator", "metadata"}:
        raise Refusal("caduceus-keyman-envelope-invalid")
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        raise Refusal("caduceus-keyman-request-invalid")
    action = metadata.get("action")
    planned = metadata.get("dryRun", False)
    if not isinstance(planned, bool):
        raise Refusal("caduceus-keyman-dry-run-invalid")
    if action == "create-key": return create(metadata, planned=planned)
    if action == "update-key": return update(metadata, planned=planned)
    if action == "admin-password": return admin_password(metadata, planned=planned)
    if action == "key-status": return key_status(metadata, planned=planned)
    if action == "ssh-password-authentication-status": return ssh_password_authentication_status(metadata, planned=planned)
    if action == "ssh-password-authentication-toggle": return ssh_password_authentication_toggle(metadata, planned=planned)
    if action in {"ssh-service-status", "samba-service-status"}: return service_status(metadata, planned=planned, action=action)
    if action in {"ssh-service-toggle", "samba-service-toggle"}: return service_toggle(metadata, planned=planned, action=action)
    if action in {"system-restart", "system-shutdown"}: return system_power(metadata, planned=planned, action=action)
    if action == "website-hard-reset": return website_hard_reset(metadata, planned=planned)
    raise Refusal("caduceus-keyman-action-invalid")


def main(argv: Sequence[str] | None = None) -> int:
    del argv
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    try:
        if len(raw) > MAX_INPUT_BYTES:
            raise Refusal("caduceus-keyman-request-too-large")
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise Refusal("caduceus-keyman-request-invalid")
        receipt = dispatch(value)
    except (UnicodeDecodeError, json.JSONDecodeError, Refusal):
        signal = "caduceus-keyman-request-invalid"
        if isinstance(sys.exc_info()[1], Refusal):
            signal = str(sys.exc_info()[1])
        receipt = _receipt("unknown", False, planned=False, commands=[], signal=signal)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
