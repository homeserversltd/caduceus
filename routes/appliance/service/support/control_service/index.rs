use crate::shared::config;
use serde_json::{json, Value};
use std::process::Command;
const SYSTEMCTL: &str = "/usr/bin/systemctl";

fn configured_systemctl() -> (String, bool) {
    if std::env::var_os("CADUCEUS_ROOT").is_some() {
        (
            std::env::var("CADUCEUS_SYSTEMCTL_BIN").unwrap_or_else(|_| SYSTEMCTL.to_string()),
            true,
        )
    } else {
        (SYSTEMCTL.to_string(), false)
    }
}

pub fn execute_service(metadata: Value) -> Result<Value, String> {
    let (systemctl, fixture) = configured_systemctl();
    execute_service_with_mode(metadata, &systemctl, fixture)
}

pub fn execute_registered_service(service: &str, action: &str) -> Result<Value, String> {
    let (systemctl, fixture) = configured_systemctl();
    execute_service_with_mode(
        json!({
            "service": service,
            "action": action,
            "systemdService": normalize_systemd_service(service),
        }),
        &systemctl,
        fixture,
    )
}

pub fn restart_registered_service(service: &str) -> Result<Value, String> {
    execute_registered_service(service, "restart")
}

pub fn execute_service_with(metadata: Value, systemctl: &str) -> Result<Value, String> {
    let fixture = std::env::var_os("CADUCEUS_ROOT").is_some();
    execute_service_with_mode(
        metadata,
        if fixture { systemctl } else { SYSTEMCTL },
        fixture,
    )
}

fn systemctl_output(
    systemctl: &str,
    fixture: bool,
    args: &[&str],
) -> std::io::Result<std::process::Output> {
    let mut command = if fixture {
        Command::new(systemctl)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.args(["-n", SYSTEMCTL]);
        command
    };
    command.args(args).output()
}

fn execute_service_with_mode(
    metadata: Value,
    systemctl: &str,
    fixture: bool,
) -> Result<Value, String> {
    let service = metadata
        .get("service")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-portal-service-name-missing".to_string())?;
    let action = metadata
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-portal-service-action-missing".to_string())?;
    let systemd_service = metadata
        .get("systemdService")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-portal-systemd-service-missing".to_string())?;
    if !safe_service_name(service)
        || !safe_service_name(systemd_service)
        || !matches!(
            action,
            "start" | "stop" | "restart" | "enable" | "disable" | "status"
        )
    {
        return Err("caduceus-portal-service-intent-invalid".to_string());
    }

    let allowed = portal_service_allowlist()?;
    let normalized = normalize_systemd_service(service);
    if systemd_service != normalized || !allowed.iter().any(|item| item == &normalized) {
        return Err("caduceus-portal-service-not-allowed".to_string());
    }

    let output = systemctl_output(systemctl, fixture, &[action, systemd_service])
        .map_err(|err| format!("caduceus-portal-systemctl-exec-failed: {err}"))?;
    let active_output = systemctl_output(systemctl, fixture, &["is-active", systemd_service])
        .map_err(|err| format!("caduceus-portal-systemctl-active-failed: {err}"))?;
    let command_output = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };
    let active = active_output.status.success()
        && String::from_utf8_lossy(&active_output.stdout).trim() == "active";

    Ok(json!({
        "schema": "caduceus.staff.portal_service.v1",
        "ok": output.status.success(),
        "accepted": true,
        "classification": "portal-service",
        "service": service,
        "action": action,
        "systemdService": systemd_service,
        "success": output.status.success(),
        "message": if output.status.success() { format!("Service {action} completed for {service}") } else { format!("Service {action} failed for {service}") },
        "output": command_output,
        "active": active,
        "mutationPerformed": action != "status" && output.status.success(),
        "execution": "systemctl",
        "firstMissingSignal": if output.status.success() { "none" } else { "portal-systemctl-command-failed" },
        "metadata": metadata
    }))
}

pub fn normalize_systemd_service(service: &str) -> String {
    if service.ends_with(".service") {
        service.to_string()
    } else {
        format!("{service}.service")
    }
}

pub fn portal_service_allowlist() -> Result<Vec<String>, String> {
    let value = config::show_json()
        .map_err(|err| format!("caduceus-homeserver-config-missing: {err}"))?
        .get("document")
        .cloned()
        .ok_or_else(|| "caduceus-homeserver-config-invalid".to_string())?;
    let portals = value
        .pointer("/tabs/portals/data/portals")
        .and_then(Value::as_array)
        .ok_or_else(|| "caduceus-homeserver-portals-missing".to_string())?;
    let mut services = portals
        .iter()
        .filter_map(|portal| portal.get("services").and_then(Value::as_array))
        .flatten()
        .filter_map(Value::as_str)
        .filter(|service| safe_service_name(service))
        .map(normalize_systemd_service)
        .collect::<Vec<_>>();
    services.sort();
    services.dedup();
    Ok(services)
}

pub fn safe_service_name(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}
