use crate::shared::config;
use serde_json::{json, Value};

pub fn execute_registered_service(service: &str, action: &str) -> Result<Value, String> {
    execute_service_with_mode(json!({
        "service": service,
        "action": action,
        "systemdService": normalize_systemd_service(service),
    }))
}

fn execute_service_with_mode(metadata: Value) -> Result<Value, String> {
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

    let payload = json!({"action": action, "service": service});
    let receipt = match crate::gate::snake::crossing_path("appliance/service", &payload) {
        Ok(receipt) => receipt,
        // crossing_path preserves the refusal token but discards the band's
        // receiptPayload on a nonzero band exit, so output and active are unknown.
        Err(signal) if is_service_band_refusal(&signal) => json!({
            "ok": false,
            "active": null,
            "output": "",
            "firstMissingSignal": signal,
        }),
        Err(signal) => return Err(signal),
    };
    let ok = receipt
        .get("ok")
        .and_then(Value::as_bool)
        .ok_or_else(|| "caduceus-portal-service-receipt-invalid".to_string())?;
    let active = match receipt.get("active") {
        Some(Value::Bool(_) | Value::Null) => receipt["active"].clone(),
        _ => return Err("caduceus-portal-service-receipt-invalid".to_string()),
    };
    let output = receipt
        .get("output")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-portal-service-receipt-invalid".to_string())?;
    let first_missing_signal = receipt
        .get("firstMissingSignal")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-portal-service-receipt-invalid".to_string())?;

    Ok(json!({
        "schema": "caduceus.staff.portal_service.v1",
        "ok": ok,
        "accepted": true,
        "classification": "portal-service",
        "service": service,
        "action": action,
        "systemdService": systemd_service,
        "success": ok,
        "message": if ok { format!("Service {action} completed for {service}") } else { format!("Service {action} failed for {service}") },
        "output": output,
        "active": active,
        "mutationPerformed": action != "status" && ok,
        "execution": "systemctl",
        "firstMissingSignal": first_missing_signal,
        "metadata": metadata
    }))
}

fn is_service_band_refusal(signal: &str) -> bool {
    matches!(
        signal,
        "portal-service-action-invalid"
            | "portal-service-name-invalid"
            | "portal-service-not-allowed"
            | "portal-service-registry-unreadable"
            | "portal-service-systemctl-failed"
    )
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
