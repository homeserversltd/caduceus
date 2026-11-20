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

    let payload = json!({"service": service});
    let band = match action {
        "start" => "appliance/service/start",
        "stop" => "appliance/service/stop",
        "restart" => "appliance/service/restart",
        "enable" => "appliance/service/enable",
        "disable" => "appliance/service/disable",
        "status" => "appliance/service/status",
        _ => return Err("caduceus-portal-service-intent-invalid".to_string()),
    };
    let mut receipt = crate::gate::snake::crossing_path_receipt(band, &payload)?;
    let active = receipt
        .get("active")
        .filter(|value| value.is_boolean() || value.is_null());
    let enabled = receipt.get("enabled").and_then(Value::as_bool);
    let output = receipt.get("output").and_then(Value::as_str);
    let first_missing_signal = receipt.get("firstMissingSignal").and_then(Value::as_str);
    let projection_invalid = active.is_none() || output.is_none() || first_missing_signal.is_none();
    let crossing_succeeded = crate::gate::receipt_succeeded(&receipt);
    let ok = crossing_succeeded && !projection_invalid;

    let projection = json!({
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
        "enabled": enabled,
        "mutationPerformed": action != "status" && ok,
        "execution": "systemctl",
        "firstMissingSignal": first_missing_signal,
        "metadata": metadata
    });
    if let Some(object) = receipt.as_object_mut() {
        // A missing projection field must not turn a crossed receipt into a bare error.
        if crossing_succeeded && projection_invalid {
            object.insert(
                "doorSignal".into(),
                json!("caduceus-portal-service-receipt-invalid"),
            );
        }
        object.entry("portalService").or_insert(projection);
    }
    Ok(receipt)
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
