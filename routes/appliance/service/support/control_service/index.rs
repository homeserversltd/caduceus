use crate::shared::config;
use serde_json::{json, Value};
use std::time::Duration;

// The budgets of routes/transmission/{up,down}, not the unit-band timeout.
const TRANSMISSION_UP: (&str, Duration) = ("transmission/up", Duration::from_secs(600));
const TRANSMISSION_DOWN: (&str, Duration) = ("transmission/down", Duration::from_secs(180));
const TRANSMISSION_START_NOT_ON: &str = "caduceus-transmission-start-not-on";

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

    if crate::routes::profile_routes::ACTIVE_PROFILE == "homeserver"
        && normalized == "transmissionVPN.service"
        && matches!(action, "start" | "stop" | "restart")
    {
        return Ok(execute_transmission_service(
            &metadata,
            service,
            action,
            systemd_service,
        ));
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
        // A crossed receipt stays whole even when the door cannot project it.
        let signal = if object.contains_key("portalService") {
            Some("caduceus-portal-service-projection-collision")
        } else {
            object.insert("portalService".into(), projection);
            (crossing_succeeded && projection_invalid)
                .then_some("caduceus-portal-service-receipt-invalid")
        };
        if let Some(signal) = signal {
            object.entry("doorSignal").or_insert_with(|| json!(signal));
        }
    }
    Ok(receipt)
}

fn chord_row<'a>(chord: &'a Value, id: &str) -> Option<&'a Value> {
    chord
        .get("stages")?
        .as_array()?
        .iter()
        .find(|stage| stage.get("stage_id").and_then(Value::as_str) == Some(id))
}

fn chord_stage<'a>(chord: &'a Value, id: &str) -> Option<&'a Value> {
    chord_row(chord, id)?.get("receipt")
}

fn missing_signal(value: &Value) -> Option<&str> {
    ["doorSignal", "firstMissingSignal", "error"]
        .into_iter()
        .filter_map(|key| value.get(key).and_then(Value::as_str))
        .find(|signal| {
            let word = signal.trim();
            !word.is_empty() && !word.eq_ignore_ascii_case("none")
        })
}

fn cross_transmission_chord((band, timeout): (&str, Duration)) -> (Value, Option<String>) {
    use crate::gate::{receipt_succeeded, snake::crossing_path_with_timeout};
    use crate::routes::leaf_schema::{aggregate_bound, bound};

    // The direct doors use a null payload when no chord arguments are supplied.
    let mut crossing = match crossing_path_with_timeout(band, &Value::Null, timeout) {
        Ok(crossing) => crossing,
        Err(signal) => return (Value::Null, Some(signal)),
    };
    let Some(receipt) = crossing.get_mut("receiptPayload").map(Value::take) else {
        return (Value::Null, Some("caduceus-snake-receipt-missing".into()));
    };
    let aggregate = aggregate_bound(&receipt, band);
    // Like the direct door, recognize the existing down stop as well as
    // an aggregate bound to that crossing. Up must supply an onness stage.
    let complete = if aggregate {
        receipt.get("failedStage").is_some_and(Value::is_null)
    } else {
        band == TRANSMISSION_DOWN.0
    };
    let failure = if !aggregate && !bound(&receipt, band) {
        Some("caduceus-schema-desync")
    } else if complete && receipt_succeeded(&crossing) && receipt_succeeded(&receipt) {
        None
    } else {
        let no_signal = if band == TRANSMISSION_UP.0 {
            TRANSMISSION_START_NOT_ON
        } else {
            "caduceus-agathodaimon-refused"
        };
        let stage_signal = receipt
            .get("failedStage")
            .and_then(Value::as_str)
            .filter(|_| aggregate)
            .and_then(|id| chord_row(&receipt, id))
            .and_then(|row| {
                missing_signal(row).or_else(|| row.get("receipt").and_then(missing_signal))
            });
        Some(
            stage_signal
                .or_else(|| missing_signal(&receipt))
                .unwrap_or(no_signal),
        )
    };
    let failure = failure.map(str::to_owned);
    (receipt, failure)
}

fn execute_transmission_service(
    metadata: &Value,
    service: &str,
    action: &str,
    systemd_service: &str,
) -> Value {
    let mut chords = Vec::new();
    let mut chord = if action == "start" {
        TRANSMISSION_UP
    } else {
        TRANSMISSION_DOWN
    };
    let (mut receipt, mut failure) = cross_transmission_chord(chord);
    if action == "restart" && failure.is_none() {
        chords.push(receipt);
        chord = TRANSMISSION_UP;
        (receipt, failure) = cross_transmission_chord(chord);
    }

    let execution = chord.0;
    // An unbound answer still rides whole, but cannot supply this unit's readback.
    let up_receipt = (execution == TRANSMISSION_UP.0
        && crate::routes::leaf_schema::aggregate_bound(&receipt, execution))
    .then_some(&receipt);
    // sbin transmission/onness answers ok true only once Transmission reads on,
    // and nests the reading under "onness" (agathodaimon/transmission/onness/index.py).
    let on = up_receipt
        .and_then(|up| chord_stage(up, "onness"))
        .is_some_and(|stage| {
            stage.get("ok").and_then(Value::as_bool) == Some(true)
                && stage
                    .pointer("/onness/on")
                    .or_else(|| stage.get("on"))
                    .and_then(Value::as_bool)
                    == Some(true)
        });
    if execution == TRANSMISSION_UP.0 && !on && failure.is_none() {
        failure = Some(TRANSMISSION_START_NOT_ON.into());
    }
    let ok = failure.is_none();
    let signal = failure.as_deref().unwrap_or("none");
    let native_start = up_receipt.and_then(|up| chord_stage(up, "native-start"));
    let active = native_start
        .and_then(|stage| stage.pointer("/readback/active_state"))
        .and_then(Value::as_str)
        .map(|state| matches!(state, "active" | "reloading"));
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
        "output": native_start.and_then(|stage| stage.get("output")).and_then(Value::as_str),
        "active": active,
        "enabled": native_start.and_then(|stage| stage.get("enabled")).and_then(Value::as_bool),
        "mutationPerformed": ok,
        "execution": execution,
        "firstMissingSignal": signal,
        "metadata": metadata
    });
    chords.push(receipt);
    json!({"ok": ok, "firstMissingSignal": signal, "portalService": projection, "transmissionChords": chords})
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
