use axum::{http::StatusCode, Json, Router};
use serde_json::{json, Map, Value};
use std::time::Duration;

const COMMAND: &str = "transmission keys status";
const SCHEMA: &str = "caduceus.transmission.keys.v1";
const TIMEOUT: Duration = Duration::from_secs(180);

fn safe_service_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')
        })
}

fn project_keys(value: &Value) -> Option<Value> {
    if value.is_null() {
        return Some(Value::Null);
    }
    let entries = value.as_object()?;
    let mut projected = Map::new();
    for (name, state) in entries.iter().take(64) {
        if !safe_service_name(name) {
            continue;
        }
        if matches!(state.as_str(), Some("present" | "absent")) {
            projected.insert(name.clone(), state.clone());
        }
    }
    Some(Value::Object(projected))
}

fn project_lengths(value: &Value) -> Option<Value> {
    if value.is_null() {
        return Some(Value::Null);
    }
    let entries = value.as_object()?;
    let mut projected = Map::new();
    for field in ["username", "password"] {
        if let Some(length) = entries.get(field) {
            if length.is_null()
                || length
                    .as_u64()
                    .is_some_and(|length| length <= 2 * 1024 * 1024)
            {
                projected.insert(field.to_string(), length.clone());
            }
        }
    }
    Some(Value::Object(projected))
}

fn safe_signal(value: Option<&Value>, ok: bool) -> String {
    if ok {
        return "none".to_string();
    }
    value
        .and_then(Value::as_str)
        .filter(|signal| {
            !signal.is_empty()
                && signal.len() <= 160
                && *signal != "none"
                && signal.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
                })
        })
        .unwrap_or("caduceus-transmission-keys-operation-refused")
        .to_string()
}

fn safe_receipt(crossing: &Value) -> Option<Value> {
    let receipt = crossing.get("receiptPayload")?;
    if !crate::routes::leaf_schema::accepts(SCHEMA, receipt) {
        return None;
    }
    let crossing_ok = crossing.get("ok").and_then(Value::as_bool) == Some(true);
    let staff_ok = match receipt.get("ok") {
        Some(Value::Bool(ok)) => *ok,
        Some(Value::Null) | None => crossing_ok,
        Some(_) => false,
    };
    let ok = crossing_ok && staff_ok;
    let mut result = json!({
        "schema": SCHEMA,
        "ok": ok,
        "firstMissingSignal": safe_signal(receipt.get("firstMissingSignal"), ok),
    });
    if let Some(keys) = receipt.get("keys").and_then(project_keys) {
        result["keys"] = keys;
    }
    if let Some(lengths) = receipt.get("lengths").and_then(project_lengths) {
        result["lengths"] = lengths;
    }
    Some(result)
}

async fn status_route(
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    if crate::routes::profile_routes::ACTIVE_PROFILE != "homeserver" {
        return Err(crate::gate::api_error(COMMAND));
    }
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(crate::gate::api_error(COMMAND)),
        Err(_) => {
            return Err(crate::gate::api_error_signal(
                COMMAND,
                "caduceus-profile-missing",
            ));
        }
    }

    let payload = json!({"action":"status"});
    let crossed = crate::gate::blocking_task(COMMAND, move || {
        crate::gate::snake::crossing_path_with_timeout("transmission/keys", &payload, TIMEOUT)
    })
    .await?;
    let crossing = crossed.map_err(|_| {
        crate::gate::service_unavailable(
            COMMAND,
            "caduceus-transmission-keys-crossing-failed",
        )
    })?;
    let receipt = safe_receipt(&crossing).ok_or_else(|| {
        crate::gate::service_unavailable(
            COMMAND,
            "caduceus-transmission-keys-receipt-invalid",
        )
    })?;

    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/transmission/keys", axum::routing::get(status_route))
}
