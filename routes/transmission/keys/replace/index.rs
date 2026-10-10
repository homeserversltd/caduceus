use axum::{
    extract::{rejection::JsonRejection, Json},
    http::StatusCode,
    Router,
};
use serde_json::{json, Map, Value};
use std::time::Duration;

const COMMAND: &str = "transmission keys replace";
const SCHEMA: &str = "caduceus.transmission.keys.v1";
const TIMEOUT: Duration = Duration::from_secs(600);

fn bad_request(
    signal: &'static str,
) -> (StatusCode, Json<crate::gate::ApiErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(crate::gate::ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: COMMAND.to_string(),
            first_missing_signal: signal.to_string(),
        }),
    )
}

fn replacement_payload(body: Value) -> Result<Value, &'static str> {
    let Some(object) = body.as_object() else {
        return Err("caduceus-transmission-keys-request-invalid");
    };
    if object.contains_key("action") {
        return Err("caduceus-transmission-keys-client-action-forbidden");
    }
    for field in ["service", "username", "password"] {
        let Some(value) = object.get(field).and_then(Value::as_str) else {
            return Err("caduceus-transmission-keys-request-invalid");
        };
        if value.is_empty()
            || value
                .chars()
                .any(|character| matches!(character, '\n' | '\r' | '\0'))
        {
            return Err("caduceus-transmission-keys-request-invalid");
        }
    }
    let mut payload = body;
    payload["action"] = Value::String("replace".to_string());
    Ok(payload)
}

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

async fn replace_route(
    body: Result<Json<Value>, JsonRejection>,
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

    let body = body
        .map(|Json(value)| value)
        .map_err(|_| bad_request("caduceus-transmission-keys-request-invalid"))?;
    let payload = replacement_payload(body).map_err(bad_request)?;
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
    router.route(
        "/api/v1/transmission/keys/replace",
        axum::routing::post(replace_route),
    )
}
