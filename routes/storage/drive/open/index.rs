use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};
use std::time::Duration;

const COMMAND: &str = "staff intent";
const NAMESPACE: &str = "storage/drive/open";

fn native_refusal(status: StatusCode, signal: &str, could_change_to: Value, attempted: bool) -> (StatusCode, Json<Value>) {
    (status, Json(json!({
        "schema": "caduceus.staff.receipt.v1",
        "stop": {"noun": "storage/drive", "verb": "open"},
        "ok": false,
        "firstMissingSignal": signal,
        "observed": {"payloadFields": ["device"]},
        "could_change_to": could_change_to,
        "attempt": {"attempted": attempted},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    })))
}

fn valid_device(device: &str) -> bool {
    if device.len() > 128 {
        return false;
    }
    let Some(segment) = device.strip_prefix("/dev/") else {
        return false;
    };
    let mut bytes = segment.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_'))
        && bytes.all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b'+' | b'-'))
}

async fn route(Json(payload): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let device = payload.get("device").and_then(Value::as_str).filter(|device| valid_device(device))
        .ok_or_else(|| native_refusal(StatusCode::BAD_REQUEST, "caduceus-drive-device-invalid", json!({"device": "/dev/<name>"}), false))?
        .to_owned();
    if !matches!(crate::shared::policy::allows_command(COMMAND), Ok(true)) {
        return Err(native_refusal(StatusCode::SERVICE_UNAVAILABLE, "caduceus-carapace-desync", Value::Null, false));
    }
    let walked = crate::gate::blocking_task(COMMAND, move || {
        crate::gate::snake::crossing_path_with_timeout(NAMESPACE, &json!({"device": device}), Duration::from_secs(600))
    }).await.map_err(|_| native_refusal(StatusCode::SERVICE_UNAVAILABLE, "caduceus-blocking-task-join-failed", Value::Null, true))?
      .map_err(|signal| native_refusal(StatusCode::SERVICE_UNAVAILABLE, &signal, Value::Null, true))?;
    let mut receipt = walked.get("receiptPayload").cloned().filter(Value::is_object)
        .ok_or_else(|| native_refusal(StatusCode::SERVICE_UNAVAILABLE, "caduceus-staff-invalid-receipt", Value::Null, true))?;
    if !crate::routes::leaf_schema::bound(&receipt, NAMESPACE) {
        if let Some(object) = receipt.as_object_mut() {
            object.entry("doorSignal").or_insert_with(|| json!("caduceus-schema-desync"));
            object.entry("crossedStop").or_insert_with(|| json!(NAMESPACE));
        }
        return Ok((StatusCode::SERVICE_UNAVAILABLE, Json(receipt)));
    }
    if walked.get("ok").and_then(Value::as_bool) != Some(true)
        && receipt.get("ok").and_then(Value::as_bool) != Some(false)
    {
        if let Some(object) = receipt.as_object_mut() {
            object.entry("doorSignal").or_insert_with(|| {
                Value::String(walked.get("firstMissingSignal").and_then(Value::as_str)
                    .filter(|signal| !signal.is_empty() && *signal != "none")
                    .unwrap_or("caduceus-agathodaimon-refused").to_string())
            });
        }
    }
    if receipt.get("ok").and_then(Value::as_bool) == Some(true) {
        crate::stats::disk_census::request_refresh();
    }
    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/storage/drive/open", axum::routing::post(route))
}
