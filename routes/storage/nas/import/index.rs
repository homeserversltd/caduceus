use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};
use std::time::Duration;

const NAMESPACE: &str = "storage/nas/import";
const COMMAND: &str = "staff intent";

fn native_refusal(status: StatusCode, signal: &str, could_change_to: Value) -> (StatusCode, Json<Value>) {
    (status, Json(json!({
        "schema": "caduceus.staff.receipt.v1",
        "stop": {"noun": "storage/nas", "verb": "import"},
        "ok": false,
        "firstMissingSignal": signal,
        "observed": {"payloadFields": ["device"]},
        "could_change_to": could_change_to,
        "attempt": {"attempted": false},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    })))
}

fn valid_device(device: &str) -> bool {
    if device.len() > 128 {
        return false;
    }
    let Some(name) = device.strip_prefix("/dev/") else {
        return false;
    };
    let mut bytes = name.bytes();
    matches!(bytes.next(), Some(b) if b.is_ascii_alphanumeric() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'+' | b'-'))
}

async fn route(Json(payload): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let device = payload.get("device").and_then(Value::as_str)
        .filter(|device| valid_device(device))
        .ok_or_else(|| native_refusal(StatusCode::BAD_REQUEST, "caduceus-drive-device-invalid", json!({"device": "/dev/<name>"})))?
        .to_owned();
    if !matches!(crate::shared::policy::allows_command(COMMAND), Ok(true)) {
        return Err(native_refusal(StatusCode::SERVICE_UNAVAILABLE, "caduceus-carapace-desync", Value::Null));
    }

    let crossed = crate::gate::blocking_task(COMMAND, move || {
        crate::gate::snake::crossing_path_with_timeout(
            NAMESPACE, &json!({"device": device}), Duration::from_secs(600),
        )
    }).await.map_err(|(status, Json(body))| native_refusal(status, &body.first_missing_signal, Value::Null))?
        .map_err(|signal| native_refusal(StatusCode::SERVICE_UNAVAILABLE, &signal, Value::Null))?;
    let mut receipt = crossed.get("receiptPayload").cloned().filter(Value::is_object)
        .ok_or_else(|| native_refusal(StatusCode::SERVICE_UNAVAILABLE, "caduceus-staff-invalid-receipt", Value::Null))?;
    if !crate::routes::leaf_schema::bound(&receipt, NAMESPACE) {
        let object = receipt.as_object_mut().expect("receipt was checked as an object");
        object.entry("doorSignal").or_insert_with(|| json!("caduceus-schema-desync"));
        object.entry("crossedStop").or_insert_with(|| json!(NAMESPACE));
        return Ok((StatusCode::SERVICE_UNAVAILABLE, Json(receipt)));
    }
    if crossed.get("ok").and_then(Value::as_bool) != Some(true)
        && receipt.get("ok").and_then(Value::as_bool) != Some(false)
    {
        if let Some(object) = receipt.as_object_mut() {
            object.entry("doorSignal").or_insert_with(|| {
                Value::String(crossed.get("firstMissingSignal").and_then(Value::as_str)
                    .filter(|signal| !signal.is_empty() && *signal != "none")
                    .unwrap_or("caduceus-agathodaimon-refused").to_string())
            });
        }
    }
    if receipt.get("ok").and_then(Value::as_bool) == Some(true)
        && receipt.get("started").and_then(Value::as_bool) != Some(true)
    {
        if let Some(object) = receipt.as_object_mut() {
            object.entry("doorSignal").or_insert_with(|| json!("caduceus-nas-import-start-unconfirmed"));
        }
        return Ok((StatusCode::SERVICE_UNAVAILABLE, Json(receipt)));
    }
    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/storage/nas/import", axum::routing::post(route))
}
