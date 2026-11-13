use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};
use std::time::Duration;

const NAMESPACE: &str = "storage/drive/remove";
const COMMAND: &str = "staff intent";

fn native_refusal(status: StatusCode, signal: &str, attempted: bool) -> (StatusCode, Json<Value>) {
    (status, Json(json!({
        "schema": "caduceus.staff.receipt.v1",
        "stop": {"noun": "storage/drive", "verb": "remove"},
        "ok": false,
        "firstMissingSignal": signal,
        "observed": {"payloadFields": ["device"]},
        "could_change_to": {"device": "/dev/<name>"},
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
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_alphanumeric() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-'))
}

async fn route(Json(payload): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let device = payload.get("device").and_then(Value::as_str)
        .filter(|device| valid_device(device))
        .ok_or_else(|| native_refusal(StatusCode::BAD_REQUEST, "caduceus-drive-device-invalid", false))?
        .to_owned();
    if !matches!(crate::shared::policy::allows_command(COMMAND), Ok(true)) {
        return Err(native_refusal(StatusCode::FORBIDDEN, "caduceus-carapace-desync", false));
    }
    let mut receipt = crate::gate::blocking_task(COMMAND, move || -> Result<Value, String> {
        let walked = crate::gate::snake::crossing_path_with_timeout(
            NAMESPACE, &json!({"device": device}), Duration::from_secs(600),
        )?;
        let mut receipt = walked.get("receiptPayload").cloned().filter(Value::is_object)
            .ok_or_else(|| "caduceus-staff-invalid-receipt".to_string())?;
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
        Ok(receipt)
    }).await.map_err(|(status, Json(body))| native_refusal(status, &body.first_missing_signal, true))?
        .map_err(|signal| native_refusal(StatusCode::SERVICE_UNAVAILABLE, &signal, true))?;

    if !crate::routes::leaf_schema::bound(&receipt, NAMESPACE) {
        if let Some(object) = receipt.as_object_mut() {
            object.insert("doorSignal".to_string(), json!("caduceus-schema-desync"));
            object.insert("crossedStop".to_string(), json!(NAMESPACE));
        }
        return Ok((StatusCode::SERVICE_UNAVAILABLE, Json(receipt)));
    }
    if receipt.get("converged").and_then(Value::as_bool) == Some(false) {
        return Ok((StatusCode::SERVICE_UNAVAILABLE, Json(receipt)));
    }
    if crate::gate::receipt_succeeded(&receipt) {
        crate::stats::disk_census::request_refresh();
    }
    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/storage/drive/remove", axum::routing::post(route))
}
