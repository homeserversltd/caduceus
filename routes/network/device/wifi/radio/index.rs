use axum::{extract::Json, http::StatusCode, response::{IntoResponse, Response}, Router};
use serde_json::{json, Value};
use std::{io::Read, process::{Command, Stdio}, time::{Duration, Instant}};
#[path = "../support.rs"]
mod support;
const DECLARATION: &str = include_str!("index.json");
async fn route(
    Json(body): Json<Value>,
) -> Result<(axum::http::StatusCode, Json<Value>), (axum::http::StatusCode, Json<Value>)> {
    support::execute("network device wifi radio", "radio", body, DECLARATION).await
}
fn read_radio() -> Result<Value, &'static str> {
    const LIMIT: usize = 64 * 1024;
    let mut child = Command::new(crate::gate::snake::cli_path())
        .args(["network", "wifi/radio/get"])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| "wifi-radio-staff-unavailable")?;
    let stdout = child.stdout.take().ok_or("wifi-radio-staff-output-unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take((LIMIT + 1) as u64).read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = match crate::shared::child_wait::until(&mut child, Instant::now() + Duration::from_secs(60)) {
        Ok(Some(status)) => Some(status),
        _ => { let _ = child.kill(); let _ = child.wait(); None }
    };
    let bytes = reader.join().map_err(|_| "wifi-radio-staff-output-invalid")?
        .map_err(|_| "wifi-radio-staff-output-invalid")?;
    let status = status.ok_or("wifi-radio-staff-timeout")?;
    if !status.success() { return Err("wifi-radio-staff-refused"); }
    if bytes.len() > LIMIT { return Err("wifi-radio-staff-output-too-large"); }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "wifi-radio-staff-receipt-invalid")?;
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("wifi-radio-staff-refused");
    }
    let present = value.get("present").and_then(Value::as_bool)
        .ok_or("wifi-radio-staff-receipt-invalid")?;
    let enabled = value.get("enabled").and_then(Value::as_bool)
        .ok_or("wifi-radio-staff-receipt-invalid")?;
    Ok(json!({"present": present, "enabled": enabled}))
}

async fn posture() -> Response {
    if !crate::gate::roster_allows("GET", "network/device/wifi/radio").unwrap_or(false) {
        return crate::gate::api_error("network/device/wifi/radio").into_response();
    }
    match tokio::task::spawn_blocking(read_radio).await {
        Ok(Ok(value)) => (StatusCode::OK, Json(value)).into_response(),
        Ok(Err(signal)) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "firstMissingSignal": signal}))).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "firstMissingSignal": "wifi-radio-staff-task-failed"}))).into_response(),
    }
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/network/device/wifi/radio",
        axum::routing::post(route).get(posture),
    )
}
