use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::{json, Value};
use std::{io::Read, process::{Command, Stdio}, time::{Duration, Instant}};

const LIMIT: usize = 64 * 1024;

fn invoke() -> Result<Value, &'static str> {
    let cli = crate::gate::snake::cli_path();
    let mut command = if std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some() {
        Command::new(&cli)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("-n").arg(&cli);
        command
    };
    let mut child = command.args(["woodpecker", "agent"])
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| "woodpecker-agent-staff-unavailable")?;
    let stdout = child.stdout.take().ok_or("woodpecker-agent-staff-output-unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take((LIMIT + 1) as u64).read_to_end(&mut bytes).map(|_| bytes)
    });
    let status = match crate::shared::child_wait::until(&mut child, Instant::now() + Duration::from_secs(60)) {
        Ok(Some(status)) => Some(status),
        _ => { let _ = child.kill(); let _ = child.wait(); None }
    };
    let bytes = reader.join().map_err(|_| "woodpecker-agent-staff-output-invalid")?
        .map_err(|_| "woodpecker-agent-staff-output-invalid")?;
    let status = status.ok_or("woodpecker-agent-staff-timeout")?;
    if !status.success() { return Err("woodpecker-agent-staff-refused"); }
    if bytes.len() > LIMIT { return Err("woodpecker-agent-staff-output-too-large"); }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "woodpecker-agent-staff-receipt-invalid")?;
    let token_present = value.get("token_present").and_then(Value::as_bool)
        .ok_or("woodpecker-agent-staff-receipt-invalid")?;
    let unit_active = value.get("unit_active").and_then(Value::as_bool)
        .ok_or("woodpecker-agent-staff-receipt-invalid")?;
    Ok(json!({"token_present": token_present, "unit_active": unit_active}))
}

async fn posture() -> Response {
    match tokio::task::spawn_blocking(invoke).await {
        Ok(Ok(value)) => (StatusCode::OK, Json(value)).into_response(),
        Ok(Err(signal)) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "firstMissingSignal": signal}))).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok": false, "firstMissingSignal": "woodpecker-agent-staff-task-failed"}))).into_response(),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/woodpecker/agent", axum::routing::get(posture))
}
