use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const LIMIT: usize = 64 * 1024;

// Secret-bearing allocations used for the crossing are wiped on every exit.
struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

fn refusal(signal: &'static str) -> Value {
    json!({"ok": false, "firstMissingSignal": signal})
}

fn request(mut body: Value) -> Result<(Secret, Secret), &'static str> {
    let password = body.as_object_mut().and_then(|body| body.remove("password"));
    let Some(Value::String(password)) = password else {
        return Err("hermes-dashboard-login-request-invalid");
    };
    let secret = Secret(password.into_bytes());
    if secret.0.is_empty() || secret.0.len() > LIMIT || secret.0.contains(&0) {
        return Err("hermes-dashboard-login-request-invalid");
    }
    let mut input = Secret(Vec::new());
    // The staff verb accepts one JSON object on stdin, not an argv value.
    let password = std::str::from_utf8(&secret.0)
        .map_err(|_| "hermes-dashboard-login-request-invalid")?;
    #[derive(serde::Serialize)]
    struct StaffRequest<'a> { password: &'a str }
    serde_json::to_writer(&mut input.0, &StaffRequest { password })
        .map_err(|_| "hermes-dashboard-login-request-invalid")?;
    Ok((secret, input))
}

fn project(value: Value, exited_ok: bool, secret: &Secret) -> Result<Value, &'static str> {
    let object = value.as_object().ok_or("hermes-dashboard-login-staff-receipt-invalid")?;
    let mut result = serde_json::Map::new();
    if let Some(ok) = object.get("ok").and_then(Value::as_bool) {
        result.insert("ok".into(), json!(ok && exited_ok));
    } else {
        return Err("hermes-dashboard-login-staff-receipt-invalid");
    }
    if let Some(restarted) = object.get("restarted") {
        if !restarted.is_boolean() {
            return Err("hermes-dashboard-login-staff-receipt-invalid");
        }
        result.insert("restarted".into(), restarted.clone());
    }
    if let Some(signal) = object.get("firstMissingSignal") {
        if !signal.is_null() {
            let signal = signal.as_str().ok_or("hermes-dashboard-login-staff-receipt-invalid")?;
            if signal.len() > 160
                || !(signal == "none" || signal.starts_with("hermes-"))
                || !signal.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
                || signal.as_bytes().windows(secret.0.len()).any(|bytes| bytes == secret.0)
            {
                return Err("hermes-dashboard-login-staff-receipt-invalid");
            }
        }
        result.insert("firstMissingSignal".into(), signal.clone());
    }
    if !exited_ok {
        result.insert("ok".into(), json!(false));
        if !result.get("firstMissingSignal").is_some_and(|v| v.as_str().is_some_and(|s| s != "none")) {
            result.insert("firstMissingSignal".into(), json!("hermes-dashboard-login-staff-refused"));
        }
    }
    Ok(Value::Object(result))
}

fn invoke(secret: Secret, input: Secret) -> Result<Value, &'static str> {
    let cli = crate::gate::snake::cli_path();
    let mut command = if std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some() {
        Command::new(&cli)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("-n").arg(&cli);
        command
    };
    let mut child = command.args(["hermes", "dashboard-login"])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .spawn().map_err(|_| "hermes-dashboard-login-staff-unavailable")?;
    let stdout = child.stdout.take().ok_or("hermes-dashboard-login-staff-output-unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Secret(Vec::new());
        stdout.take((LIMIT + 1) as u64).read_to_end(&mut bytes.0).map(|_| bytes)
    });
    let stdin = child.stdin.take();
    let writer = std::thread::spawn(move || {
        stdin.ok_or(()).and_then(|mut stdin| stdin.write_all(&input.0).map_err(|_| ()))
    });
    let status = match crate::shared::child_wait::until(&mut child, Instant::now() + Duration::from_secs(60)) {
        Ok(Some(status)) => Some(status),
        _ => { let _ = child.kill(); let _ = child.wait(); None }
    };
    let written = writer.join().map_err(|_| "hermes-dashboard-login-staff-stdin-failed")?;
    let bytes = reader.join().map_err(|_| "hermes-dashboard-login-staff-output-invalid")?
        .map_err(|_| "hermes-dashboard-login-staff-output-invalid")?;
    let status = status.ok_or("hermes-dashboard-login-staff-timeout")?;
    if bytes.0.len() > LIMIT { return Err("hermes-dashboard-login-staff-output-too-large"); }
    let value = serde_json::from_slice(&bytes.0).map_err(|_| "hermes-dashboard-login-staff-receipt-invalid")?;
    let value = project(value, status.success(), &secret)?;
    if written.is_err() && status.success() { return Err("hermes-dashboard-login-staff-stdin-failed"); }
    Ok(value)
}

async fn set(body: Result<Json<Value>, JsonRejection>) -> Response {
    let result = match body {
        Ok(Json(body)) => match request(body) {
            Ok((secret, input)) => match tokio::task::spawn_blocking(move || invoke(secret, input)).await {
                Ok(Ok(value)) => value,
                Ok(Err(signal)) => refusal(signal),
                Err(_) => refusal("hermes-dashboard-login-staff-task-failed"),
            },
            Err(signal) => refusal(signal),
        },
        Err(_) => refusal("hermes-dashboard-login-request-invalid"),
    };
    let status = if result["ok"] == true { StatusCode::OK }
        else if result["firstMissingSignal"] == "hermes-dashboard-login-request-invalid" { StatusCode::BAD_REQUEST }
        else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(result)).into_response()
}

async fn posture() -> Json<Value> {
    // The sibling staff verb has no contracted posture reader yet.
    Json(json!({"ok": true, "door": "present"}))
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/hermes/dashboard-login", axum::routing::get(posture).post(set))
}
