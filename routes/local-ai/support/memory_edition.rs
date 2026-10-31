//! The owner chooses an edition; the staff owns the eligibility observation.
use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::{json, Value};
use std::{sync::Mutex, time::{Duration, Instant}};

use crate::shared::config;

type Failure = (StatusCode, Value);
static EDITION: Mutex<()> = Mutex::new(());

fn unavailable(signal: &str) -> Failure {
    (StatusCode::SERVICE_UNAVAILABLE, json!({"ok": false, "signal": signal}))
}

// Keep the staff document intact: a successful memory document has no `ok`.
fn crossing(verb: &str, args: Value) -> Result<(bool, Value), Failure> {
    let reply = crate::gate::snake::crossing_path_with_timeout(
        &format!("local-ai/{verb}"), &json!({"args": args}), Duration::from_secs(30),
    ).map_err(|signal| unavailable(&signal))?;
    let payload = reply.get("receiptPayload").cloned()
        .ok_or_else(|| unavailable("local-ai-staff-reply-missing"))?;
    Ok((reply.get("ok").and_then(Value::as_bool) == Some(true), payload))
}

fn memory() -> Result<Value, Failure> {
    let (transport_ok, payload) = crossing("memory", json!([]))?;
    if !transport_ok || !payload.is_object()
        || payload.get("ok").and_then(Value::as_bool) == Some(false)
        || payload.get("converged").and_then(Value::as_bool) == Some(false)
    {
        return Err((StatusCode::SERVICE_UNAVAILABLE, payload));
    }
    Ok(payload)
}

fn choose(body: &Value) -> Result<Value, Failure> {
    let wanted = match body.get("edition") {
        Some(Value::Null) => Value::Null,
        Some(Value::String(value)) if value == "memory" => json!("memory"),
        _ => return Err((StatusCode::UNPROCESSABLE_ENTITY,
            json!({"ok": false, "signal": "invalid-edition"}))),
    };
    let _guard = EDITION.try_lock().map_err(|_| (StatusCode::CONFLICT,
        json!({"ok": false, "signal": "edition-change-in-progress"})))?;
    let argument = if wanted.is_null() { "none" } else { "memory" };
    let (transport_ok, check) = crossing("edition", json!(["check", argument]))?;
    if check.get("ok").and_then(Value::as_bool) == Some(false) {
        let signal = check.get("signal").and_then(Value::as_str);
        if matches!(signal, Some("drive_required" | "card-too-small")) {
            return Err((StatusCode::CONFLICT, check));
        }
        return Err((StatusCode::SERVICE_UNAVAILABLE, check));
    }
    if !transport_ok || check.get("ok").and_then(Value::as_bool) != Some(true)
        || check.get("converged").and_then(Value::as_bool) == Some(false)
    {
        return Err((StatusCode::SERVICE_UNAVAILABLE, check));
    }
    // Update only the named leaf under the sole writer's lock, preserving the
    // entire existing declaration and every unknown sibling field.
    let (_, changed) = config::update_block_json("local_ai", |current| {
        let mut local_ai = current.cloned().ok_or_else(|| "local-ai-declaration-missing".to_string())?;
        let fields = local_ai.as_object_mut().ok_or_else(|| "local-ai-declaration-invalid".to_string())?;
        fields.insert("edition".into(), wanted);
        Ok(Some(local_ai))
    }).map_err(|signal| unavailable(&signal))?;
    match memory() {
        Ok(value) => Ok(value),
        Err((status, readback)) => Err((status, json!({
            "ok": false, "signal": "edition-readback-failed",
            "edition_written": changed, "readback": readback
        }))),
    }
}

pub async fn memory_http() -> Response {
    if !crate::gate::roster_allows("GET", "local-ai/memory").unwrap_or(false) {
        return crate::gate::api_error("local-ai/memory").into_response();
    }
    match crate::gate::blocking_task("local-ai/memory", memory).await {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err((status, value))) => (status, Json(value)).into_response(),
        Err(error) => error.into_response(),
    }
}

pub async fn edition_http(body: Value) -> Response {
    if !crate::gate::roster_allows("PUT", "local-ai/edition").unwrap_or(false) {
        return crate::gate::api_error("local-ai/edition").into_response();
    }
    match crate::gate::blocking_task("local-ai/edition", move || {
        let started = Instant::now();
        let choice = match body.get("edition") {
            Some(Value::String(value)) if value == "memory" => "memory",
            Some(Value::Null) => "none",
            _ => "invalid",
        };
        let result = choose(&body);
        let signal = match result.as_ref().err().and_then(|(_, value)| value.get("signal"))
            .and_then(Value::as_str) {
            Some("drive_required") => "drive_required",
            Some("card-too-small") => "card-too-small",
            Some("invalid-edition") => "invalid-edition",
            Some("edition-change-in-progress") => "edition-change-in-progress",
            Some("edition-readback-failed") => "edition-readback-failed",
            Some(_) => "staff-or-config-failure",
            None if result.is_err() => "staff-or-config-failure",
            None => "none",
        };
        eprintln!("who=owner verb=edition target={} outcome={} duration_ms={} signal={}",
            choice, if result.is_ok() { "success" } else if signal == "edition-readback-failed" { "readback-failed" } else { "refused" },
            started.elapsed().as_millis(), signal);
        result
    }).await {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err((status, value))) => (status, Json(value)).into_response(),
        Err(error) => error.into_response(),
    }
}
