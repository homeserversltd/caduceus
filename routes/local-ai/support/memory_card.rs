//! One bounded slot transaction; the staff owns inventory, block maths and runtime.
use crate::shared::config;
use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

type Failure = (StatusCode, Value);
static SWAP: Mutex<()> = Mutex::new(());

fn failure(status: StatusCode, words: &str) -> Failure {
    (status, json!({"ok":false,"error":words}))
}
fn unavailable(words: &str) -> Failure {
    failure(StatusCode::SERVICE_UNAVAILABLE, words)
}
fn valid_file(value: &Value) -> bool {
    value.as_str().is_some_and(|file| {
        !file.is_empty()
            && file.len() <= 255
            && file.ends_with(".gguf")
            && !file.contains(['/', '\\'])
            && !file.chars().any(char::is_control)
            && file != "."
            && file != ".."
    })
}
fn role(slot: &str) -> Option<&'static str> {
    match slot {
        "brain" => Some("text-to-text"),
        "embed" => Some("embedding"),
        "ear" => Some("speech-to-text"),
        _ => None,
    }
}

// Shared executor bounds output and deadline. Parsed staff refusal bytes ride home;
// reads and crossings keep no inventory cache, file receipt or body log.
fn staff(verb: &str, args: Value) -> Result<Value, Failure> {
    let crossing = crate::gate::snake::crossing_path_with_timeout(
        &format!("local-ai/{verb}"),
        &json!({"args":args}),
        Duration::from_secs(30),
    )
    .map_err(|signal| unavailable(&signal))?;
    let payload = crossing
        .get("receiptPayload")
        .cloned()
        .ok_or_else(|| unavailable("local-ai-staff-reply-missing"))?;
    if crossing.get("ok").and_then(Value::as_bool) != Some(true)
        || payload.get("ok").and_then(Value::as_bool) != Some(true)
        || payload.get("converged").and_then(Value::as_bool) == Some(false)
    {
        return Err((StatusCode::SERVICE_UNAVAILABLE, payload));
    }
    Ok(payload)
}

pub async fn read_http(verb: &'static str) -> Response {
    let namespace = format!("local-ai/{verb}");
    if !crate::gate::roster_allows("GET", &namespace).unwrap_or(false) {
        return crate::gate::api_error(&namespace).into_response();
    }
    match crate::gate::blocking_task(&namespace, move || staff(verb, json!([]))).await {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err((status, value))) => (status, Json(value)).into_response(),
        Err(error) => error.into_response(),
    }
}

fn restore(
    tokens: Vec<config::JsonSetRollback>,
    original: Failure,
    reapply: Option<&str>,
) -> Failure {
    let mut failures = Vec::new();
    for token in tokens.into_iter().rev() {
        if let Err(signal) = config::restore_json_set(token) {
            failures.push(signal);
        }
    }
    if !failures.is_empty() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({
                "ok":false, "error":"local-ai-slot-restore-failed",
                "refusal":original.1, "restore_errors":failures
            }),
        );
    }
    if let Some(slot) = reapply {
        if let Err(refusal) = staff("slot", json!(["apply", slot])) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "ok":false, "error":"local-ai-slot-runtime-restore-failed",
                    "config_restored":true, "runtime_restored":false,
                    "refusal":original.1, "restore_refusal":refusal.1
                }),
            );
        }
    }
    original
}

fn swap(slot: &str, body: &Value) -> Result<Value, Failure> {
    // Refuse concurrent producers rather than keeping a queue of swaps. This lock
    // spans inventory/fit, both ear leaves, apply, rollback and final card read.
    let _guard = SWAP
        .try_lock()
        .map_err(|_| failure(StatusCode::CONFLICT, "A slot change is already in progress"))?;
    let wanted_role = role(slot).ok_or_else(|| failure(StatusCode::NOT_FOUND, "Unknown slot"))?;
    let model = body
        .get("model")
        .filter(|value| value.is_null() || valid_file(value))
        .ok_or_else(|| {
            failure(
                StatusCode::UNPROCESSABLE_ENTITY,
                "Choose a shelf file or null",
            )
        })?;
    let local_ai =
        config::get_json("local_ai").map_err(|signal| unavailable(&signal))?["value"].clone();
    if !crate::routes::leaf_schema::accepts("appliance.local_ai.v1", &local_ai) {
        return Err(unavailable("local-ai-declaration-schema-desync"));
    }
    let current = &local_ai["slots"][slot];
    if current["role"].as_str() != Some(wanted_role) {
        return Err(unavailable("local-ai-slot-role-desync"));
    }
    let mut mmproj = Value::Null;
    if !model.is_null() {
        let library = staff("library", json!([]))?;
        let saves = library
            .get("saves")
            .and_then(Value::as_array)
            .ok_or_else(|| unavailable("local-ai-library-saves-missing"))?;
        let save = saves
            .iter()
            .find(|save| save.get("file") == Some(model))
            .ok_or_else(|| {
                failure(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Model is not on the shelf",
                )
            })?;
        if save["role"].as_str() != Some(wanted_role) {
            return Err(failure(
                StatusCode::UNPROCESSABLE_ENTITY,
                "This save belongs in a different role slot",
            ));
        }
        let blocks = save["blocks"]
            .as_u64()
            .filter(|blocks| *blocks > 0)
            .ok_or_else(|| unavailable("local-ai-library-blocks-missing"))?;
        if slot == "ear" {
            mmproj = save.get("mmproj").cloned().unwrap_or(Value::Null);
            if !valid_file(&mmproj) {
                return Err(failure(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "Speech save has no paired projector on the shelf",
                ));
            }
        }
        let card = staff("card", json!([]))?;
        let total = card["total_blocks"]
            .as_u64()
            .ok_or_else(|| unavailable("local-ai-card-total-missing"))?;
        let free = card["free_blocks"]
            .as_u64()
            .filter(|free| *free <= total)
            .ok_or_else(|| unavailable("local-ai-card-free-missing"))?;
        let held = &card["slots"][slot];
        let old_blocks = held["blocks"]
            .as_u64()
            .filter(|blocks| *blocks <= total)
            .ok_or_else(|| unavailable("local-ai-card-slot-blocks-missing"))?;
        if held["model"] != current["model"] || held["role"].as_str() != Some(wanted_role) {
            return Err(unavailable("local-ai-card-config-desync"));
        }
        if blocks > free.saturating_add(old_blocks).min(total) {
            return Err(failure(StatusCode::CONFLICT, "Not enough free blocks"));
        }
    }

    // Only these leaves change. Unknown fields, role, ctx, port and LAN survive.
    // The lever's compare-before-restore token also preserves outside changes.
    let mut tokens = Vec::new();
    let mut updates = vec![(format!("local_ai.slots.{slot}.model"), model.clone())];
    if slot == "ear" {
        updates.push(("local_ai.slots.ear.mmproj".into(), mmproj));
    }
    for (path, value) in updates {
        let mut rollback = None;
        let written = config::set_json_with_rollback(&path, value, &mut rollback);
        if let Some(token) = rollback {
            tokens.push(token);
        }
        if let Err(signal) = written {
            return Err(restore(tokens, unavailable(&signal), None));
        }
    }
    if let Err(refusal) = staff("slot", json!(["apply", slot])) {
        return Err(restore(tokens, refusal, None));
    }
    match staff("card", json!([])) {
        Ok(card) => Ok(card),
        Err(refusal) => {
            // A swap is not accepted without its new card. Restore the narrow
            // config leaves and re-apply the old slot before returning refusal.
            Err(restore(tokens, refusal, Some(slot)))
        }
    }
}

pub async fn slot_http(slot: &'static str, body: Value) -> Response {
    let namespace = format!("local-ai/slot/{slot}");
    if !crate::gate::roster_allows("PUT", &namespace).unwrap_or(false) {
        return crate::gate::api_error(&namespace).into_response();
    }
    match crate::gate::blocking_task(&namespace, move || {
        let started = Instant::now();
        let result = swap(slot, &body);
        // One bounded Canonical Log Line: filename is an identifier, never model
        // content or the request/response body. Invalid input is not echoed.
        let model = body.get("model").filter(|value| valid_file(value));
        eprintln!(
            "who=caduceus verb=slot target={} model={} outcome={} duration_ms={} signal={}",
            slot,
            model.unwrap_or(&Value::Null),
            if result.is_ok() { "success" } else { "refused" },
            started.elapsed().as_millis(),
            result
                .as_ref()
                .err()
                .map(|error| error.0.as_u16())
                .unwrap_or(0)
        );
        result
    })
    .await
    {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err((status, value))) => (status, Json(value)).into_response(),
        Err(error) => error.into_response(),
    }
}
