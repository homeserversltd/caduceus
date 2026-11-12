use axum::{
    body::Bytes,
    extract::rejection::BytesRejection,
    extract::Json,
    http::StatusCode,
};
use serde_json::{json, Map, Value};
use std::time::Duration;

const SCHEMA: &str = "caduceus.network.tailscale.v1";
const TIMEOUT_UP: Duration = Duration::from_secs(35);
const TIMEOUT_DOWN: Duration = Duration::from_secs(35);
const TIMEOUT_AUTHKEY: Duration = Duration::from_secs(30);
const TIMEOUT_TAILNET: Duration = Duration::from_secs(360);
const MAX_AUTHKEY_BYTES: usize = 1024;

type HttpResult = Result<
    (StatusCode, Json<Value>),
    (StatusCode, Json<Value>),
>;

fn command(action: &str) -> String {
    format!("network tailscale {action}")
}

fn stop(action: &str) -> &'static str {
    match action {
        "up" => "network/tailscale/up",
        "down" => "network/tailscale/down",
        "authkey" => "network/tailscale/authkey",
        "tailnet" => "network/tailscale/tailnet",
        _ => unreachable!("validated tailscale action"),
    }
}

fn stop_seat(action: &str) -> String {
    format!("caduceus.network.tailscale.{action}.v1")
}

fn timeout(action: &str) -> Duration {
    match action {
        "up" => TIMEOUT_UP,
        "down" => TIMEOUT_DOWN,
        "authkey" => TIMEOUT_AUTHKEY,
        "tailnet" => TIMEOUT_TAILNET,
        _ => TIMEOUT_UP,
    }
}

fn native_refusal(action: &str, signal: &str) -> Value {
    json!({
        "schema": "caduceus.staff.receipt.v1",
        "ok": false,
        "stop": {"noun": "network/tailscale", "verb": action},
        "observed": {"command": command(action)},
        "could_change_to": null,
        "attempt": null,
        "final_receipt": {"ok": false, "firstMissingSignal": signal},
        "command": command(action),
        "firstMissingSignal": signal,
    })
}

fn bad_request(command: &str, signal: &'static str) -> (StatusCode, Json<Value>) {
    let action = command.rsplit(' ').next().unwrap_or("");
    (StatusCode::BAD_REQUEST, Json(native_refusal(action, signal)))
}

fn forbidden(action: &str, signal: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::FORBIDDEN, Json(native_refusal(action, signal)))
}

fn safe_text(value: &Value, max_len: usize, secret: Option<&str>) -> Option<Value> {
    match value {
        Value::Null => Some(Value::Null),
        Value::String(text)
            if text.len() <= max_len
                && !text.to_ascii_lowercase().contains("tskey-")
                && !secret.is_some_and(|secret| !secret.is_empty() && text.contains(secret)) =>
        {
            Some(Value::String(text.clone()))
        }
        _ => None,
    }
}

fn safe_string_array(
    value: &Value,
    max_items: usize,
    max_len: usize,
    secret: Option<&str>,
) -> Option<Value> {
    match value {
        Value::Null => Some(Value::Null),
        Value::Array(values) => Some(Value::Array(
            values
                .iter()
                .take(max_items)
                .filter_map(|value| match safe_text(value, max_len, secret) {
                    Some(Value::String(text)) => Some(Value::String(text)),
                    _ => None,
                })
                .collect(),
        )),
        _ => None,
    }
}

fn scrub_marked(value: Value, secret: Option<&str>) -> Option<Value> {
    match value {
        Value::String(text) => {
            if text.to_ascii_lowercase().contains("tskey-")
                || secret.is_some_and(|secret| !secret.is_empty() && text.contains(secret)) {
                None
            } else {
                Some(Value::String(text))
            }
        }
        Value::Array(values) => Some(Value::Array(
            values
                .into_iter()
                .filter_map(|value| scrub_marked(value, secret))
                .collect(),
        )),
        Value::Object(values) => {
            let mut scrubbed = Map::new();
            for (key, value) in values {
                if key.to_ascii_lowercase().contains("tskey-")
                    || secret.is_some_and(|secret| !secret.is_empty() && key.contains(secret)) {
                    continue;
                }
                if let Some(value) = scrub_marked(value, secret) {
                    scrubbed.insert(key, value);
                }
            }
            Some(Value::Object(scrubbed))
        }
        other => Some(other),
    }
}

fn safe_signal(value: Option<&Value>) -> Option<String> {
    let Some(Value::String(signal)) = value else {
        return None;
    };
    if signal.is_empty()
        || signal.len() > 160
        || signal == "none"
        || !signal
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
        || signal.to_ascii_lowercase().contains("tskey-")
    {
        return None;
    }
    Some(signal.clone())
}

fn project_final(value: Option<&Value>, secret: Option<&str>) -> Value {
    let Some(value) = value else {
        return Value::Null;
    };
    if value.is_null() {
        return Value::Null;
    }
    let Some(fields) = value.as_object() else {
        return Value::Null;
    };
    let mut projected = Map::new();
    for field in [
        "status",
        "interface",
        "ip",
        "tailnet",
        "backendState",
        "declaredTailnet",
        "priorTailnet",
        "newTailnet",
    ] {
        if let Some(value) = fields.get(field).and_then(|value| safe_text(value, 4096, secret)) {
            projected.insert(field.to_string(), value);
        }
    }
    for field in [
        "connected",
        "backupComplete",
        "certificateRefreshed",
        "nginxReloaded",
        "tlsHostnameVerified",
        "rollbackComplete",
        "hostnameVerified",
    ] {
        if let Some(value) = fields.get(field) {
            if value.is_null() || value.is_boolean() {
                projected.insert(field.to_string(), value.clone());
            }
        }
    }
    for (field, max_items, max_len) in [
        ("changedFiles", 512, 4096),
        ("subjectAltNames", 256, 253),
    ] {
        if let Some(value) = fields
            .get(field)
            .and_then(|value| safe_string_array(value, max_items, max_len, secret))
        {
            projected.insert(field.to_string(), value);
        }
    }
    Value::Object(projected)
}

fn optional_text(
    source: &Value,
    field: &str,
    target: &mut Map<String, Value>,
    max_len: usize,
    secret: Option<&str>,
) {
    if let Some(value) = source
        .get(field)
        .and_then(|value| safe_text(value, max_len, secret))
    {
        target.insert(field.to_string(), value);
    }
}

fn safe_receipt(crossing: &Value, action: &str, secret: Option<&str>) -> Option<Value> {
    let receipt = crossing.get("receiptPayload")?;
    let staff_ok = receipt.get("ok").and_then(Value::as_bool);
    let receipt_action = receipt.get("action").and_then(Value::as_str);
    let unknown_action_refusal = receipt_action == Some("unknown") && staff_ok == Some(false);
    let front_refusal = matches!(action, "up" | "down")
        && receipt.get("action").is_none()
        && staff_ok == Some(false)
        && crate::routes::leaf_schema::bound(receipt, stop(action));
    if (receipt.get("schema").and_then(Value::as_str) != Some(stop_seat(action).as_str())
        && !crate::routes::leaf_schema::bound(receipt, stop(action)))
        || (receipt_action != Some(action) && !unknown_action_refusal && !front_refusal)
    {
        return None;
    }
    let crossing_ok = crossing.get("ok").and_then(Value::as_bool) == Some(true);
    let ok = crossing_ok && staff_ok == Some(true);
    let signal = if ok {
        "none".to_string()
    } else if staff_ok == Some(false) {
        safe_signal(receipt.get("firstMissingSignal"))
            .unwrap_or_else(|| "caduceus-network-tailscale-staff-refused".to_string())
    } else {
        "caduceus-network-tailscale-crossing-refused".to_string()
    };
    let mutation = receipt
        .get("mutationPerformed")
        .filter(|value| value.is_boolean() || value.is_null())
        .cloned()
        .unwrap_or(Value::Null);
    let final_value = project_final(receipt.get("final"), secret);
    let mut projected = json!({
        "schema": SCHEMA,
        "ok": ok,
        "action": action,
        "firstMissingSignal": signal,
        "mutationPerformed": mutation,
        "final": final_value,
    });
    let Some(fields) = projected.as_object_mut() else {
        return None;
    };
    if action == "up" {
        let login_url = receipt
            .get("loginUrl")
            .or_else(|| receipt.get("final").and_then(|final_value| final_value.get("loginUrl")));
        if let Some(value) = login_url.and_then(|value| safe_text(value, 4096, secret)) {
            fields.insert("loginUrl".to_string(), value);
        }
    }
    if action == "tailnet" {
        for (field, limit) in [("priorTailnet", 256), ("newTailnet", 256), ("backupPath", 4096)] {
            optional_text(receipt, field, fields, limit, secret);
        }
        for (field, max_items, max_len) in [
            ("changedFiles", 512, 4096),
            ("subjectAltNames", 256, 253),
        ] {
            if let Some(value) = receipt
                .get(field)
                .and_then(|value| safe_string_array(value, max_items, max_len, secret))
            {
                fields.insert(field.to_string(), value);
            }
        }
    }
    let mut answer = receipt.clone();
    let fields = answer.as_object_mut()?;
    if crate::routes::leaf_schema::accepts(SCHEMA, &projected) {
        fields.entry("face").or_insert(projected);
    }
    if staff_ok == Some(true) && !crossing_ok {
        fields.entry("doorSignal").or_insert_with(|| json!("caduceus-network-tailscale-crossing-refused"));
    }
    scrub_marked(answer, secret)
}

fn unknown_receipt(action: &str, signal: &'static str) -> Value {
    let mut receipt = native_refusal(action, signal);
    let fields = receipt.as_object_mut().expect("native receipt is an object");
    fields.insert("action".to_string(), json!(action));
    fields.insert("mutationPerformed".to_string(), Value::Null);
    fields.insert("final".to_string(), Value::Null);
    receipt
}

async fn execute(action: &'static str, body: Result<Bytes, BytesRejection>) -> HttpResult {
    let command = command(action);
    if crate::routes::profile_routes::ACTIVE_PROFILE != "homeserver" {
        return Err(forbidden(action, "caduceus-public-action-not-allowed"));
    }
    match crate::shared::policy::allows_command(&command) {
        Ok(true) => {}
        Ok(false) => return Err(forbidden(action, "caduceus-public-action-not-allowed")),
        Err(_) => {
            return Err(forbidden(action, "caduceus-carapace-desync"));
        }
    }

    let body = body.map_err(|_| {
        bad_request(
            &command,
            "caduceus-network-tailscale-request-invalid",
        )
    })?;
    let mut secret = None;
    let payload = match action {
        "up" | "down" => {
            // Forward the caller's object after the gate strips flags.exousia.pin.
            if body.is_empty() {
                json!({})
            } else {
                let value = serde_json::from_slice::<Value>(body.as_ref()).map_err(|_| {
                    bad_request(&command, "caduceus-network-tailscale-request-invalid")
                })?;
                if !value.is_object() {
                    return Err(bad_request(&command, "caduceus-network-tailscale-request-invalid"));
                }
                value
            }
        }
        "authkey" => {
            let value = serde_json::from_slice::<Value>(body.as_ref()).map_err(|_| {
                bad_request(
                    &command,
                    "caduceus-network-tailscale-request-invalid",
                )
            })?;
            let Some(object) = value.as_object() else {
                return Err(bad_request(
                    &command,
                    "caduceus-network-tailscale-request-invalid",
                ));
            };
            let Some(key) = object.get("key").and_then(Value::as_str) else {
                return Err(bad_request(
                    &command,
                    "caduceus-network-tailscale-request-invalid",
                ));
            };
            if key.is_empty() || key.len() > MAX_AUTHKEY_BYTES {
                return Err(bad_request(
                    &command,
                    "caduceus-network-tailscale-request-invalid",
                ));
            }
            secret = Some(key.to_string());
            json!({"key": key})
        }
        "tailnet" => {
            let value = serde_json::from_slice::<Value>(body.as_ref()).map_err(|_| {
                bad_request(
                    &command,
                    "caduceus-network-tailscale-request-invalid",
                )
            })?;
            let Some(object) = value.as_object() else {
                return Err(bad_request(
                    &command,
                    "caduceus-network-tailscale-request-invalid",
                ));
            };
            let Some(name) = object.get("name").and_then(Value::as_str) else {
                return Err(bad_request(
                    &command,
                    "caduceus-network-tailscale-request-invalid",
                ));
            };
            json!({"name": name})
        }
        _ => {
            return Err(forbidden(action, "tailscale-operation-required"));
        }
    };

    let timeout = timeout(action);
    let crossed = if matches!(action, "up" | "down") {
        let envelope = crate::gate::snake::route_envelope(stop(action), &payload);
        crate::gate::snake::execute_ordered_serve_with_timeout(
            &[json!({"snake": stop(action)})], &envelope, Some(timeout),
        ).await
    } else {
        match crate::gate::blocking_task(&command, move || {
            crate::gate::snake::crossing_path_with_timeout(stop(action), &payload, timeout)
        })
        .await
        {
            Ok(result) => result,
            Err(_) => {
                return Ok((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(unknown_receipt(
                        action,
                        "caduceus-network-tailscale-crossing-outcome-unknown",
                    )),
                ));
            }
        }
    };
    let crossing = match crossed {
        Ok(crossing) => crossing,
        Err(signal) if signal == "caduceus-agathodaimon-timeout" => {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(unknown_receipt(action, "caduceus-network-tailscale-timeout")),
            ));
        }
        Err(_) => {
            return Ok((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(unknown_receipt(
                    action,
                    "caduceus-network-tailscale-crossing-outcome-unknown",
                )),
            ));
        }
    };

    let receipt_payload = crossing.get("receiptPayload");
    if receipt_payload
        .and_then(|receipt| receipt.get("mutationPerformed"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        let _ = crate::stats::poke(crate::stats::IndicatorBlock::Tailscale);
    }
    let Some(receipt) = safe_receipt(&crossing, action, secret.as_deref()) else {
        return Ok((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(unknown_receipt(
                action,
                "caduceus-network-tailscale-receipt-invalid",
            )),
        ));
    };

    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub(super) async fn up_route(body: Result<Bytes, BytesRejection>) -> HttpResult {
    execute("up", body).await
}

pub(super) async fn down_route(body: Result<Bytes, BytesRejection>) -> HttpResult {
    execute("down", body).await
}

pub(super) async fn authkey_route(body: Result<Bytes, BytesRejection>) -> HttpResult {
    execute("authkey", body).await
}

pub(super) async fn tailnet_route(body: Result<Bytes, BytesRejection>) -> HttpResult {
    execute("tailnet", body).await
}
