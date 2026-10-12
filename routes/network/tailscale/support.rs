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
    (StatusCode, Json<crate::gate::ApiErrorBody>),
>;

fn command(action: &str) -> String {
    format!("network tailscale {action}")
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

fn bad_request(
    command: &str,
    signal: &'static str,
) -> (StatusCode, Json<crate::gate::ApiErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(crate::gate::ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.to_string(),
            first_missing_signal: signal.to_string(),
        }),
    )
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

fn scrub_marked(value: Value) -> Option<Value> {
    match value {
        Value::String(text) => {
            if text.to_ascii_lowercase().contains("tskey-") {
                None
            } else {
                Some(Value::String(text))
            }
        }
        Value::Array(values) => Some(Value::Array(
            values
                .into_iter()
                .filter_map(scrub_marked)
                .collect(),
        )),
        Value::Object(values) => {
            let mut scrubbed = Map::new();
            for (key, value) in values {
                if key.to_ascii_lowercase().contains("tskey-") {
                    continue;
                }
                if let Some(value) = scrub_marked(value) {
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
    if receipt.get("schema").and_then(Value::as_str) != Some(crate::protocol::SCHEMA_ID)
        || (receipt_action != Some(action) && !unknown_action_refusal)
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
    let projected = scrub_marked(projected)?;
    crate::routes::leaf_schema::accepts(SCHEMA, &projected).then_some(projected)
}

fn unknown_receipt(action: &str, signal: &'static str) -> Value {
    json!({
        "schema": SCHEMA,
        "ok": false,
        "action": action,
        "firstMissingSignal": signal,
        "mutationPerformed": null,
        "final": null,
    })
}

async fn execute(action: &'static str, body: Result<Bytes, BytesRejection>) -> HttpResult {
    let command = command(action);
    if crate::routes::profile_routes::ACTIVE_PROFILE != "homeserver" {
        return Err(crate::gate::api_error(&command));
    }
    match crate::shared::policy::allows_command(&command) {
        Ok(true) => {}
        Ok(false) => return Err(crate::gate::api_error(&command)),
        Err(_) => {
            return Err(crate::gate::api_error_signal(
                &command,
                "caduceus-profile-missing",
            ));
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
            // The gate strips flags.exousia.pin and forwards what remains (often `{}`);
            // these acts take no input, so the body is ignored and never forwarded.
            let _ = &body;
            json!({"action": action})
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
            json!({"action": "authkey", "key": key})
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
            json!({"action": "tailnet", "name": name})
        }
        _ => {
            return Err(crate::gate::api_error_signal(
                &command,
                "caduceus-network-tailscale-action-invalid",
            ));
        }
    };

    let timeout = timeout(action);
    let crossed = match crate::gate::blocking_task(&command, move || {
        crate::gate::snake::crossing_path_with_timeout("network/tailscale", &payload, timeout)
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
