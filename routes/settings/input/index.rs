use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};

const READ_COMMAND: &str = "settings input read";
const SET_COMMAND: &str = "settings input set";
const SCHEMA: &str = "caduceus.staff.v1";
const INPUT_FIELDS: &[&str] = &[
    "pointer_sensitivity", "scroll_factor", "natural_scroll", "tap_to_click",
    "middle_button_emulation", "keyboard_layout", "keyboard_variant", "key_repeat",
    "repeat_delay_ms", "repeat_interval_ms", "pointer_speed", "accel_profile",
    "left_handed", "disable_while_typing",
];

fn admitted(command: &str) -> Result<(), (StatusCode, Json<Value>)> {
    match crate::shared::policy::allows_command(command) {
        Ok(true) => Ok(()),
        Ok(false) => Err((StatusCode::FORBIDDEN, Json(json!({"schema":"caduceus.api.error.v1","ok":false,"command":command,"first_missing_signal":"caduceus-public-action-not-allowed"})))),
        Err(_) => Err((StatusCode::FORBIDDEN, Json(json!({"schema":"caduceus.api.error.v1","ok":false,"command":command,"first_missing_signal":"caduceus-carapace-desync"})))),
    }
}

fn actuator_receipt(transition: &str, payload: Option<Value>) -> Result<Value, String> {
    let input = payload.unwrap_or_else(|| json!({}));
    let walked = crate::gate::snake::crossing_path_with_timeout(
        &format!("settings/input/{transition}"),
        &input,
        std::time::Duration::from_secs(180),
    )?;
    if walked.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(walked.get("receiptPayload").cloned().unwrap_or(walked))
    } else {
        Err(walked.get("receiptPayload")
            .and_then(|receipt| receipt.get("error").or_else(|| receipt.get("firstMissingSignal")))
            .and_then(Value::as_str)
            .or_else(|| walked.get("firstMissingSignal").and_then(Value::as_str))
            .unwrap_or("caduceus-agathodaimon-refused").to_string())
    }
}

fn input_payload(body: &Value) -> Value {
    let source = if INPUT_FIELDS.iter().any(|field| body.get(*field).is_some()) {
        body
    } else {
        body.get("payload").filter(|value| value.is_object()).unwrap_or(body)
    };
    let mut payload = serde_json::Map::new();
    for field in INPUT_FIELDS {
        if let Some(value) = source.get(*field) {
            payload.insert((*field).to_string(), value.clone());
        }
    }
    Value::Object(payload)
}

async fn read_http() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    admitted(READ_COMMAND)?;
    let result = crate::gate::blocking_task(READ_COMMAND, || actuator_receipt("read", None))
        .await
        .map_err(|(status, Json(body))| (status, Json(serde_json::json!(body))))?;
    result.map(|receipt| (crate::gate::mutation_status(&receipt), Json(receipt))).map_err(|signal| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"schema":SCHEMA,"ok":false,"command":READ_COMMAND,"firstMissingSignal":signal}))))
}

async fn set_http(Json(body): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    admitted(SET_COMMAND)?;
    let result = crate::gate::blocking_task(SET_COMMAND, move || actuator_receipt("set", Some(input_payload(&body))))
        .await
        .map_err(|(status, Json(body))| (status, Json(serde_json::json!(body))))?;
    result.map(|receipt| (crate::gate::mutation_status(&receipt), Json(receipt))).map_err(|signal| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"schema":SCHEMA,"ok":false,"command":SET_COMMAND,"firstMissingSignal":signal}))))
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/settings/input",
        axum::routing::get(read_http)
            .post(set_http)
            .put(set_http)
            .patch(set_http),
    )
}
