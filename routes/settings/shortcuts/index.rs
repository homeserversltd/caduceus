use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};

const READ_COMMAND: &str = "settings shortcuts read";
const MUTATE_COMMAND: &str = "settings shortcuts mutate";
const SCHEMA: &str = "caduceus.staff.v1";

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
        &format!("settings/shortcuts/{transition}"),
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

fn shortcut_payload(body: &Value) -> Value {
    let source = if body.get("from").is_some() {
        body
    } else {
        body.get("payload").unwrap_or(body)
    };
    let mut payload = serde_json::Map::new();
    for field in ["from", "to"] {
        if let Some(value) = source.get(field) {
            payload.insert(field.to_string(), value.clone());
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

async fn mutate_http(Json(body): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    admitted(MUTATE_COMMAND)?;
    let result = crate::gate::blocking_task(MUTATE_COMMAND, move || actuator_receipt("set", Some(shortcut_payload(&body))))
        .await
        .map_err(|(status, Json(body))| (status, Json(serde_json::json!(body))))?;
    result.map(|receipt| (crate::gate::mutation_status(&receipt), Json(receipt))).map_err(|signal| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"schema":SCHEMA,"ok":false,"command":MUTATE_COMMAND,"firstMissingSignal":signal}))))
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/settings/shortcuts",
        axum::routing::get(read_http)
            .post(mutate_http)
            .put(mutate_http)
            .patch(mutate_http),
    )
}
