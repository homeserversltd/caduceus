use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};

const READ_COMMAND: &str = "settings shortcuts read";
const MUTATE_COMMAND: &str = "settings shortcuts mutate";

fn admitted(command: &str) -> Result<(), (StatusCode, Json<Value>)> {
    match crate::shared::policy::allows_command(command) {
        Ok(true) => Ok(()),
        Ok(false) => Err((StatusCode::FORBIDDEN, Json(json!({"schema":"caduceus.api.error.v1","ok":false,"command":command,"first_missing_signal":"caduceus-public-action-not-allowed"})))),
        Err(_) => Err((StatusCode::FORBIDDEN, Json(json!({"schema":"caduceus.api.error.v1","ok":false,"command":command,"first_missing_signal":"caduceus-carapace-desync"})))),
    }
}

fn actuator_receipt(transition: &str, payload: Option<Value>) -> (StatusCode, Value) {
    let input = payload.unwrap_or_else(|| json!({}));
    let walked = crate::gate::snake::crossing_path_with_timeout(
        &format!("settings/shortcuts/{transition}"),
        &input,
        std::time::Duration::from_secs(180),
    );
    let signal = match walked {
        Ok(walked) => {
            let crossing_ok = walked.get("ok").and_then(Value::as_bool) == Some(true);
            let receipt = walked.get("receiptPayload");
            let receipt_ok = receipt.and_then(|value| value.get("ok")).and_then(Value::as_bool);
            if let Some(receipt) = receipt.filter(|value| value.is_object()) {
                if crossing_ok || receipt_ok == Some(false) {
                    let status = if crossing_ok && receipt_ok == Some(true) {
                        StatusCode::OK
                    } else {
                        StatusCode::SERVICE_UNAVAILABLE
                    };
                    return (status, receipt.clone());
                }
            }
            receipt.and_then(|value| value.get("error").and_then(Value::as_str)
                .or_else(|| value.get("firstMissingSignal").and_then(Value::as_str)))
                .or_else(|| if !crossing_ok { walked.get("firstMissingSignal").and_then(Value::as_str) } else { None })
                .unwrap_or("caduceus-agathodaimon-refused").to_string()
        }
        Err(signal) => signal,
    };
    let could_change_to = if transition == "read" { Value::Null } else { input };
    (StatusCode::SERVICE_UNAVAILABLE, json!({
        "schema": "caduceus.staff.receipt.v1",
        "ok": false,
        "firstMissingSignal": signal,
        "stop": {"noun": "settings/shortcuts", "verb": transition},
        "observed": null,
        "could_change_to": could_change_to,
        "attempt": {"attempted": null, "step": format!("settings/shortcuts/{transition}"), "outcome": signal},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    }))
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
    Ok((result.0, Json(result.1)))
}

async fn mutate_http(Json(body): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    admitted(MUTATE_COMMAND)?;
    let result = crate::gate::blocking_task(MUTATE_COMMAND, move || actuator_receipt("set", Some(shortcut_payload(&body))))
        .await
        .map_err(|(status, Json(body))| (status, Json(serde_json::json!(body))))?;
    Ok((result.0, Json(result.1)))
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
