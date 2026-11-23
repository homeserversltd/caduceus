use crate::gate::{api_error, api_error_signal, blocking_task, mutation_status, ApiErrorBody};
use crate::shared::{hyalos, policy};
use axum::{body::Bytes, http::StatusCode, routing::post, Json, Router};
use serde_json::{json, Value};

#[path = "hand.rs"]
pub(crate) mod hand;

const COMMAND: &str = "hyalos clear";

pub(crate) fn stamp_refusal(verb: &str, mut body: Value, attempted: Option<bool>) -> Value {
    if let Some(fields) = body
        .as_object_mut()
        .filter(|fields| fields.get("ok") == Some(&Value::Bool(false)))
    {
        let command = format!("log {verb}");
        let (noun, verb) = crate::shared::load_trace::refusal_stop(&command);
        let stamp = json!({
            "schema": "caduceus.staff.receipt.v1",
            "stop": {"noun": noun, "verb": verb},
            "observed": {"command": command},
            "could_change_to": null,
            "attempt": attempted.map(|attempted| json!({"attempted": attempted})),
            "final_receipt": {"ok": false, "firstMissingSignal": fields.get("firstMissingSignal")},
            "command": command,
        });
        // Keep the native outcome, including the count from an interrupted clear.
        if let Value::Object(stamp) = stamp {
            for (key, value) in stamp {
                fields.entry(key).or_insert(value);
            }
        }
    }
    body
}

async fn http(body: Bytes) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(COMMAND)),
        Err(_) => return Err(api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
    let outcome = blocking_task(COMMAND, move || {
        let value = if body.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&body).map_err(|_| hyalos::CLEAR_INVALID)?
        };
        hyalos::clear_json(&value)
    })
    .await?;
    Ok(match outcome {
        Ok(body) => (
            mutation_status(&body),
            Json(stamp_refusal("clear", body, None)),
        ),
        Err(signal) => (
            StatusCode::BAD_REQUEST,
            Json(stamp_refusal("clear", hyalos::door_error(signal), Some(false))),
        ),
    })
}

pub fn register(router: Router) -> Router {
    router.route(LEAF_LOG_CLEAR_CANONICAL, post(http))
}
