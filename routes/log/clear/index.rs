use crate::gate::{api_error, api_error_signal, blocking_task, mutation_status, ApiErrorBody};
use crate::shared::{hyalos, policy};
use axum::{body::Bytes, http::StatusCode, routing::post, Json, Router};
use serde_json::{json, Value};

#[path = "hand.rs"]
pub(crate) mod hand;

const COMMAND: &str = "hyalos clear";

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
        Ok(body) => (mutation_status(&body), Json(body)),
        Err(signal) => (StatusCode::BAD_REQUEST, Json(hyalos::door_error(signal))),
    })
}

pub fn register(router: Router) -> Router {
    router.route(LEAF_LOG_CLEAR_CANONICAL, post(http))
}
