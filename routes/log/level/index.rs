use crate::gate::{api_error, api_error_signal, blocking_task, mutation_status, ApiErrorBody};
use crate::shared::{hyalos, policy};
use axum::{body::Bytes, http::StatusCode, routing::get, Json, Router};
use serde_json::Value;

const COMMAND: &str = "hyalos level";
type Reply = Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)>;

async fn run(action: impl FnOnce() -> hyalos::DoorResult + Send + 'static) -> Reply {
    match policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(COMMAND)),
        Err(_) => return Err(api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
    Ok(match blocking_task(COMMAND, action).await? {
        Ok(body) => (mutation_status(&body), Json(body)),
        Err(signal) => (StatusCode::BAD_REQUEST, Json(hyalos::door_error(signal))),
    })
}

async fn read() -> Reply {
    run(|| Ok(hyalos::level_json())).await
}

async fn set(body: Bytes) -> Reply {
    run(move || {
        let value = serde_json::from_slice(&body).map_err(|_| hyalos::LEVEL_INVALID)?;
        hyalos::set_level_json(&value)
    })
    .await
}

pub fn register(router: Router) -> Router {
    router.route(LEAF_LOG_LEVEL_CANONICAL, get(read).post(set))
}
