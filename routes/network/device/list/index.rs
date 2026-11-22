use crate::gate::ApiErrorBody;
use axum::http::StatusCode;
use axum::{response::Json, Router};
use serde_json::Value;

async fn device_list_route() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    crate::routes::network_read_route("network device list").await
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/network/device",
        axum::routing::get(device_list_route),
    )
}
