

use serde_json::Value;
use axum::{response::Json, Router};
use crate::gate::{gated_json, ApiErrorBody};

async fn network_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("network status", network::status_json).await
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/status", axum::routing::get(network_status_route))
}
