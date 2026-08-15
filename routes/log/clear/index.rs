use crate::gate::{gated_mutation, ApiErrorBody};
use crate::routes::logs;
use axum::{
    http::{HeaderMap, StatusCode},
    Json,
};
use serde_json::Value;

pub const NAMESPACE: &str = "log/clear";

async fn clear_http(
    _headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("logs clear", logs::clear_json).await
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/log/clear", axum::routing::post(clear_http))
}
