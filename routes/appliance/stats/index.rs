use crate::gate::{gated_json, ApiErrorBody};
use axum::{http::StatusCode, Json};
use serde_json::Value;

async fn current_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("appliance stats read", crate::stats::current).await
}
async fn history_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("appliance stats read", crate::stats::history).await
}
async fn pulse_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("appliance stats read", crate::stats::request_model_lane_pulse).await
}
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/appliance/stats", axum::routing::get(current_http))
        .route(
            "/api/v1/appliance/stats/history",
            axum::routing::get(history_http),
        )
        .route(
            "/api/v1/appliance/model-lanes/pulse",
            axum::routing::post(pulse_http),
        )
}
