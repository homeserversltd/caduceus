use axum::{extract::Json, Router};
use serde_json::Value;
#[path = "../support.rs"]
mod support;
const DECLARATION: &str = include_str!("index.json");
async fn route(
) -> Result<(axum::http::StatusCode, Json<Value>), (axum::http::StatusCode, Json<Value>)> {
    support::execute(
        "network device wifi saved",
        "saved",
        serde_json::json!({}),
        DECLARATION,
    )
    .await
}
pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/network/device/wifi/saved",
        axum::routing::get(route),
    )
}
