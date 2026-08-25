use axum::{extract::Json, Router};
use serde_json::Value;
#[path = "../wifi/support.rs"]
mod support;
const DECLARATION: &str = include_str!("index.json");
async fn route(
    Json(body): Json<Value>,
) -> Result<(axum::http::StatusCode, Json<Value>), (axum::http::StatusCode, Json<Value>)> {
    support::execute("network device connect", "connect", body, DECLARATION).await
}
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/device/connect", axum::routing::post(route))
}
