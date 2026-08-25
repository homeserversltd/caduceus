use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;

pub const NAMESPACE: &str = "gaming/input/profile/write";

async fn act(
    Json(input): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let _ = input;
    crate::routes::canopy::staff_route(
        input,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/routes/gaming/input/profile/write/index.json"
        )),
    )
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/gaming/input/profile/write",
        axum::routing::post(act),
    )
}
