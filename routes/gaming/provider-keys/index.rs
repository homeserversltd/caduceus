use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;

pub const NAMESPACE: &str = "gaming/provider-keys";

async fn act(
    Json(input): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    crate::routes::canopy::staff_route(
        input,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/routes/gaming/provider-keys/index.json"
        )),
    )
}

/// One canonical cold-seat endpoint; profile commands remain metadata only.
pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/gaming/provider-keys",
        axum::routing::post(act),
    )
}
