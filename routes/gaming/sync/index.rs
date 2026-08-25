use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;

pub const NAMESPACE: &str = "gaming/sync";

async fn act(
    Json(input): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    crate::routes::canopy::staff_route(
        input,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/routes/gaming/sync/index.json"
        )),
    )
}

/// Canonical registration plus the ratified `/games/sync` compatibility alias.
pub fn register(router: Router) -> Router {
    router
        .route("/api/v1/gaming/sync", axum::routing::post(act))
        .route("/api/v1/games/sync", axum::routing::post(act))
}
