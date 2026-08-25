use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;

pub const NAMESPACE: &str = "appliance/poweroff";

async fn act(
    Json(input): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let _ = input;
    crate::routes::canopy::staff_route(
        input,
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/routes/appliance/poweroff/index.json"
        )),
    )
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/appliance/poweroff", axum::routing::post(act))
}
