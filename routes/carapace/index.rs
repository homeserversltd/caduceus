use axum::{routing::get, Json, Router};
use serde_json::Value;

async fn carapace() -> Json<Value> {
    Json(crate::shared::config::carapace_with_build_identity())
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/carapace", get(carapace))
}
