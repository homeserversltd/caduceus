use axum::{extract::Json, http::StatusCode, Router};

pub const NAMESPACE: &str = "python/list";
pub async fn route() -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    crate::gate::snake::list()
        .map(Json)
        .map_err(|signal| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"ok":false,"firstMissingSignal":signal})),
            )
        })
}
pub fn register(router: Router) -> Router {
    router.route("/api/v1/python/list", axum::routing::get(route))
}
