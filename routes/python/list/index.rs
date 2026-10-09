use axum::{extract::Json, http::StatusCode, Router};

pub const NAMESPACE: &str = "python/list";
pub async fn route() -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let result = crate::gate::blocking_task("python list", crate::gate::snake::list)
        .await
        .map_err(|(status, Json(body))| (status, Json(serde_json::json!(body))))?;
    result
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
