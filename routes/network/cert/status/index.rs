/// C2 route leaf.
pub const NAMESPACE: &str = "network/cert/status";

/// Canonical registration seam for this leaf.
async fn legacy_status() -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, axum::Json<serde_json::Value>)> { crate::routes::issue_certificate::status_json().map(axum::Json).map_err(|e|(axum::http::StatusCode::SERVICE_UNAVAILABLE,axum::Json(serde_json::json!({"firstMissingSignal":e})))) }
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/cert/status", axum::routing::get(legacy_status))
}
