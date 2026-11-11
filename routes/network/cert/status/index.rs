/// C2 route leaf.
pub const NAMESPACE: &str = "network/cert/status";

/// Canonical registration seam for this leaf.
pub(super) async fn legacy_status() -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, axum::Json<serde_json::Value>)> {
    let result = crate::gate::blocking_task("cert status", || crate::routes::issue_certificate::status_receipt(std::time::Duration::from_secs(60)))
        .await
        .map_err(|(status, axum::Json(body))| (status, axum::Json(serde_json::json!(body))))?;
    result
        .map(axum::Json)
        .map_err(|e|(axum::http::StatusCode::SERVICE_UNAVAILABLE,axum::Json(e)))
}
pub fn register(router: axum::Router) -> axum::Router {
    router
}
