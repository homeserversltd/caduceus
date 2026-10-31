async fn put(axum::Json(body): axum::Json<serde_json::Value>) -> axum::response::Response {
    crate::routes::memory_edition_support::edition_http(body).await
}
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/local-ai/edition", axum::routing::put(put))
}
