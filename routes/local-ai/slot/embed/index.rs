async fn put(axum::Json(body): axum::Json<serde_json::Value>) -> axum::response::Response {
    crate::routes::memory_card_support::slot_http("embed", body).await
}
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/local-ai/slot/embed", axum::routing::put(put))
}
