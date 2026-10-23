async fn put(axum::Json(body): axum::Json<serde_json::Value>) -> axum::response::Response {
    crate::routes::memory_card_support::slot_http("brain", body).await
}
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/local-ai/slot/brain", axum::routing::put(put))
}
