async fn read() -> axum::response::Response {
    crate::routes::memory_card_support::read_http("library").await
}
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/local-ai/library", axum::routing::get(read))
}
