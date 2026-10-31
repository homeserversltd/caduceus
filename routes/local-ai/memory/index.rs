async fn read() -> axum::response::Response {
    crate::routes::memory_edition_support::memory_http().await
}
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/local-ai/memory", axum::routing::get(read))
}
