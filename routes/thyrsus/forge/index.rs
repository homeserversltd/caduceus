async fn route() -> axum::response::Response {
    crate::routes::thyrsus_support::handle(
        crate::routes::thyrsus_support::Verb::Forge,
        Ok(axum::Json(serde_json::json!({}))),
    )
    .await
}
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/thyrsus/forge", axum::routing::get(route))
}
