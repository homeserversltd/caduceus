async fn route(
    body: Result<axum::Json<serde_json::Value>, axum::extract::rejection::JsonRejection>,
) -> axum::response::Response {
    crate::routes::thyrsus_support::handle(crate::routes::thyrsus_support::Verb::Admit, body).await
}
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/thyrsus/admit", axum::routing::post(route))
}
