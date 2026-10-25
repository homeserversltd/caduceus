async fn route(
    body: Result<axum::Json<serde_json::Value>, axum::extract::rejection::JsonRejection>,
) -> axum::response::Response {
    crate::routes::thyrsus_support::handle(crate::routes::thyrsus_support::Verb::Propose, body)
        .await
}
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/thyrsus/propose", axum::routing::post(route))
}
