include!(concat!(env!("CARGO_MANIFEST_DIR"), "/routes/face/support.rs"));

async fn route(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    face_post(include_str!("index.json"), body).await
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/face/badge", axum::routing::post(route))
}
