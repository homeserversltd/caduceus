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
    face_post_with_timeout(
        include_str!("index.json"),
        body,
        Some(std::time::Duration::from_secs(60)),
    )
    .await
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/face/dictate", axum::routing::post(route))
}
