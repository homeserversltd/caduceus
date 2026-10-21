include!(concat!(env!("CARGO_MANIFEST_DIR"), "/routes/face/support.rs"));

async fn route(
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::extract::FromRequest;
    use axum::response::IntoResponse;

    let payload = if body.is_empty() {
        serde_json::json!({})
    } else {
        let mut request = axum::http::Request::new(axum::body::Body::from(body));
        *request.headers_mut() = headers;
        match axum::Json::<serde_json::Value>::from_request(request, &()).await {
            Ok(axum::Json(payload)) => payload,
            Err(rejection) => return rejection.into_response(),
        }
    };
    face_post_with_timeout(
        include_str!("index.json"),
        payload,
        Some(std::time::Duration::from_secs(60)),
    )
    .await
    .into_response()
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/face/dictate", axum::routing::post(route))
}
