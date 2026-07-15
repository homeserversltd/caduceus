use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use caduceus::bands::serve;
use tower::ServiceExt;

fn request(peer: &str, body: Body) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/access/sessions/mint")
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
    request
}

#[tokio::test(flavor = "current_thread")]
async fn access_loopback_is_admitted_before_secret_body_is_dispatched() {
    let response = serve::router()
        .oneshot(request("127.0.0.1:40231", Body::from("{malformed")))
        .await
        .unwrap();
    // The JSON extractor runs for loopback; its parse response proves the
    // pre-body peer membrane did not reject the local peer.
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "current_thread")]
async fn nonloopback_access_is_refused_before_malformed_or_oversize_body_parsing() {
    for body in [Body::from("{malformed"), Body::from(vec![b'x'; 32 * 1024])] {
        let response = serve::router()
            .oneshot(request("192.0.2.44:40231", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["firstMissingSignal"], "caduceus-access-non-loopback");
    }
}
