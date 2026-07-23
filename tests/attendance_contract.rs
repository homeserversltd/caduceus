use axum::body::Body;
use axum::http::{Request, StatusCode};
use caduceus::bands::serve;
use tower::ServiceExt;

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn request(path: &str, value: serde_json::Value) -> Request<Body> {
    Request::builder().method("POST").uri(path).header("content-type", "application/json").body(Body::from(value.to_string())).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn attendance_open_validate_invalidate_is_document_incarnation_bound() {
    let opened = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1"}))).await.unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let opened = json(opened).await;
    let attendance = opened["attendance"].as_str().unwrap();
    let valid = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"attendance":attendance,"documentId":"doc-a","documentIncarnation":"inc-1"}))).await.unwrap();
    assert_eq!(valid.status(), StatusCode::OK);
    assert_eq!(json(valid).await["ok"], true);
    let mismatch = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"attendance":attendance,"documentId":"doc-a","documentIncarnation":"inc-2"}))).await.unwrap();
    assert_eq!(mismatch.status(), StatusCode::FORBIDDEN);
    assert_eq!(json(mismatch).await["firstMissingSignal"], "caduceus-attendance-document-incarnation-mismatch");
    let invalidated = serve::router().oneshot(request("/api/v1/attendance/invalidate", serde_json::json!({"attendance":attendance,"documentId":"doc-a","documentIncarnation":"inc-1"}))).await.unwrap();
    assert_eq!(invalidated.status(), StatusCode::OK);
    let after = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"attendance":attendance,"documentId":"doc-a","documentIncarnation":"inc-1"}))).await.unwrap();
    assert_eq!(after.status(), StatusCode::FORBIDDEN);
}

#[test]
fn retired_sidecar_and_routes_are_absent() {
    let serve = include_str!("../src/bands/serve.rs");
    assert!(serve.contains("/api/v1/attendance/open"));
    assert!(serve.contains("/api/v1/attendance/validate"));
    assert!(serve.contains("/api/v1/attendance/invalidate"));
    assert!(!serve.contains("/api/v1/access/"));
    assert!(!std::path::Path::new("src/tools/access.rs").exists());
}
