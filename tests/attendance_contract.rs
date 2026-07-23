use axum::body::Body;
use axum::http::{Request, StatusCode};
use caduceus::bands::serve;
use caduceus::tools::attendance;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use tower::ServiceExt;

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn request(path: &str, value: serde_json::Value) -> Request<Body> {
    Request::builder().method("POST").uri(path).header("content-type", "application/json").body(Body::from(value.to_string())).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn attendance_open_crosses_bound_staff_verifier_and_refuses_wrong_or_unprovisioned_pin() {
    let root = std::env::temp_dir().join(format!("caduceus-attendance-{}", std::process::id()));
    let bin = root.join("bin"); fs::create_dir_all(&bin).unwrap();
    let sudo = bin.join("sudo");
    fs::write(&sudo, "#!/bin/sh\n[ \"$1\" = -n ] || exit 9\ncase \"$2\" in\n/usr/local/sbin/caduceus-bind) echo '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}' ;;\n/usr/local/sbin/caduceus-verify) [ \"$3\" = 2468 ] && [ \"$4\" = fixture-public ] && echo '{\"ok\":true,\"verified\":true}' || echo '{\"ok\":false,\"verified\":false}' ;;\n*) exit 8;; esac\n").unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
    let old_path = std::env::var("PATH").unwrap(); std::env::set_var("PATH", format!("{}:{old_path}", bin.display()));
    attendance::reset_for_tests(); attendance::bind();
    let opened = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"2468"}))).await.unwrap();
    assert_eq!(opened.status(), StatusCode::OK); assert!(json(opened).await["attendance"].is_string());
    let wrong = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"nope"}))).await.unwrap();
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN); assert_eq!(json(wrong).await["firstMissingSignal"], "caduceus-attendance-pin-refused");
    attendance::reset_for_tests();
    let unbound = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"2468"}))).await.unwrap();
    assert_eq!(unbound.status(), StatusCode::FORBIDDEN); assert_eq!(json(unbound).await["firstMissingSignal"], "caduceus-pin-not-yet-provisioned");
    std::env::set_var("PATH", old_path); let _ = fs::remove_dir_all(root);
}

#[test]
fn retired_sidecar_and_routes_are_absent() { let serve = include_str!("../src/bands/serve.rs"); assert!(serve.contains("/api/v1/attendance/open")); assert!(!serve.contains("/api/v1/access/")); }
