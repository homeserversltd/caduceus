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
    fs::write(&sudo, "#!/bin/sh\n[ \"$1\" = -n ] || exit 9\ncase \"$2\" in\n/usr/local/sbin/caduceus-bind) echo '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}' ;;\n/usr/local/sbin/caduceus-verify) payload=$(cat); case \"$payload\" in *'\"pin\":\"2468\"'*'\"publicKey\":\"fixture-public\"'*) echo '{\"ok\":true,\"verified\":true}' ;; *'\"pin\":\"9753\"'*'\"publicKey\":\"fixture-new\"'*) echo '{\"ok\":true,\"verified\":true}' ;; *) echo '{\"ok\":false,\"verified\":false}' ;; esac ;;\n/usr/local/sbin/caduceus-atomic-change-pin) payload=$(cat); case \"$payload\" in *'\"newPin\":\"0000\"'*) echo '{\"ok\":false,\"firstMissingSignal\":\"fixture-staff-failure\"}'; exit 1 ;; *'\"newPin\":\"9753\"'*) case \"$payload\" in *'\"oldPin\":\"2468\"'*) echo '{\"ok\":true,\"publicKey\":\"fixture-new\",\"epoch\":\"2\",\"rotated\":true}' ;; *) exit 7 ;; esac ;; *) exit 7 ;; esac ;;\n*) exit 8;; esac\n").unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
    let old_path = std::env::var("PATH").unwrap(); std::env::set_var("PATH", format!("{}:{old_path}", bin.display()));
    attendance::reset_for_tests(); attendance::bind();
    let opened = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"2468"}))).await.unwrap();
    assert_eq!(opened.status(), StatusCode::OK); let presenting = json(opened).await["attendance"].as_str().unwrap().to_string();
    let other = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-b","documentIncarnation":"inc-2","pin":"2468"}))).await.unwrap();
    assert_eq!(other.status(), StatusCode::OK); let other = json(other).await["attendance"].as_str().unwrap().to_string();
    let wrong = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"nope"}))).await.unwrap();
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN); assert_eq!(json(wrong).await["firstMissingSignal"], "caduceus-attendance-pin-refused");
    let missing_new_pin = serve::router().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468"}))).await.unwrap();
    assert_eq!(missing_new_pin.status(), StatusCode::FORBIDDEN); assert_eq!(json(missing_new_pin).await["firstMissingSignal"], "caduceus-attendance-newPin-missing");
    let wrong_current_pin = serve::router().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"nope","newPin":"9753"}))).await.unwrap();
    assert_eq!(wrong_current_pin.status(), StatusCode::FORBIDDEN); assert_eq!(json(wrong_current_pin).await["firstMissingSignal"], "caduceus-attendance-pin-refused");
    let failed_change = serve::router().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468","newPin":"0000"}))).await.unwrap();
    assert_eq!(failed_change.status(), StatusCode::FORBIDDEN); assert_eq!(json(failed_change).await["firstMissingSignal"], "caduceus-attendance-change-failed");
    for (document_id, document_incarnation, attendance) in [("doc-a", "inc-1", &presenting), ("doc-b", "inc-2", &other)] {
        let still_current = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":document_id,"documentIncarnation":document_incarnation,"attendance":attendance}))).await.unwrap();
        assert_eq!(still_current.status(), StatusCode::OK);
    }
    let changed = serve::router().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468","newPin":"9753"}))).await.unwrap();
    assert_eq!(changed.status(), StatusCode::OK);
    let presenting_survives = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting}))).await.unwrap();
    assert_eq!(presenting_survives.status(), StatusCode::OK);
    let other_evicted = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":"doc-b","documentIncarnation":"inc-2","attendance":other}))).await.unwrap();
    assert_eq!(other_evicted.status(), StatusCode::FORBIDDEN); assert_eq!(json(other_evicted).await["firstMissingSignal"], "caduceus-attendance-not-current");
    let reopened = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-c","documentIncarnation":"inc-3","pin":"9753"}))).await.unwrap();
    assert_eq!(reopened.status(), StatusCode::OK);
    attendance::reset_for_tests();
    let unbound = serve::router().oneshot(request("/api/v1/attendance/open", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"2468"}))).await.unwrap();
    assert_eq!(unbound.status(), StatusCode::FORBIDDEN); assert_eq!(json(unbound).await["firstMissingSignal"], "caduceus-pin-not-yet-provisioned");
    std::env::set_var("PATH", old_path); let _ = fs::remove_dir_all(root);
}

#[test]
fn retired_sidecar_and_routes_are_absent() { let serve = include_str!("../src/bands/serve.rs"); assert!(serve.contains("/api/v1/attendance/open")); assert!(serve.contains("/api/v1/attendance/change-pin")); assert!(!serve.contains("/api/v1/access/")); }
