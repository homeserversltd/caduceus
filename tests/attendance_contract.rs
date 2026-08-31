use axum::body::Body;
use axum::http::{Request, StatusCode};
use caduceus::routes::serve;
use caduceus::shared::attendance;
use std::path::Path;
use tower::ServiceExt;

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn request(path: &str, value: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn attendance_open_crosses_bound_staff_verifier_and_refuses_wrong_or_unprovisioned_pin() {
    let old_staff_cli = std::env::var_os("CADUCEUS_AGATHODAIMON_CLI");
    let staff_cli = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/staff/agathodaimon/cli.py");
    std::env::set_var("CADUCEUS_AGATHODAIMON_CLI", &staff_cli);
    attendance::reset_for_tests();
    attendance::bind();
    let router = serve::router();
    let opened = router
        .clone()
        .oneshot(request(
            "/api/v1/attendance/open",
            serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"2468"}),
        ))
        .await
        .unwrap();
    assert_eq!(opened.status(), StatusCode::OK);
    let presenting = json(opened).await["attendance"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(attendance::admits_target(&presenting, "doc-a"));
    assert!(!attendance::admits_target(&presenting, "doc-b"));
    let other = router
        .clone()
        .oneshot(request(
            "/api/v1/attendance/open",
            serde_json::json!({"documentId":"doc-b","documentIncarnation":"inc-2","pin":"2468"}),
        ))
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::OK);
    let other = json(other).await["attendance"]
        .as_str()
        .unwrap()
        .to_string();
    let wrong = router
        .clone()
        .oneshot(request(
            "/api/v1/attendance/open",
            serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"nope"}),
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(wrong).await["firstMissingSignal"],
        "caduceus-attendance-pin-refused"
    );
    let missing_new_pin = router.clone().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468"}))).await.unwrap();
    assert_eq!(missing_new_pin.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(missing_new_pin).await["firstMissingSignal"],
        "caduceus-attendance-newPin-missing"
    );
    let wrong_current_pin = router.clone().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"nope","newPin":"9753"}))).await.unwrap();
    assert_eq!(wrong_current_pin.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(wrong_current_pin).await["firstMissingSignal"],
        "caduceus-attendance-pin-refused"
    );
    let failed_change = router.clone().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468","newPin":"0000"}))).await.unwrap();
    assert_eq!(failed_change.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(failed_change).await["firstMissingSignal"],
        "caduceus-attendance-change-failed"
    );
    for (document_id, document_incarnation, attendance) in
        [("doc-a", "inc-1", &presenting), ("doc-b", "inc-2", &other)]
    {
        let still_current = router.clone().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":document_id,"documentIncarnation":document_incarnation,"attendance":attendance}))).await.unwrap();
        assert_eq!(still_current.status(), StatusCode::OK);
    }
    let changed = router.clone().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468","newPin":"9753"}))).await.unwrap();
    assert_eq!(changed.status(), StatusCode::OK);
    let presenting_survives = router.clone().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting}))).await.unwrap();
    assert_eq!(presenting_survives.status(), StatusCode::OK);
    let other_evicted = router.clone().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":"doc-b","documentIncarnation":"inc-2","attendance":other}))).await.unwrap();
    assert_eq!(other_evicted.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(other_evicted).await["firstMissingSignal"],
        "caduceus-attendance-not-current"
    );
    let reopened = router
        .clone()
        .oneshot(request(
            "/api/v1/attendance/open",
            serde_json::json!({"documentId":"doc-c","documentIncarnation":"inc-3","pin":"9753"}),
        ))
        .await
        .unwrap();
    assert_eq!(reopened.status(), StatusCode::OK);
    attendance::reset_for_tests();
    let unbound = router
        .clone()
        .oneshot(request(
            "/api/v1/attendance/open",
            serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"2468"}),
        ))
        .await
        .unwrap();
    assert_eq!(unbound.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(unbound).await["firstMissingSignal"],
        "caduceus-pin-not-yet-provisioned"
    );
    match old_staff_cli {
        Some(value) => std::env::set_var("CADUCEUS_AGATHODAIMON_CLI", value),
        None => std::env::remove_var("CADUCEUS_AGATHODAIMON_CLI"),
    }
}

#[test]
fn retired_sidecar_and_routes_are_absent() {
    assert!(!Path::new("routes/gate.rs").exists());
    assert!(include_str!("../gate/index.rs").contains("pub fn router"));
}
