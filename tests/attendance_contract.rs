use axum::body::Body;
use axum::http::{Request, StatusCode};
use caduceus::routes::serve;
use caduceus::shared::attendance;
use std::fs;
use std::os::unix::fs::PermissionsExt;
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
    let root = std::env::temp_dir().join(format!("caduceus-attendance-{}", std::process::id()));
    let bin = root.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let sudo = bin.join("sudo");
    fs::write(&sudo, "#!/bin/sh\ncase \"$1/$2\" in\nexousia/bind) cat >/dev/null; if [ -f \"$(dirname \"$0\")/rotated\" ]; then printf '%s\\n' '{\"ok\":true,\"publicKey\":\"fixture-new\",\"epoch\":\"2\"}'; else printf '%s\\n' '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}'; fi ;;\nexousia/verify) payload=$(cat); case \"$payload\" in *'\"pin\":\"2468\"'*'\"publicKey\":\"fixture-public\"'*) printf '%s\\n' '{\"ok\":true,\"verified\":true}' ;; *'\"pin\":\"9753\"'*'\"publicKey\":\"fixture-new\"'*) printf '%s\\n' '{\"ok\":true,\"verified\":true}' ;; *) printf '%s\\n' '{\"ok\":true,\"verified\":false}' ;; esac ;;\nexousia/change) payload=$(cat); case \"$payload\" in *'\"newPin\":\"0000\"'*) printf '%s\\n' '{\"ok\":false,\"firstMissingSignal\":\"fixture-staff-failure\"}'; exit 1 ;; *'\"newPin\":\"9753\"'*'\"oldPin\":\"2468\"'*) touch \"$(dirname \"$0\")/rotated\"; printf '%s\\n' '{\"ok\":true,\"publicKey\":\"fixture-new\",\"epoch\":\"2\",\"rotated\":true}' ;; *) exit 7 ;; esac ;;\n*) exit 8 ;;\nesac\n").unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
    let old_path = std::env::var("PATH").unwrap();
    let old_launcher = std::env::var_os("CADUCEUS_AGATHODAIMON_CLI");
    std::env::set_var("PATH", format!("{}:{old_path}", bin.display()));
    std::env::set_var("CADUCEUS_AGATHODAIMON_CLI", &sudo);
    attendance::reset_for_tests();
    attendance::bind();
    let opened = serve::router()
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
    let other = serve::router()
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
    let wrong = serve::router()
        .oneshot(request(
            "/api/v1/attendance/open",
            serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","pin":"nope"}),
        ))
        .await
        .unwrap();
    assert_eq!(wrong.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(wrong).await["firstMissingSignal"],
        "caduceus-attendance-pin-wrong"
    );
    let missing_new_pin = serve::router().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468"}))).await.unwrap();
    assert_eq!(missing_new_pin.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(missing_new_pin).await["firstMissingSignal"],
        "caduceus-attendance-newPin-missing"
    );
    let wrong_current_pin = serve::router().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"nope","newPin":"9753"}))).await.unwrap();
    assert_eq!(wrong_current_pin.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(wrong_current_pin).await["firstMissingSignal"],
        "caduceus-attendance-pin-wrong"
    );
    let failed_change = serve::router().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468","newPin":"0000"}))).await.unwrap();
    assert_eq!(failed_change.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(failed_change).await["firstMissingSignal"],
        "caduceus-attendance-change-failed"
    );
    for (document_id, document_incarnation, attendance) in
        [("doc-a", "inc-1", &presenting), ("doc-b", "inc-2", &other)]
    {
        let still_current = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":document_id,"documentIncarnation":document_incarnation,"attendance":attendance}))).await.unwrap();
        assert_eq!(still_current.status(), StatusCode::OK);
    }
    let changed = serve::router().oneshot(request("/api/v1/attendance/change-pin", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting,"currentPin":"2468","newPin":"9753"}))).await.unwrap();
    assert_eq!(changed.status(), StatusCode::OK);
    let presenting_survives = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":"doc-a","documentIncarnation":"inc-1","attendance":presenting}))).await.unwrap();
    assert_eq!(presenting_survives.status(), StatusCode::OK);
    let other_evicted = serve::router().oneshot(request("/api/v1/attendance/validate", serde_json::json!({"documentId":"doc-b","documentIncarnation":"inc-2","attendance":other}))).await.unwrap();
    assert_eq!(other_evicted.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(other_evicted).await["firstMissingSignal"],
        "caduceus-attendance-not-current"
    );
    let reopened = serve::router()
        .oneshot(request(
            "/api/v1/attendance/open",
            serde_json::json!({"documentId":"doc-c","documentIncarnation":"inc-3","pin":"9753"}),
        ))
        .await
        .unwrap();
    assert_eq!(reopened.status(), StatusCode::OK);
    let agent = serve::router()
        .oneshot(request(
            "/api/v1/exousia/open",
            serde_json::json!({
                "schema": "caduceus.staff.v1",
                "intent_id": "agent-exousia-open",
                "transition": "exousia.open",
                "target": {
                    "document": "/api/v1/appliance/service/{service}/restart",
                    "service": "coronatio",
                    "action": "restart"
                },
                "flags": {"exousia": {"pin": "9753"}},
                "unknown_additive": {"retained": true}
            }),
        ))
        .await
        .unwrap();
    assert_eq!(agent.status(), StatusCode::OK);
    let agent = json(agent).await;
    assert_eq!(
        agent["documentId"],
        "/api/v1/appliance/service/{service}/restart"
    );
    assert!(agent.get("pin").is_none());
    assert!(!agent.to_string().contains("9753"));
    assert!(attendance::admits_target(
        agent["attendance"].as_str().unwrap(),
        "/api/v1/appliance/service/{service}/restart"
    ));
    fs::remove_file(bin.join("rotated")).unwrap();
    let stale = serve::router()
        .oneshot(request(
            "/api/v1/attendance/open",
            serde_json::json!({"documentId":"doc-stale","documentIncarnation":"inc-stale","pin":"9753"}),
        ))
        .await
        .unwrap();
    assert_eq!(stale.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(stale).await["firstMissingSignal"],
        "caduceus-signer-stale-derived"
    );
    fs::write(bin.join("rotated"), b"").unwrap();
    let posture = attendance::posture_json().unwrap();
    assert_eq!(posture["posture"], "DERIVED_BOUND");
    assert_eq!(posture["bound"], true);
    assert_eq!(posture["currentPresent"], true);
    assert_eq!(posture["epochMatches"], true);
    assert!(posture.get("publicKey").is_none());
    assert!(posture.get("epoch").is_none());
    attendance::reset_for_tests();
    let unbound = serve::router()
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
    std::env::set_var("PATH", old_path);
    match old_launcher {
        Some(value) => std::env::set_var("CADUCEUS_AGATHODAIMON_CLI", value),
        None => std::env::remove_var("CADUCEUS_AGATHODAIMON_CLI"),
    }
    let _ = fs::remove_dir_all(root);
}

#[test]
fn retired_sidecar_and_routes_are_absent() {
    assert!(!Path::new("routes/gate.rs").exists());
    assert!(include_str!("../gate/index.rs").contains("pub fn router"));
}
