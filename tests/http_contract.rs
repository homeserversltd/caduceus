use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use caduceus::bands::serve;
use std::sync::Mutex;
use tower::ServiceExt;

static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

fn use_fixture(root: &str) -> std::sync::MutexGuard<'static, ()> {
    let guard = FIXTURE_LOCK.lock().unwrap();
    std::env::set_var("CADUCEUS_ROOT", root);
    guard
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn liveness_health_is_always_open() {
    let _guard = use_fixture("tests/fixtures/tv");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "current_thread")]
async fn tv_identity_route_is_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/tv");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/identity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test(flavor = "current_thread")]
async fn tv_pjlink_http_routes_are_profile_allowed_and_safe() {
    let _guard = use_fixture("tests/fixtures/tv");
    let app = serve::router();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pjlink/devices")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.pjlink.devices.v1");
    assert_eq!(json["devices"][0]["id"], "living-room-tv");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pjlink/power")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"deviceId":"living-room-tv","state":"on","dryRun":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.pjlink.power.v1");
    assert_eq!(json["mutation"], false);
    assert_eq!(json["dryRun"], true);
    assert_eq!(json["requestedState"], "on");

    let app = serve::router();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/pjlink/known-products")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.pjlink.known-products.v1");
    assert_eq!(json["entries"][0]["productName"], "Living Room TV");

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pjlink/product/scan")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"deviceId":"living-room-tv","dryRun":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.pjlink.product-scan.v1");
    assert_eq!(json["product"]["manufacturer"], "HOMESERVER");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pjlink/known-products")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"deviceId":"living-room-tv","dryRun":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.pjlink.known-product.add.v1");
    assert_eq!(json["mutation"], false);
    assert_eq!(
        json["entry"]["id"],
        "living-room-tv:homeserver:living-room-tv"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn locked_profile_rejects_disallowed_identity_route() {
    let _guard = use_fixture("tests/fixtures/locked");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/identity")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "current_thread")]
async fn console_update_status_route_is_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/console");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/update/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.update.status.v1");
    assert_eq!(json["routePresent"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn console_legacy_sbin_list_route_is_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/console");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/legacy-sbin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.legacy_sbin.list.v1");
    assert!(json["count"].as_u64().unwrap_or(0) > 20);
}

#[tokio::test(flavor = "current_thread")]
async fn console_legacy_sbin_show_returns_whole_body() {
    let _guard = use_fixture("tests/fixtures/console");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/legacy-sbin/show?id=openvpnup-sh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.legacy_sbin.show.v1");
    assert_eq!(json["entry"]["execution"], "not-executed-by-caduceus");
    assert!(json["entry"]["body"]
        .as_str()
        .unwrap_or("")
        .contains("NAMESPACE=\"vpn\""));
}

#[tokio::test(flavor = "current_thread")]
async fn locked_profile_rejects_legacy_sbin_list() {
    let _guard = use_fixture("tests/fixtures/locked");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/legacy-sbin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "current_thread")]
async fn console_update_service_status_reads_profile_timer() {
    let _guard = use_fixture("tests/fixtures/console");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/update/service/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["timer"], "harmonia-homeconsole.timer");
    assert!(!json["timerState"]
        .as_str()
        .unwrap_or("")
        .contains("arch-console-maintenance"));
}

#[tokio::test(flavor = "current_thread")]
async fn console_sync_now_route_is_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/console");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/sync/now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(response).await;
    assert_eq!(json["route"], "sync_now");
}

#[tokio::test(flavor = "current_thread")]
async fn console_gui_update_route_is_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/console");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/gui/update/now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let json = body_json(response).await;
    assert_eq!(json["route"], "gui_update_now");
}

#[tokio::test(flavor = "current_thread")]
async fn console_local_ai_runtime_status_reads_route() {
    let _guard = use_fixture("tests/fixtures/console");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/local-ai/runtime/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["routePresent"], true);
}

#[tokio::test(flavor = "current_thread")]
async fn locked_profile_rejects_console_update_now() {
    let _guard = use_fixture("tests/fixtures/locked");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/update/now")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "current_thread")]
async fn console_network_status_route_is_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/console");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/network/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.network.status.v1");
    assert_eq!(json["openvpnInterface"], "tun0");
    assert_eq!(json["portForwardingProcessPresent"], true);
    assert_eq!(json["tailscaleHasAddress"], true);
    assert_eq!(json["firstMissingSignal"], "none");
}

#[tokio::test(flavor = "current_thread")]
async fn locked_profile_rejects_network_status() {
    let _guard = use_fixture("tests/fixtures/locked");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/network/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "current_thread")]
async fn homeserver_sbin_list_route_is_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/homeserver-sbin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.homeserver_sbin.list.v1");
    assert_eq!(json["count"], 18);
}

#[tokio::test(flavor = "current_thread")]
async fn homeserver_sbin_show_route_preserves_body() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/homeserver-sbin/show?id=mountvault-sh")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.homeserver_sbin.show.v1");
    assert_eq!(json["entry"]["execution"], "not-executed-by-caduceus");
    assert_eq!(json["entry"]["replacementBand"], "vault");
}

#[tokio::test(flavor = "current_thread")]
async fn locked_profile_rejects_homeserver_sbin_list() {
    let _guard = use_fixture("tests/fixtures/locked");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/homeserver-sbin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "current_thread")]
async fn homeserver_staff_actuators_route_is_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/staff/actuators")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.staff.actuators.v1");
    assert_eq!(json["count"], 5);
    assert_eq!(json["actuators"][0]["actuatorClass"], "staff-python");
}

#[tokio::test(flavor = "current_thread")]
async fn locked_profile_rejects_staff_actuators() {
    let _guard = use_fixture("tests/fixtures/locked");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/staff/actuators")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "current_thread")]
async fn homeserver_staff_intent_route_accepts_coronatio_button_intent() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/staff/intent")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"method":"POST","route":"/api/admin/system/restart","classification":"crown-legacy"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.staff.intent.v1");
    assert_eq!(json["route"], "/api/admin/system/restart");
    assert_eq!(json["execution"], "queued-behind-typed-actuator");
}
