use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use caduceus::bands::serve;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

fn capability(action: &str, target: &str, seconds_from_now: i64) -> String {
    capability_with_seed(
        action,
        target,
        seconds_from_now,
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    )
}

fn capability_with_seed(
    action: &str,
    target: &str,
    seconds_from_now: i64,
    seed_hex: &str,
) -> String {
    let seed = hex_bytes(seed_hex);
    let key = SigningKey::from_bytes(&seed.try_into().unwrap());
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let exp = (now + seconds_from_now).max(0) as u64;
    let payload = format!(
        r#"{{"actor":"fixture","action":"{}","target":"{}","exp":{}}}"#,
        action, target, exp
    );
    let signature = key.sign(payload.as_bytes());
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn hex_bytes(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

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
                .header(
                    "x-caduceus-capability",
                    capability("pjlink power set", "living-room-tv", 60),
                )
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
                .header(
                    "x-caduceus-capability",
                    capability("pjlink scan", "living-room-tv", 60),
                )
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
                .header(
                    "x-caduceus-capability",
                    capability("pjlink known add", "living-room-tv", 60),
                )
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
                .header("x-caduceus-capability", capability("sync now", "local", 60))
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
                .header(
                    "x-caduceus-capability",
                    capability("gui update now", "local", 60),
                )
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
                .header(
                    "x-caduceus-capability",
                    capability("update now", "local", 60),
                )
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
    assert_eq!(json["count"], 6);
    assert_eq!(json["actuators"][0]["id"], "network-dhcp");
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
                .header("x-caduceus-capability", capability("staff intent", "/api/admin/system/restart", 60))
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

#[tokio::test(flavor = "current_thread")]
async fn homeserver_staff_intent_route_accepts_upload_metadata() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/staff/intent")
                .header("x-caduceus-capability", capability("staff intent", "/api/files/upload", 60))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"method":"POST","route":"/api/files/upload","classification":"file-ingress","metadata":{"filename":"proof.txt","bytes":5,"destination":"/mnt/nas"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.staff.intent.v1");
    assert_eq!(json["upload"]["schema"], "caduceus.staff.upload_intent.v1");
    assert_eq!(json["upload"]["metadata"]["filename"], "proof.txt");
    assert_eq!(json["execution"], "upload-queued-behind-typed-actuator");
}

#[tokio::test(flavor = "current_thread")]
async fn http_capability_walls_cover_fresh_expired_scope_tampered_and_missing() {
    let _guard = use_fixture("tests/fixtures/tv");
    let app = serve::router();

    let fresh = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pjlink/power")
                .header(
                    "x-caduceus-capability",
                    capability("pjlink power set", "living-room-tv", 60),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"deviceId":"living-room-tv","state":"on","dryRun":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(fresh.status(), StatusCode::OK);
    assert_eq!(body_json(fresh).await["mutation"], false);

    let expired = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pjlink/power")
                .header(
                    "x-caduceus-capability",
                    capability("pjlink power set", "living-room-tv", -10),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"deviceId":"living-room-tv","state":"on","dryRun":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(expired.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(expired).await["firstMissingSignal"],
        "caduceus-capability-expired"
    );

    let scope = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pjlink/power")
                .header(
                    "x-caduceus-capability",
                    capability("pjlink power set", "other-tv", 60),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"deviceId":"living-room-tv","state":"on","dryRun":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(scope.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(scope).await["firstMissingSignal"],
        "caduceus-capability-scope"
    );

    let token = capability("pjlink power set", "living-room-tv", 60);
    let (payload, signature) = token.split_once('.').unwrap();
    let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
    let token = format!("{payload}.{replacement}{}", &signature[1..]);
    let tampered = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/pjlink/power")
                .header("x-caduceus-capability", token)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"deviceId":"living-room-tv","state":"on","dryRun":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tampered.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(tampered).await["firstMissingSignal"],
        "caduceus-capability-unsigned"
    );

    let missing = app
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
    assert_eq!(missing.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(missing).await["firstMissingSignal"],
        "caduceus-capability-unsigned"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn homeserver_dhcp_http_status_and_staff_intent_execute_python_actuator() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    std::env::set_var("PYTHONPATH", "tests/fixtures/staff");
    std::env::set_var(
        "CADUCEUS_DHCP_CMD",
        "python3 -m caduceus_staff.network.dhcp",
    );
    let app = serve::router();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/network/dhcp/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await["schema"],
        "caduceus.network.dhcp.status.v1"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/staff/intent")
                .header(
                    "x-caduceus-capability",
                    capability("staff intent", "/api/dhcp/reservations", 60),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"method":"POST","route":"/api/dhcp/reservations","metadata":{"ip":"192.168.1.7"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = body_json(response).await;
    assert_eq!(json["classification"], "network-control");
    assert_eq!(json["mutationPerformed"], true);
    assert_eq!(json["execution"], "caduceus_staff.network.dhcp");
}
