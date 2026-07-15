use axum::body::{to_bytes, Body};
use axum::extract::ConnectInfo;
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
async fn network_dns_mutation_requires_scoped_unexpired_capability() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let request = |token: Option<String>| {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/api/v1/network/dns")
            .header("content-type", "application/json");
        if let Some(token) = token {
            builder = builder.header("x-caduceus-capability", token);
        }
        builder
            .body(Body::from(
                r#"{"dropIn":"server: local-zone: \\\"home.arpa. transparent\\\""}"#,
            ))
            .unwrap()
    };

    for (token, signal) in [
        (None, "caduceus-capability-unsigned".to_string()),
        (
            Some(capability("wrong action", "/api/dns/unbound/drop-in", 60)),
            "caduceus-capability-scope".to_string(),
        ),
        (
            Some(capability("network dns", "/api/dns/unbound/drop-in", -1)),
            "caduceus-capability-expired".to_string(),
        ),
    ] {
        let response = serve::router().oneshot(request(token)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let json = body_json(response).await;
        assert_eq!(json["firstMissingSignal"], signal);
    }
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
    assert_eq!(json["count"], 10);
    assert_eq!(json["actuators"][0]["id"], "network-dhcp");
    assert_eq!(json["actuators"][1]["id"], "network-dns");
    assert_eq!(json["actuators"][2]["id"], "household-capability");
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
async fn loopback_portal_service_skips_capability_but_remote_does_not() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let root = std::env::temp_dir().join(format!("caduceus-http-systemctl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let systemctl = root.join("systemctl");
    std::fs::write(
        &systemctl,
        "#!/bin/sh\n[ \"$1\" = is-active ] && echo active\nexit 0\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(&systemctl).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut permissions, 0o755);
    std::fs::set_permissions(&systemctl, permissions).unwrap();
    std::env::set_var("CADUCEUS_SYSTEMCTL_BIN", &systemctl);
    let body = r#"{"method":"POST","route":"/api/service/control","classification":"portal-service","metadata":{"service":"jellyfin","action":"restart","systemdService":"jellyfin.service"}}"#;

    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/staff/intent")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "127.0.0.1:43210".parse::<std::net::SocketAddr>().unwrap(),
    ));
    let response = serve::router().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    assert_eq!(
        body_json(response).await["systemdService"],
        "jellyfin.service"
    );

    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/staff/intent")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    request.extensions_mut().insert(ConnectInfo(
        "192.0.2.1:43210".parse::<std::net::SocketAddr>().unwrap(),
    ));
    assert_eq!(
        serve::router().oneshot(request).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    std::env::remove_var("CADUCEUS_SYSTEMCTL_BIN");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "current_thread")]
async fn homeserver_staff_intent_route_executes_upload_bytes() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let root = std::env::temp_dir().join(format!("caduceus-http-upload-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::copy(
        "tests/fixtures/homeserver/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    std::env::set_var("CADUCEUS_ROOT", &root);
    std::env::set_var("CADUCEUS_FILE_INGRESS_ROOT", &root);
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/staff/intent")
                .header("x-caduceus-capability", capability("staff intent", "/api/files/upload", 60))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"method":"POST","route":"/api/files/upload","classification":"file-ingress","metadata":{"filename":"proof.txt","bytes":5,"destination":"/mnt/nas","payload":[104,101,108,108,111]}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.staff.file_ingress.v1");
    assert_eq!(json["mutationPerformed"], true);
    assert_eq!(json["execution"], "native-rust-file-ingress");
    assert_eq!(json["hyalos"]["event"]["kind"], "upload");
    assert_eq!(std::fs::read(root.join("proof.txt")).unwrap(), b"hello");
    assert!(
        std::fs::read_to_string(root.join("var/log/hyalos/channel.jsonl"))
            .unwrap()
            .contains("proof.txt")
    );
    assert!(!root.join("var/log/hyalos/projections/upload.log").exists());
    std::env::remove_var("CADUCEUS_FILE_INGRESS_ROOT");
    let _ = std::fs::remove_dir_all(root);
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

fn config_temp_root(tag: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("caduceus-http-config-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::create_dir_all(root.join("etc/tv")).unwrap();
    std::fs::copy(
        "tests/fixtures/tv/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    std::fs::copy(
        "tests/fixtures/tv/etc/tv/config.json",
        root.join("etc/tv/config.json"),
    )
    .unwrap();
    root
}

#[tokio::test(flavor = "current_thread")]
async fn config_path_show_get_routes_resolve_tv_profile() {
    let _guard = use_fixture("tests/fixtures/tv");
    let app = serve::router();

    let path = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/config/path")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(path.status(), StatusCode::OK);
    let path = body_json(path).await;
    assert_eq!(path["schema"], "caduceus.household-config.path.v1");
    assert_eq!(path["profile"], "tv");
    assert_eq!(path["path"], "/etc/tv/config.json");
    assert!(!path["path"].as_str().unwrap().contains("tests/fixtures"));

    let show = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/config/show")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(show.status(), StatusCode::OK);
    let show = body_json(show).await;
    assert_eq!(show["schema"], "caduceus.household-config.show.v1");
    assert_eq!(show["document"]["schema"], "household.config.v1");
    assert_eq!(show["path"], "/etc/tv/config.json");

    let get = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/config/get?path=tabs.starred")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let get = body_json(get).await;
    assert_eq!(get["schema"], "caduceus.household-config.get.v1");
    assert_eq!(get["value"][0], "jellyfin");
    assert_eq!(get["value"][1], "photos");
}

#[tokio::test(flavor = "current_thread")]
async fn config_set_route_mutates_isolated_root_with_valid_capability() {
    let root = config_temp_root("set");
    let _guard = use_fixture(root.to_str().unwrap());
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/set")
                .header(
                    "x-caduceus-capability",
                    capability("config set", "display.theme", 60),
                )
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"display.theme","value":"light"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let receipt = body_json(response).await;
    assert_eq!(receipt["schema"], "caduceus.household-config.mutation.v1");
    assert_eq!(receipt["ok"], true);
    assert_eq!(receipt["op"], "set");
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["path"], "/etc/tv/config.json");
    assert_eq!(receipt["keysTouched"][0], "display.theme");

    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("etc/tv/config.json")).unwrap())
            .unwrap();
    assert_eq!(document["display"]["theme"], "light");
    assert_eq!(document["tabs"]["starred"][0], "jellyfin");

    let backups: Vec<_> = std::fs::read_dir(root.join("var/lib/caduceus/backups/household-config"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(backups.len(), 1);
    assert!(std::fs::read_to_string(&backups[0])
        .unwrap()
        .contains("\"dark\""));
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "current_thread")]
async fn config_patch_route_deep_merge_preserves_starred() {
    let root = config_temp_root("patch");
    let _guard = use_fixture(root.to_str().unwrap());
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/patch")
                .header(
                    "x-caduceus-capability",
                    capability("config patch", "household-config", 60),
                )
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"merge":{"tabs":{"order":["media","home"]},"display":{"sleepMinutes":15}}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let receipt = body_json(response).await;
    assert_eq!(receipt["schema"], "caduceus.household-config.mutation.v1");
    assert_eq!(receipt["op"], "patch");
    assert_eq!(receipt["changed"], true);

    let document: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("etc/tv/config.json")).unwrap())
            .unwrap();
    assert_eq!(document["tabs"]["starred"][0], "jellyfin");
    assert_eq!(document["tabs"]["starred"][1], "photos");
    assert_eq!(document["tabs"]["order"][0], "media");
    assert_eq!(document["display"]["sleepMinutes"], 15);
    assert_eq!(document["display"]["theme"], "dark");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "current_thread")]
async fn config_mutation_routes_refuse_without_capability() {
    let root = config_temp_root("refuse");
    let _guard = use_fixture(root.to_str().unwrap());
    let original = std::fs::read_to_string(root.join("etc/tv/config.json")).unwrap();
    let app = serve::router();

    let set = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/set")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"display.theme","value":"light"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(set.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(set).await["firstMissingSignal"],
        "caduceus-capability-unsigned"
    );

    let patch = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/patch")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"merge":{"display":{"theme":"light"}}}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(patch.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(patch).await["firstMissingSignal"],
        "caduceus-capability-unsigned"
    );

    assert_eq!(
        std::fs::read_to_string(root.join("etc/tv/config.json")).unwrap(),
        original
    );
    assert!(!root.join("var/lib/caduceus/backups").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "current_thread")]
async fn config_routes_refuse_path_injection_without_mutation() {
    let root = config_temp_root("inject");
    let _guard = use_fixture(root.to_str().unwrap());
    let original = std::fs::read_to_string(root.join("etc/tv/config.json")).unwrap();
    let app = serve::router();

    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/config/get?path=../../etc/passwd")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(get).await["firstMissingSignal"],
        "caduceus-household-config-path-invalid"
    );

    for hostile in ["../../etc/hostile", "/etc/hostile", "tabs..starred"] {
        let set = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/config/set")
                    .header(
                        "x-caduceus-capability",
                        capability("config set", hostile, 60),
                    )
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"path":"{hostile}","value":"x"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            set.status(),
            StatusCode::BAD_REQUEST,
            "{hostile} was not refused"
        );
        assert_eq!(
            body_json(set).await["firstMissingSignal"],
            "caduceus-household-config-path-invalid"
        );
    }

    assert_eq!(
        std::fs::read_to_string(root.join("etc/tv/config.json")).unwrap(),
        original
    );
    assert!(!root.join("var/lib/caduceus/backups").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "current_thread")]
async fn hyalos_http_reflect_tail_filters_and_no_projection_route() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let root = std::env::temp_dir().join(format!("caduceus-hyalos-http-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::copy(
        "tests/fixtures/homeserver/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    std::env::set_var("CADUCEUS_ROOT", &root);
    let app = serve::router();
    let reflected = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/hyalos/reflect")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"organ":"file-ingress","kind":"upload","level":"info","message":"http-proof","payload":{"password":"hidden"}}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reflected.status(), StatusCode::OK);
    let reflected = body_json(reflected).await;
    assert_eq!(reflected["event"]["schema"], "hyalos.channel.event.v2");
    assert_eq!(reflected["event"]["level"], "info");
    assert!(reflected["event"]["timestamp"]
        .as_str()
        .unwrap_or("")
        .contains('T'));
    assert_eq!(
        reflected["event"]["attributes_redacted"]["password"],
        "[REDACTED]"
    );

    let other = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/hyalos/reflect")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"organ":"caduceus","kind":"receipt","message":"other"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(other.status(), StatusCode::OK);

    let tail = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/hyalos/tail?count=5&kind=upload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(tail.status(), StatusCode::OK);
    let tail_json = body_json(tail).await;
    assert_eq!(tail_json["count"], 1);
    assert_eq!(tail_json["filters"]["kind"], "upload");
    assert_eq!(tail_json["events"][0]["kind"], "upload");

    let projection = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/hyalos/project/upload")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(projection.status(), StatusCode::NOT_FOUND);
    std::env::remove_var("CADUCEUS_ROOT");
    let _ = std::fs::remove_dir_all(root);
}
