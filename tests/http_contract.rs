use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use caduceus::{routes::serve, shared::attendance};
use std::{
    env,
    ffi::OsString,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Mutex, MutexGuard},
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

static FIXTURE_LOCK: Mutex<()> = Mutex::new(());

fn use_fixture(root: &str) -> std::sync::MutexGuard<'static, ()> {
    let guard = FIXTURE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    std::env::set_var("CADUCEUS_ROOT", root);
    guard
}

struct DnsCommandFixture {
    root: PathBuf,
    prior_command: Option<std::ffi::OsString>,
}

impl DnsCommandFixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!(
            "caduceus-dns-http-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let args_log = root.join("launcher-args");
        let stdin_log = root.join("launcher-stdin");
        let launcher = root.join("fixture-launcher");
        fs::write(
            &launcher,
            format!(
                "#!/bin/sh\nprintf '%s' \"$*\" > {}\ncat > {}\nprintf '{{\"schema\":\"caduceus.network.dns.intent.v1\",\"ok\":true,\"mutationPerformed\":false,\"receipt\":\"fixture-actuator-receipt\"}}\\n'\n",
                args_log.display(),
                stdin_log.display()
            ),
        )
        .unwrap();
        let mut permissions = fs::metadata(&launcher).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&launcher, permissions).unwrap();
        let prior_command = env::var_os("CADUCEUS_DNS_CMD");
        env::set_var("CADUCEUS_DNS_CMD", &launcher);
        Self {
            root,
            prior_command,
        }
    }

    fn launcher_args(&self) -> String {
        fs::read_to_string(self.root.join("launcher-args")).unwrap()
    }

    fn launcher_stdin(&self) -> String {
        fs::read_to_string(self.root.join("launcher-stdin")).unwrap()
    }
}

impl Drop for DnsCommandFixture {
    fn drop(&mut self) {
        match &self.prior_command {
            Some(command) => env::set_var("CADUCEUS_DNS_CMD", command),
            None => env::remove_var("CADUCEUS_DNS_CMD"),
        }
        let _ = fs::remove_dir_all(&self.root);
    }
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
    let _guard = use_fixture("tests/fixtures/homeconsole");
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
    let _guard = use_fixture("tests/fixtures/homeconsole");
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
    assert!(json["entries"].as_array().is_some_and(|entries| {
        entries.iter().all(|entry| {
            entry["id"].is_string()
                && entry["execution"].as_str() == Some("not-executed-by-caduceus")
        })
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn console_legacy_sbin_show_returns_whole_body() {
    let _guard = use_fixture("tests/fixtures/homeconsole");
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
    assert_eq!(json["entry"]["legacyIntent"], "discovery-projection");
    assert!(json["entry"].get("body").is_none());
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
    let _guard = use_fixture("tests/fixtures/homeconsole");
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
    let _fixture = HarmoniaFailureFixture::new("sync");
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
    let _fixture = HarmoniaFailureFixture::new("gui-update");
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
    assert_eq!(json["action"], "gui_update_now");
}

#[tokio::test(flavor = "current_thread")]
async fn console_local_ai_runtime_status_reads_route() {
    let _guard = use_fixture("tests/fixtures/homeconsole");
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
    let _guard = use_fixture("tests/fixtures/homeconsole");
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
async fn network_dns_mutation_invokes_staff_launcher_when_profile_allowed() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let fixture = DnsCommandFixture::new();
    let payload = r#"{"dropIn":"server: local-zone: \"home.arpa.\" transparent","dryRun":true}"#;
    let response = serve::router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/network/dns")
                .header("content-type", "application/json")
                .body(Body::from(payload))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let receipt = body_json(response).await;
    assert_eq!(receipt["schema"], "caduceus.network.dns.public_receipt.v1");
    assert!(receipt.get("receipt").is_none());
    assert!(receipt.get("dropIn").is_none());
    assert!(!receipt.to_string().contains("home.arpa."));

    assert_eq!(
        fixture.launcher_args(),
        "intent POST /api/dns/unbound/drop-in --metadata-json {\"dropIn\":\"server: local-zone: \\\"home.arpa.\\\" transparent\",\"dryRun\":true}"
    );
    assert_eq!(fixture.launcher_stdin(), "");
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
    assert!(json["entries"].as_array().is_some_and(|entries| {
        entries.iter().all(|entry| {
            entry["id"].is_string()
                && entry["sourcePath"].is_string()
                && entry["execution"].as_str() == Some("not-executed-by-caduceus")
        })
    }));
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
    assert_eq!(json["entry"]["legacyIntent"], "discovery-projection");
    assert!(json["entry"].get("replacementBand").is_none());
    assert_eq!(json["entry"]["legacyIntent"], "discovery-projection");
    assert!(json["entry"].get("body").is_none());
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
async fn homeserver_retired_admin_action_route_is_not_found() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    let app = serve::router();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/admin/action")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

struct PortalServiceFixture {
    root: PathBuf,
    previous_env: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl PortalServiceFixture {
    fn new() -> Self {
        let lock = FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = env::temp_dir().join(format!(
            "caduceus-http-service-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let caduceus = root.join("etc/caduceus");
        let appliance = root.join("etc/appliance");
        fs::create_dir_all(&caduceus).unwrap();
        fs::create_dir_all(&appliance).unwrap();
        fs::copy(
            "profiles/homeserver/index.yaml",
            caduceus.join("profile.yaml"),
        )
        .unwrap();
        fs::copy(
            "tests/fixtures/homeserver/etc/appliance/config.json",
            appliance.join("config.json"),
        )
        .unwrap();
        fs::write(
            appliance.join("profile.json"),
            r#"{"profile":"homeserver"}"#,
        )
        .unwrap();

        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        let sudo = bin.join("sudo");
        fs::write(
            &sudo,
            "#!/bin/sh\ncase \"$1/$2\" in\nexousia/bind) printf '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}\\n' ;;\nexousia/verify) payload=$(cat); case \"$payload\" in *'\"pin\":\"2468\"'*'\"publicKey\":\"fixture-public\"'*) printf '{\"ok\":true,\"verified\":true}\\n' ;; *) printf '{\"ok\":false,\"verified\":false}\\n' ;; esac ;;\n*) exit 8 ;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(&sudo, fs::Permissions::from_mode(0o755)).unwrap();
        let state = root.join("state");
        fs::write(&state, "active\n").unwrap();
        let calls = root.join("calls");
        fs::write(&calls, "").unwrap();
        let systemctl = root.join("systemctl");
        fs::write(
            &systemctl,
            format!(
                "#!/bin/sh\nprintf '%s %s\\n' \"$1\" \"$2\" >> {}\nif [ \"$1\" = is-active ]; then\n  if [ \"$(cat {})\" = active ]; then printf 'active\\n'; exit 0; fi\n  printf 'inactive\\n'; exit 3\nfi\ncase \"$1\" in\n  start|restart|enable) printf 'active\\n' > {} ;;\n  stop|disable) printf 'inactive\\n' > {} ;;\n  status) : ;;\n  *) exit 9 ;;\nesac\nexit 0\n",
                calls.display(),
                state.display(),
                state.display(),
                state.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&systemctl, fs::Permissions::from_mode(0o755)).unwrap();

        let names = [
            "CADUCEUS_ROOT",
            "CADUCEUS_SYSTEMCTL_BIN",
            "CADUCEUS_AGATHODAIMON_CLI",
            "CADUCEUS_DOCUMENT_INCARNATION",
            "PATH",
        ];
        let previous_env = names
            .iter()
            .map(|name| (*name, env::var_os(name)))
            .collect();
        let old_path = env::var_os("PATH").unwrap_or_default();
        env::set_var("CADUCEUS_ROOT", &root);
        env::set_var("CADUCEUS_SYSTEMCTL_BIN", &systemctl);
        env::set_var("CADUCEUS_AGATHODAIMON_CLI", &sudo);
        env::set_var("CADUCEUS_DOCUMENT_INCARNATION", "inc-1");
        env::set_var("PATH", format!("{}:{}", bin.display(), old_path.to_string_lossy()));
        attendance::reset_for_tests();
        attendance::bind();
        Self {
            root,
            previous_env,
            _lock: lock,
        }
    }

    fn systemctl_calls(&self) -> String {
        fs::read_to_string(self.root.join("calls")).unwrap()
    }
}

impl Drop for PortalServiceFixture {
    fn drop(&mut self) {
        attendance::reset_for_tests();
        for (name, value) in self.previous_env.drain(..) {
            match value {
                Some(value) => env::set_var(name, value),
                None => env::remove_var(name),
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn service_request(uri: &str, attendance: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(attendance) = attendance {
        builder = builder.header("x-caduceus-attendance", attendance);
    }
    builder.body(Body::from(r#"{}"#)).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn registered_service_actions_require_static_attendance_and_read_systemctl_state() {
    let fixture = PortalServiceFixture::new();
    let actions = [
        ("status", true),
        ("start", true),
        ("stop", false),
        ("enable", true),
        ("disable", false),
        ("restart", true),
    ];

    for (action, _) in actions.iter().copied() {
        for prefix in ["/api/v1/appliance/service/", "/api/v1/service/"] {
            let uri = format!("{prefix}jellyfin/{action}");
            let response = serve::router()
                .oneshot(service_request(&uri, None))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                body_json(response).await["firstMissingSignal"],
                "caduceus-attendance-not-current"
            );
        }
    }
    assert!(fixture.systemctl_calls().is_empty());

    for (index, (action, expected_active)) in actions.iter().copied().enumerate() {
        let static_target = format!("/api/v1/appliance/service/{{service}}/{action}");
        let static_attendance = attendance::open_json(&serde_json::json!({
            "documentId": static_target,
            "documentIncarnation": "inc-1",
            "pin": "2468"
        }))
        .unwrap()["attendance"]
            .as_str()
            .unwrap()
            .to_owned();
        let concrete_attendance = attendance::open_json(&serde_json::json!({
            "documentId": format!("/api/v1/appliance/service/jellyfin/{action}"),
            "documentIncarnation": "inc-1",
            "pin": "2468"
        }))
        .unwrap()["attendance"]
            .as_str()
            .unwrap()
            .to_owned();
        let wrong_action = if action == "status" { "start" } else { "status" };
        let wrong_attendance = attendance::open_json(&serde_json::json!({
            "documentId": format!("/api/v1/appliance/service/{{service}}/{wrong_action}"),
            "documentIncarnation": "inc-1",
            "pin": "2468"
        }))
        .unwrap()["attendance"]
            .as_str()
            .unwrap()
            .to_owned();
        for token in [&concrete_attendance, &wrong_attendance] {
            let uri = format!("/api/v1/appliance/service/jellyfin/{action}");
            let response = serve::router()
                .oneshot(service_request(&uri, Some(token)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert_eq!(
                body_json(response).await["firstMissingSignal"],
                "caduceus-attendance-not-current"
            );
        }
        let prefix = if index % 2 == 0 {
            "/api/v1/appliance/service/"
        } else {
            "/api/v1/service/"
        };
        let uri = format!("{prefix}jellyfin/{action}");
        let response = serve::router()
            .oneshot(service_request(&uri, Some(&static_attendance)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt = body_json(response).await;
        assert_eq!(receipt["action"], action);
        assert_eq!(receipt["service"], "jellyfin");
        assert_eq!(receipt["systemdService"], "jellyfin.service");
        assert_eq!(receipt["success"], true);
        assert_eq!(receipt["active"], expected_active);
    }

    let schema = serve::router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/schema/caduceus.doors.readback.v1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(schema.status(), StatusCode::OK);
    let schema = body_json(schema).await;
    assert_eq!(
        schema["required"],
        serde_json::json!(["schema", "ok", "profile", "routes"])
    );
    assert!(schema.get("seat").is_none());
    assert_eq!(schema["fields"]["schema"]["const"], "caduceus.doors.readback.v1");
    assert_eq!(schema["fields"]["ok"]["type"], "boolean");
    assert_eq!(schema["fields"]["profile"]["type"], "string");
    assert_eq!(schema["fields"]["routes"]["type"], "array");
    assert_eq!(schema["fields"]["routes"]["items"]["type"], "string");

    let doors = serve::router()
        .oneshot(
            Request::builder()
                .uri("/api/v1/doors")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(doors.status(), StatusCode::OK);
    let doors = body_json(doors).await;
    assert_eq!(doors["schema"], "caduceus.doors.readback.v1");
    assert!(doors["ok"].is_boolean());
    assert!(doors["profile"].is_string());
    assert!(doors["routes"]
        .as_array()
        .is_some_and(|routes| routes.iter().all(serde_json::Value::is_string)));
    assert!(doors.get("seat").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn homeserver_named_file_ingress_route_executes_upload_bytes() {
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
                .uri("/api/v1/file/ingress")

                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"filename":"proof.txt","bytes":5,"destination":"/mnt/nas","payload":[104,101,108,108,111]}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["schema"], "caduceus.staff.file_ingress.v1");
    assert_eq!(json["mutationPerformed"], true);
    assert_eq!(json["execution"], "native-rust-file-ingress");
    assert_eq!(json["hyalos"]["event"]["kind"], "upload");
    assert_eq!(std::fs::read(root.join("proof.txt")).unwrap(), b"hello");
    assert!(
        std::fs::read_to_string(root.join("var/log/appliance/appliance.log"))
            .unwrap()
            .contains("proof.txt")
    );
    std::env::remove_var("CADUCEUS_FILE_INGRESS_ROOT");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "current_thread")]
async fn homeserver_dhcp_http_status_and_named_actuator_execute_python_actuator() {
    let _guard = use_fixture("tests/fixtures/homeserver");
    std::env::set_var("PYTHONPATH", "tests/fixtures/staff");
    let shim = env::temp_dir().join(format!("caduceus-http-dhcp-shim-{}", std::process::id()));
    fs::write(&shim, "#!/bin/sh\n[ \"$1\" = network ] && [ \"$2\" = dhcp ] || exit 9\ncase \"$2\" in\n  dhcp) printf '{\"ok\":true,\"schema\":\"caduceus.network.dhcp.intent.v1\",\"execution\":\"agathodaimon.network.dhcp\",\"classification\":\"network-control\",\"mutationPerformed\":true}' ;;\nesac\n").unwrap();
    fs::set_permissions(&shim, fs::Permissions::from_mode(0o755)).unwrap();
    std::env::set_var("CADUCEUS_AGATHODAIMON_CLI", &shim);
    std::env::set_var(
        "CADUCEUS_NETWORK_READ_CMD",
        "python3 -m agathodaimon.network.dhcp",
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
        body_json(response).await["payload"]["schema"],
        "caduceus.network.dhcp.status.v1"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/network/dhcp")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"ip":"192.168.1.7"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let json = body_json(response).await;
    assert_eq!(json["classification"], "network-control");
    assert_eq!(json["mutationPerformed"], true);
    assert_eq!(json["execution"], "agathodaimon.network.dhcp");
    std::env::remove_var("CADUCEUS_AGATHODAIMON_CLI");
    let _ = fs::remove_file(shim);
}

fn config_temp_root(tag: &str) -> std::path::PathBuf {
    let root =
        std::env::temp_dir().join(format!("caduceus-http-config-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::create_dir_all(root.join("etc/appliance")).unwrap();
    std::fs::copy(
        "tests/fixtures/tv/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    std::fs::copy(
        "tests/fixtures/tv/etc/appliance/config.json",
        root.join("etc/appliance/config.json"),
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
    assert_eq!(path["path"], "/etc/appliance/config.json");
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
    assert_eq!(show["path"], "/etc/appliance/config.json");

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
    assert_eq!(receipt["path"], "/etc/appliance/config.json");
    assert_eq!(receipt["keysTouched"][0], "display.theme");

    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
    )
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

    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(document["tabs"]["starred"][0], "jellyfin");
    assert_eq!(document["tabs"]["starred"][1], "photos");
    assert_eq!(document["tabs"]["order"][0], "media");
    assert_eq!(document["display"]["sleepMinutes"], 15);
    assert_eq!(document["display"]["theme"], "dark");
    let _ = std::fs::remove_dir_all(root);
}

#[tokio::test(flavor = "current_thread")]
async fn config_routes_refuse_path_injection_without_mutation() {
    let root = config_temp_root("inject");
    let _guard = use_fixture(root.to_str().unwrap());
    let original = std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap();
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
        std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
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

#[tokio::test(flavor = "current_thread")]
async fn profile_allowed_config_set_writes_installed_path() {
    let root = config_temp_root("guest");
    let _guard = use_fixture(root.to_str().unwrap());
    let app = serve::router();

    let starred = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/config/set")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"path":"tabs.starred","value":["photos"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(starred.status(), StatusCode::OK);
    let receipt = body_json(starred).await;
    assert_eq!(receipt["path"], "/etc/appliance/config.json");
    assert_eq!(receipt["changed"], true);
    let installed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(installed["tabs"]["starred"], serde_json::json!(["photos"]));

    let guest_other = app
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
    assert_eq!(guest_other.status(), StatusCode::OK);
    let installed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(installed["display"]["theme"], "light");
    let _ = std::fs::remove_dir_all(root);
}

struct CertTempRoot(PathBuf);

impl CertTempRoot {
    fn path(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for CertTempRoot {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path()
    }
}

impl Drop for CertTempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct HarmoniaFailureFixture {
    _root: CertTempRoot,
    previous_root: Option<OsString>,
    previous_path: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl HarmoniaFailureFixture {
    fn new(tag: &str) -> Self {
        let lock = FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = cert_temp_root(tag, "homeconsole");
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let sudo = bin_dir.join("sudo");
        fs::write(&sudo, "#!/bin/sh\nexit 1\n").unwrap();
        let mut permissions = fs::metadata(&sudo).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&sudo, permissions).unwrap();
        let previous_root = env::var_os("CADUCEUS_ROOT");
        let previous_path = env::var_os("PATH");
        let mut paths = vec![bin_dir];
        if let Some(path) = previous_path.as_deref() {
            paths.extend(env::split_paths(path));
        }
        env::set_var("CADUCEUS_ROOT", root.as_os_str());
        env::set_var("PATH", env::join_paths(paths).unwrap());
        Self {
            _root: root,
            previous_root,
            previous_path,
            _lock: lock,
        }
    }
}

impl Drop for HarmoniaFailureFixture {
    fn drop(&mut self) {
        match self.previous_root.take() {
            Some(value) => env::set_var("CADUCEUS_ROOT", value),
            None => env::remove_var("CADUCEUS_ROOT"),
        }
        match self.previous_path.take() {
            Some(value) => env::set_var("PATH", value),
            None => env::remove_var("PATH"),
        }
    }
}

fn cert_temp_root(tag: &str, profile: &str) -> CertTempRoot {
    let root = env::temp_dir().join(format!(
        "caduceus-cert-http-{tag}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let root = CertTempRoot(root);
    fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    for name in ["profile.yaml"] {
        fs::copy(
            format!("tests/fixtures/{profile}/etc/caduceus/{name}"),
            root.join("etc/caduceus").join(name),
        )
        .unwrap();
    }
    root
}

fn run_house_ca(root: &Path, args: &[&str]) -> serde_json::Value {
    let output = Command::new("python3")
        .args([
            "tests/fixtures/staff/agathodaimon/cli.py",
            "cert",
            "house-ca",
        ])
        .args(args)
        .env("PYTHONPATH", "tests/fixtures/staff")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("CADUCEUS_ROOT", root)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "house_ca {:?} failed: {} {}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn file_snapshot(root: &Path) -> Vec<(String, u64, SystemTime)> {
    fn visit(root: &Path, path: &Path, output: &mut Vec<(String, u64, SystemTime)>) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    visit(root, &path, output);
                } else {
                    let metadata = entry.metadata().unwrap();
                    output.push((
                        path.strip_prefix(root).unwrap().display().to_string(),
                        metadata.len(),
                        metadata.modified().unwrap(),
                    ));
                }
            }
        }
    }
    let mut output = Vec::new();
    visit(root, root, &mut output);
    output.sort_by(|a, b| a.0.cmp(&b.0));
    output
}

struct CertFixture {
    root: CertTempRoot,
    previous_env: Vec<(&'static str, Option<OsString>)>,
    _lock: MutexGuard<'static, ()>,
}

impl CertFixture {
    fn new(tag: &str, profile: &str) -> Self {
        let lock = FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = cert_temp_root(tag, profile);
        // The Rust membrane executes this override directly. Keep the source
        // fixture immutable and provide an isolated executable shim instead
        // of leaking a non-executable Python path into the process.
        let cli = root.join("agathodaimon-cli");
        fs::write(
            &cli,
            "#!/bin/sh\nexec python3 tests/fixtures/staff/agathodaimon/cli.py \"$@\"\n",
        )
        .unwrap();
        let mut permissions = fs::metadata(&cli).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&cli, permissions).unwrap();
        let values = [
            ("CADUCEUS_ROOT", root.as_os_str()),
            ("PYTHONPATH", std::ffi::OsStr::new("tests/fixtures/staff")),
            ("PYTHONDONTWRITEBYTECODE", std::ffi::OsStr::new("1")),
            ("CADUCEUS_AGATHODAIMON_CLI", cli.as_os_str()),
        ];
        let previous_env = values
            .iter()
            .map(|(name, _)| (*name, env::var_os(name)))
            .collect();
        for (name, value) in values {
            env::set_var(name, value);
        }
        Self {
            root,
            previous_env,
            _lock: lock,
        }
    }

    fn root(&self) -> &Path {
        self.root.path()
    }
}

impl Drop for CertFixture {
    fn drop(&mut self) {
        for (name, value) in self.previous_env.drain(..) {
            match value {
                Some(value) => env::set_var(name, value),
                None => env::remove_var(name),
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn cert_bundle_download_is_public_deterministic_and_read_only() {
    let fixture = CertFixture::new("download", "homeserver");
    let root = fixture.root();
    let app = serve::router();

    let before_absent = file_snapshot(&root);
    let absent = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/cert/bundle/download?platform=linux")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(absent.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body_json(absent).await["firstMissingSignal"],
        "caduceus-house-ca-refused"
    );
    assert_eq!(before_absent, file_snapshot(&root));
    assert!(!root.join("var/lib/caduceus/certs").exists());

    for platform in ["windows", "android", "chromeos", "linux", "macos"] {
        run_house_ca(&root, &["bundle-export", platform]);
    }
    let status = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/cert/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(
        body_json(status).await["schema"],
        "caduceus.staff.house_ca.status.v1"
    );
    let before_downloads = file_snapshot(&root);
    for platform in ["windows", "android", "chromeos", "linux", "macos"] {
        let uri = format!("/api/v1/cert/bundle/download?platform={platform}");
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{platform}");
        assert_eq!(
            response.headers()["content-type"],
            "application/x-x509-ca-cert"
        );
        let suffix = if platform == "windows" {
            ".cer"
        } else {
            ".crt"
        };
        let filename = format!("homeserver-house-ca-{platform}{suffix}");
        assert_eq!(
            response.headers()["content-disposition"],
            format!("attachment; filename=\"{filename}\"")
        );
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(
            bytes.as_ref(),
            fs::read(root.join("var/lib/caduceus/certs/bundles").join(filename))
                .unwrap()
                .as_slice()
        );
        assert!(!bytes
            .windows(b"PRIVATE KEY".len())
            .any(|window| window == b"PRIVATE KEY"));
    }
    let default_linux = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/cert/bundle/download")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(default_linux.status(), StatusCode::OK);
    assert_eq!(
        default_linux.headers()["content-disposition"],
        "attachment; filename=\"homeserver-house-ca-linux.crt\""
    );

    let hostile = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/cert/bundle/download?platform=..%2F..%2Fetc%2Fpasswd")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(hostile.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(hostile).await["firstMissingSignal"],
        "caduceus-cert-platform-invalid"
    );
    assert_eq!(before_downloads, file_snapshot(&root));
}

#[tokio::test(flavor = "current_thread")]
async fn csr_sign_route_has_profile_and_body_walls() {
    let fixture = CertFixture::new("csr-walls", "homeserver");
    run_house_ca(fixture.root(), &["ensure-root"]);
    let app = serve::router();
    let body = r#"{"csrPem":"not a csr"}"#;
    let refused = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/cert/csr/sign")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(refused).await["firstMissingSignal"],
        "caduceus-attendance-not-current"
    );
    let malformed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/cert/csr/sign")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        body_json(malformed).await["firstMissingSignal"],
        "caduceus-attendance-not-current"
    );
    let caller_policy = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/cert/csr/sign")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"csrPem":"not a csr","ips":["192.0.2.10"]}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(caller_policy.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let oversized = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/cert/csr/sign")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    "{{\"csrPem\":\"{}\"}}",
                    "x".repeat(70_000)
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(flavor = "current_thread")]
async fn appliance_logs_http_read_and_clear_expose_rotation_fields() {
    let root = env::temp_dir().join(format!("caduceus-log-http-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    fs::write(
        root.join("etc/caduceus/profile.yaml"),
        "schema: caduceus.profile.v1\nprofile: homeserver\ncommands:\n- logs read\n- logs clear\n",
    )
    .unwrap();
    let _guard = use_fixture(root.to_str().unwrap());
    let log = root.join("var/log/appliance/appliance.log");
    fs::create_dir_all(log.parent().unwrap()).unwrap();
    fs::write(&log, b"http-log-line\n").unwrap();
    let app = serve::router();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/log/read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await;
    assert_eq!(body["file_size"], 14);
    assert!(body["last_rotation_timestamp"].is_null());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/log/clear")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await["file_size"], 0);
    let _ = fs::remove_dir_all(&root);
}

struct UpdateModuleFixture {
    root: PathBuf,
    previous_root: Option<OsString>,
    prior_path: Option<OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl UpdateModuleFixture {
    fn new() -> Self {
        let lock = FIXTURE_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = env::temp_dir().join(format!(
            "caduceus-update-module-http-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let bin_dir = root.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let args_log = root.join("sudo-args");
        let harmonia = root.join("fixture-harmonia");
        let sudo = bin_dir.join("sudo");
        let profile_dir = root.join("etc/caduceus");
        fs::create_dir_all(&profile_dir).unwrap();
        let profile = fs::read_to_string("tests/fixtures/homeconsole/etc/caduceus/profile.yaml")
            .unwrap()
            .replace("/usr/local/bin/harmonia", harmonia.to_str().unwrap());
        fs::write(profile_dir.join("profile.yaml"), profile).unwrap();
        fs::write(
            &harmonia,
            r##"#!/bin/sh
module=
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--module" ]; then shift; module="$1"; fi
  shift
done
if [ "$module" = "install-caduceus" ]; then
  printf '%s' '{"schema":"harmonia.update_module.v1","module_id":"install-caduceus","profile_id":"homeconsole","identity":"fixture","ok":false,"changed":false,"operation_count":0,"first_missing_signal":"module-is-pinned-syzygy-member-install-caduceus","unknown_sentinel":"refusal-preserved"}'
  exit 42
fi
printf '%s' '{"schema":"harmonia.update_module.v1","module_id":"'$module'","profile_id":"homeconsole","identity":"fixture","ok":true,"changed":true,"operation_count":1,"first_missing_signal":"none","unknown_sentinel":"success-preserved"}'
"##,
        )
        .unwrap();
        fs::write(
            &sudo,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" >> {}\n[ \"$1\" = \"-n\" ] || exit 97\nshift\n[ \"$1\" = \"{}\" ] || exit 98\nexec \"$@\"\n",
                args_log.display(),
                harmonia.display()
            ),
        )
        .unwrap();
        for path in [&harmonia, &sudo] {
            let mut permissions = fs::metadata(path).unwrap().permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(path, permissions).unwrap();
        }
        let previous_root = env::var_os("CADUCEUS_ROOT");
        let prior_path = env::var_os("PATH");
        let path = match &prior_path {
            Some(value) => format!("{}:{}", bin_dir.display(), value.to_string_lossy()),
            None => bin_dir.display().to_string(),
        };
        env::set_var("CADUCEUS_ROOT", &root);
        env::set_var("PATH", path);
        Self {
            root,
            previous_root,
            prior_path,
            _lock: lock,
        }
    }

    fn sudo_args(&self) -> String {
        fs::read_to_string(self.root.join("sudo-args")).unwrap()
    }

    fn harmonia_path(&self) -> PathBuf {
        self.root.join("fixture-harmonia")
    }
}

impl Drop for UpdateModuleFixture {
    fn drop(&mut self) {
        match &self.previous_root {
            Some(value) => env::set_var("CADUCEUS_ROOT", value),
            None => env::remove_var("CADUCEUS_ROOT"),
        }
        match &self.prior_path {
            Some(value) => env::set_var("PATH", value),
            None => env::remove_var("PATH"),
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn update_module_http_preserves_child_receipts_and_uses_transition_argv() {
    let fixture = UpdateModuleFixture::new();
    let app = serve::router();
    let success_stdout = r#"{"schema":"harmonia.update_module.v1","module_id":"household-time","profile_id":"homeconsole","identity":"fixture","ok":true,"changed":true,"operation_count":1,"first_missing_signal":"none","unknown_sentinel":"success-preserved"}"#;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/update/module")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"schema":"caduceus.staff.v1","intent_id":"http:update-module-success","transition":"update.module","version":"1","timestamp":"0","origin_of_intent":"near","target":{"module":"household-time"},"flags":{"apply":true},"unknown_envelope":"preserved"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let success = body_json(response).await;
    assert_eq!(success["ok"], true);
    assert_eq!(success["transition"], "update.module");
    assert_eq!(success["version"], "1");
    assert_eq!(success["timestamp"], "0");
    assert_eq!(success["unknown_envelope"], "preserved");
    assert_eq!(success["rawChildStdout"], success_stdout);
    assert_eq!(
        success["receiptPayload"]["unknown_sentinel"],
        "success-preserved"
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/update/module")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"schema":"caduceus.staff.v1","intent_id":"http:update-module-refusal","transition":"update.module","version":"1","timestamp":"0","origin_of_intent":"near","target":{"module":"install-caduceus"},"flags":{"apply":false},"unknown_envelope":"also-preserved"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let refusal = body_json(response).await;
    assert_eq!(refusal["ok"], false);
    assert_eq!(refusal["first_missing_signal"], "module-is-pinned-syzygy-member-install-caduceus");
    assert_eq!(
        refusal["harmoniaReceipt"]["firstMissingSignal"],
        "module-is-pinned-syzygy-member-install-caduceus"
    );
    assert_eq!(refusal["unknown_envelope"], "also-preserved");
    assert_eq!(
        refusal["receiptPayload"]["unknown_sentinel"],
        "refusal-preserved"
    );
    assert_eq!(
        refusal["rawChildStdout"],
        r#"{"schema":"harmonia.update_module.v1","module_id":"install-caduceus","profile_id":"homeconsole","identity":"fixture","ok":false,"changed":false,"operation_count":0,"first_missing_signal":"module-is-pinned-syzygy-member-install-caduceus","unknown_sentinel":"refusal-preserved"}"#
    );

    let args = fixture.sudo_args();
    let command_prefix = format!(
        "-n {} update-module /etc/harmonia/profiles/homeconsole/index.json --module",
        fixture.harmonia_path().display()
    );
    assert!(args.contains(&format!("{command_prefix} household-time --apply")));
    assert!(args.contains(&format!("{command_prefix} install-caduceus")));
    assert!(!args.contains(&format!("{command_prefix} install-caduceus --apply")));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/schema/harmonia.update_module.v1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        body_json(response).await["schema"],
        "harmonia.update_module.v1"
    );
}
