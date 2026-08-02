use axum::body::Body;
use axum::http::{Request, StatusCode};
use caduceus::bands::{firewall, serve};
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

static LOCK: Mutex<()> = Mutex::new(());
const MAC: &str = "aa:bb:cc:dd:ee:01";
const REVISION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Fixture {
    root: PathBuf,
    old_root: Option<std::ffi::OsString>,
    old_launcher: Option<std::ffi::OsString>,
}
impl Fixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!(
            "caduceus-firewall-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let launcher = root.join("launcher");
        fs::write(&launcher, format!("#!/bin/sh\ncat > {}/stdin\nprintf '%s' \"${{CADUCEUS_FIREWALL_RESPONSE:-{{\\\"ok\\\":true}}}}\"\n", root.display())).unwrap();
        let mut mode = fs::metadata(&launcher).unwrap().permissions();
        mode.set_mode(0o755);
        fs::set_permissions(&launcher, mode).unwrap();
        let old_root = env::var_os("CADUCEUS_ROOT");
        let old_launcher = env::var_os("CADUCEUS_FIREWALL_LAUNCHER");
        env::set_var("CADUCEUS_ROOT", "tests/fixtures/homeserver");
        env::set_var("CADUCEUS_FIREWALL_LAUNCHER", &launcher);
        Self {
            root,
            old_root,
            old_launcher,
        }
    }
    fn calls(&self) -> usize {
        fs::read_to_string(self.root.join("stdin"))
            .map(|_| 1)
            .unwrap_or(0)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        match &self.old_root {
            Some(v) => env::set_var("CADUCEUS_ROOT", v),
            None => env::remove_var("CADUCEUS_ROOT"),
        };
        match &self.old_launcher {
            Some(v) => env::set_var("CADUCEUS_FIREWALL_LAUNCHER", v),
            None => env::remove_var("CADUCEUS_FIREWALL_LAUNCHER"),
        };
        env::remove_var("CADUCEUS_FIREWALL_RESPONSE");
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn body(enabled: bool) -> String {
    serde_json::json!({"schema":"policy.v1","mac":MAC,"mode":"allow-only","sites":["example.com"],"expectedRevision":REVISION,"enabled":enabled,"enforcement":"dns-policy"}).to_string()
}
fn capability() -> String {
    // fixture verifier accepts only signed capabilities; malformed credentials must refuse before staff.
    "not-a-capability".into()
}

#[tokio::test(flavor = "current_thread")]
async fn firewall_routes_are_exactly_gated_and_globally_bounded() {
    let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let fixture = Fixture::new();
    let app = serve::router();
    let guest = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/network/firewall/policies/{MAC}"))
                .header("content-type", "application/json")
                .body(Body::from(body(true)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(guest.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.calls(), 0);
    let bad = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/network/firewall/policies/{MAC}"))
                .header("content-type", "application/json")
                .header("x-caduceus-capability", capability())
                .body(Body::from(body(true)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(bad.status(), StatusCode::FORBIDDEN);
    assert_eq!(fixture.calls(), 0);
    let oversized = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/v1/network/firewall/policies/{MAC}"))
                .header("content-type", "application/json")
                .body(Body::from("x".repeat(8193)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(fixture.calls(), 0);
    let status = app
        .oneshot(
            Request::builder()
                .uri("/api/v1/network/firewall/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(fixture.calls(), 1);
}

#[test]
fn firewall_launcher_refuses_oversize_and_keeps_staff_failures_structured() {
    let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let fixture = Fixture::new();
    let huge = fixture.root.join("huge");
    fs::write(&huge, "#!/bin/sh\nhead -c 65537 /dev/zero\n").unwrap();
    let mut mode = fs::metadata(&huge).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(&huge, mode).unwrap();
    env::set_var("CADUCEUS_FIREWALL_LAUNCHER", &huge);
    assert_eq!(
        firewall::command_json(serde_json::json!({"action":"status"})).unwrap_err()
            ["firstMissingSignal"],
        "firewall-staff-output-too-large"
    );
    let refused = fixture.root.join("refused");
    fs::write(
        &refused,
        "#!/bin/sh\nprintf '{\"error\":\"firewall-revision-conflict\"}'\nexit 1\n",
    )
    .unwrap();
    let mut mode = fs::metadata(&refused).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(&refused, mode).unwrap();
    env::set_var("CADUCEUS_FIREWALL_LAUNCHER", &refused);
    let error =
        firewall::command_json(serde_json::json!({"action":"put","site":"a; b"})).unwrap_err();
    assert_eq!(error["ok"], false);
    assert_eq!(error["firstMissingSignal"], "firewall-revision-conflict");
}

#[test]
fn firewall_contract_literals_and_delivery_are_present() {
    let serve = include_str!("../src/bands/serve.rs");
    let profile = include_str!("../data/staff-actuators/profile.json");
    for route in [
        "/api/v1/network/firewall/status",
        "/api/v1/network/firewall/policies",
        "/api/v1/network/firewall/policies/:mac",
    ] {
        assert!(serve.contains(route));
    }
    for literal in [
        "policy.v1",
        "policy.delete.v1",
        "allow-only",
        "dns-policy",
        "DefaultBodyLimit::max(8192)",
    ] {
        assert!(serve.contains(literal));
    }
    assert!(profile.contains("network-firewall"));
    assert!(profile.contains("caduceus_staff.network.firewall"));
}
