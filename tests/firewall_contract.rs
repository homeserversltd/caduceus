use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use caduceus::routes::serve;
use caduceus::routes::whitelist_device as firewall;
use caduceus::shared::attendance;
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
        fs::write(&launcher, r#"#!/bin/sh
if [ "$1" = exousia ] && [ "$2" = bind ]; then cat >/dev/null; printf '%s' '{"ok":true,"publicKey":"fixture-public","epoch":"1"}'; exit 0; fi
if [ "$1" = exousia ] && [ "$2" = verify ]; then cat >/dev/null; printf '%s' '{"ok":true,"verified":true}'; exit 0; fi
if [ "$1" = network ] && [ "$2" = firewall ]; then cat > "$(dirname "$0")/stdin"; printf '%s' '{"ok":true}'; exit 0; fi
exit 9
"#).unwrap();
        let mut mode = fs::metadata(&launcher).unwrap().permissions();
        mode.set_mode(0o755);
        fs::set_permissions(&launcher, mode).unwrap();
        let old_root = env::var_os("CADUCEUS_ROOT");
        let old_launcher = env::var_os("CADUCEUS_AGATHODAIMON_CLI");
        env::set_var("CADUCEUS_ROOT", "tests/fixtures/homeserver");
        env::set_var("CADUCEUS_AGATHODAIMON_CLI", &launcher);
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
            Some(v) => env::set_var("CADUCEUS_AGATHODAIMON_CLI", v),
            None => env::remove_var("CADUCEUS_AGATHODAIMON_CLI"),
        };
        env::remove_var("CADUCEUS_FIREWALL_RESPONSE");
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn body(enabled: bool) -> String {
    serde_json::json!({"schema":"caduceus.network.firewall.policy.v1","mac":MAC,"mode":"allow-only","sites":["example.com"],"expectedRevision":REVISION,"enabled":enabled,"enforcement":"dns-policy"}).to_string()
}

async fn json(response: axum::response::Response) -> serde_json::Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
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

fn firewall_request(
    method: &str,
    request_body: String,
    document: &str,
    attendance: &str,
) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(format!("/api/v1/network/firewall/policies/{MAC}"))
        .header("content-type", "application/json")
        .header("x-caduceus-document", document)
        .header("x-caduceus-attendance", attendance)
        .body(Body::from(request_body))
        .unwrap()
}

fn assert_firewall_staff_envelope(raw: &str, payload: serde_json::Value) {
    let envelope: serde_json::Value = serde_json::from_str(raw).unwrap();
    assert_eq!(envelope["schema"], "caduceus.staff.v1");
    assert_eq!(envelope["intent_id"], "caduceus-network/firewall");
    assert_eq!(envelope["origin_of_intent"], "near");
    assert_eq!(envelope["transition"], "network/firewall");
    assert_eq!(envelope["payload"], payload);
}

#[tokio::test(flavor = "current_thread")]
async fn firewall_document_attendance_is_static_and_precedes_staff() {
    let _lock = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let fixture = Fixture::new();
    let bin = fixture.root.join("bin");
    let sudo = bin.join("sudo");
    fs::create_dir_all(&bin).unwrap();
    fs::write(
        &sudo,
        "#!/bin/sh\n[ \"$1\" = -n ] || exit 9\n[ \"$2\" = /usr/local/sbin/agathodaimon/cli.py ] || exit 9\ncase \"$3/$4\" in\nexousia/bind) cat >/dev/null; printf '%s\\n' '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}' ;;\nexousia/verify) cat >/dev/null; printf '%s\\n' '{\"ok\":true,\"verified\":true}' ;;\nexousia/change) printf '%s\\n' '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}' ;;\n*) exit 8 ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
    let old_path = env::var("PATH").unwrap();
    env::set_var("PATH", format!("{}:{old_path}", bin.display()));
    attendance::reset_for_tests();
    attendance::bind();
    let open = |document: &str| {
        attendance::open_json(&serde_json::json!({
            "documentId": document,
            "documentIncarnation": document,
            "pin": "2468"
        }))
        .unwrap()["attendance"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let current_parent = open("/api/v1/network/firewall/policies/{mac}");
    let refused = serve::router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/exousia/open")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "schema": "caduceus.staff.v1",
                        "intent_id": "firewall-attendance-child",
                        "transition": "exousia.open",
                        "target": {"document": "/api/v1/network/firewall/policies/{mac}"},
                        "flags": {"exousia": {
                            "attendance": current_parent.clone(),
                            "documentId": "/api/v1/network/firewall/policies/{mac}",
                            "documentIncarnation": "inc-1"
                        }},
                        "unknown_additive": {"retained": true}
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        json(refused).await["firstMissingSignal"],
        "caduceus-attendance-derivation-untrusted"
    );
    let current = current_parent.clone();
    let concrete = open(&format!("/api/v1/network/firewall/policies/{MAC}"));
    let wrong_static = open("/api/v1/network/firewall/policies/{device}");
    for token in [&concrete, &wrong_static] {
        let response = serve::router()
            .oneshot(firewall_request("PUT", body(true), token, token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(fixture.calls(), 0);
    }
    let put = serve::router()
        .oneshot(firewall_request(
            "PUT",
            body(true),
            "/api/v1/network/firewall/policies/{mac}",
            &current,
        ))
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::OK);
    assert_eq!(fixture.calls(), 1);
    assert_firewall_staff_envelope(
        &fs::read_to_string(fixture.root.join("stdin")).unwrap(),
        serde_json::json!({"action":"put","mac":MAC,"fqdns":["example.com"],"revision":REVISION}),
    );
    let disabled = serve::router()
        .oneshot(firewall_request(
            "PUT",
            body(false),
            "/api/v1/network/firewall/policies/{mac}",
            &current,
        ))
        .await
        .unwrap();
    assert_eq!(disabled.status(), StatusCode::OK);
    assert_firewall_staff_envelope(
        &fs::read_to_string(fixture.root.join("stdin")).unwrap(),
        serde_json::json!({"action":"delete","mac":MAC,"revision":REVISION}),
    );
    let delete = serde_json::json!({"schema":"caduceus.network.firewall.policy.delete.v1","mac":MAC,"expectedRevision":REVISION}).to_string();
    let deleted = serve::router()
        .oneshot(firewall_request(
            "DELETE",
            delete,
            "/api/v1/network/firewall/policies/{mac}",
            &current,
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    assert_firewall_staff_envelope(
        &fs::read_to_string(fixture.root.join("stdin")).unwrap(),
        serde_json::json!({"action":"delete","mac":MAC,"revision":REVISION}),
    );
    attendance::reset_for_tests();
    env::set_var("PATH", old_path);
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
    env::set_var("CADUCEUS_AGATHODAIMON_CLI", &huge);
    assert_eq!(
        firewall::command_json(serde_json::json!({"action":"status"})).unwrap_err()
            ["firstMissingSignal"],
        "firewall-staff-output-too-large"
    );
    let refused = fixture.root.join("refused");
    fs::write(
        &refused,
        "#!/bin/sh\nprintf '{\"ok\":false,\"error\":\"firewall-revision-conflict\"}'\nexit 1\n",
    )
    .unwrap();
    let mut mode = fs::metadata(&refused).unwrap().permissions();
    mode.set_mode(0o755);
    fs::set_permissions(&refused, mode).unwrap();
    env::set_var("CADUCEUS_AGATHODAIMON_CLI", &refused);
    let error =
        firewall::command_json(serde_json::json!({"action":"put","site":"a; b"})).unwrap_err();
    assert_eq!(error["ok"], false);
    assert_eq!(error["firstMissingSignal"], "firewall-revision-conflict");
}
