use axum::body::Body;
use axum::http::{Request, StatusCode};
use caduceus::routes::serve;
use caduceus::shared::{attendance, policy};
use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn root() -> std::path::PathBuf {
    env::temp_dir().join(format!(
        "caduceus-dns-attendance-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn request(document: Option<&str>, attendance: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/network/dns")
        .header("content-type", "application/json");
    if let Some(document) = document {
        builder = builder.header("x-caduceus-document", document);
    }
    if let Some(attendance) = attendance {
        builder = builder.header("x-caduceus-attendance", attendance);
    }
    builder.body(Body::from(r#"{"action":"status"}"#)).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn dns_http_uses_exact_document_attendance_when_document_is_supplied() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = root();
    let stdin_log = root.join("launcher-stdin");
    let launcher = root.join("dns-launcher");
    fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    fs::write(
        root.join("etc/caduceus/profile.yaml"),
        "profile: homeserver\ncommands:\n- network dns status\n- network dns intent\n",
    )
    .unwrap();
    fs::write(
        &launcher,
        format!(
            "#!/bin/sh\ncase \"$1/$2\" in\nexousia/bind) cat >/dev/null; printf '%s\\n' '{{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}}' ;;\nexousia/verify) cat >/dev/null; printf '%s\\n' '{{\"ok\":true,\"verified\":true}}' ;;\nnetwork/dns) cat > {}; printf '%s\\n' '{{\"schema\":\"caduceus.network.dns.receipt.v2\",\"ok\":true,\"receipt\":\"fixture-actuator-receipt\"}}' ;;\n*) exit 8 ;;\nesac\n",
            stdin_log.display(),
        ),
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();

    let old_root = env::var_os("CADUCEUS_ROOT");
    let old_launcher = env::var_os("CADUCEUS_AGATHODAIMON_CLI");
    env::set_var("CADUCEUS_ROOT", &root);
    env::set_var("CADUCEUS_AGATHODAIMON_CLI", &launcher);
    attendance::reset_for_tests();
    attendance::bind();
    let current = attendance::open_json(&serde_json::json!({
        "documentId": "dns-document",
        "documentIncarnation": "inc-1",
        "pin": "2468"
    }))
    .unwrap()["attendance"]
        .as_str()
        .unwrap()
        .to_string();

    assert!(!policy::allows_command("network dns").unwrap());
    assert!(policy::allows_command("network dns status").unwrap());
    assert!(policy::allows_command("network dns intent").unwrap());
    for (document, token) in [
        (Some("wrong-document"), Some(current.as_str())),
        (Some("dns-document"), None),
    ] {
        let response = serve::router()
            .oneshot(request(document, token))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!stdin_log.exists());
    }
    let response = serve::router()
        .oneshot(request(Some("dns-document"), Some(&current)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&stdin_log).unwrap())
            .unwrap()["schema"],
        "caduceus.staff.v1"
    );
    let envelope: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&stdin_log).unwrap()).unwrap();
    assert_eq!(envelope["transition"], "network/dns");
    assert_eq!(
        envelope["payload"]["args"],
        serde_json::json!([
            "intent",
            "POST",
            "/api/dns/unbound/drop-in",
            "--metadata-json",
            "{\"action\":\"status\"}"
        ])
    );

    attendance::reset_for_tests();
    match old_root {
        Some(value) => env::set_var("CADUCEUS_ROOT", value),
        None => env::remove_var("CADUCEUS_ROOT"),
    }
    match old_launcher {
        Some(value) => env::set_var("CADUCEUS_AGATHODAIMON_CLI", value),
        None => env::remove_var("CADUCEUS_AGATHODAIMON_CLI"),
    }
    let _ = fs::remove_dir_all(root);
}
