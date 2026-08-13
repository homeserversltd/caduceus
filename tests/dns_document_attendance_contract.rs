use axum::body::Body;
use axum::http::{Request, StatusCode};
use caduceus::shared::{attendance, policy};
use caduceus::trigger_gate_routes as serve;
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
    let bin = root.join("bin");
    let args_log = root.join("launcher-args");
    let stdin_log = root.join("launcher-stdin");
    let launcher = root.join("dns-launcher");
    fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(
        root.join("etc/caduceus/profile.yaml"),
        "profile: homeserver\ncommands:\n- network dns status\n- network dns intent\n",
    )
    .unwrap();
    let sudo = bin.join("sudo");
    fs::write(
        &sudo,
        "#!/bin/sh\n[ \"$1\" = -n ] || exit 9\ncase \"$3\" in\nattendance) case \"$4\" in bind) echo '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}' ;; verify) payload=$(cat); case \"$payload\" in *'\"pin\":\"2468\"'*'\"publicKey\":\"fixture-public\"'*) echo '{\"ok\":true,\"verified\":true}' ;; *) echo '{\"ok\":false,\"verified\":false}' ;; esac ;; esac ;;\nnetwork) echo '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}' ;;\n*) exit 8 ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(
        &launcher,
        format!(
            "#!/bin/sh\nprintf '%s' \"$*\" > {}\ncat > {}\nprintf '{{\"schema\":\"caduceus.network.dns.receipt.v2\",\"ok\":true,\"receipt\":\"fixture-actuator-receipt\"}}\\n'\n",
            args_log.display(),
            stdin_log.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&launcher, fs::Permissions::from_mode(0o700)).unwrap();

    let old_path = env::var("PATH").unwrap();
    let old_root = env::var_os("CADUCEUS_ROOT");
    let old_incarnation = env::var_os("CADUCEUS_DOCUMENT_INCARNATION");
    let old_launcher = env::var_os("CADUCEUS_DNS_CMD");
    env::set_var("PATH", format!("{}:{old_path}", bin.display()));
    env::set_var("CADUCEUS_ROOT", &root);
    env::remove_var("CADUCEUS_DOCUMENT_INCARNATION");
    env::set_var("CADUCEUS_DNS_CMD", &launcher);
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
        assert!(!args_log.exists());
        assert!(!stdin_log.exists());
    }
    let response = serve::router()
        .oneshot(request(Some("dns-document"), Some(&current)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        fs::read_to_string(&args_log).unwrap(),
        "intent POST /api/dns/unbound/drop-in --metadata-json {\"action\":\"status\"}"
    );
    assert_eq!(fs::read_to_string(&stdin_log).unwrap(), "");

    attendance::reset_for_tests();
    match old_root {
        Some(value) => env::set_var("CADUCEUS_ROOT", value),
        None => env::remove_var("CADUCEUS_ROOT"),
    }
    match old_incarnation {
        Some(value) => env::set_var("CADUCEUS_DOCUMENT_INCARNATION", value),
        None => env::remove_var("CADUCEUS_DOCUMENT_INCARNATION"),
    }
    match old_launcher {
        Some(value) => env::set_var("CADUCEUS_DNS_CMD", value),
        None => env::remove_var("CADUCEUS_DNS_CMD"),
    }
    env::set_var("PATH", old_path);
    let _ = fs::remove_dir_all(root);
}
