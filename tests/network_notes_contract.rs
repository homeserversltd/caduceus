use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use caduceus::shared::attendance;
use caduceus::trigger_gate_routes as serve;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "caduceus-network-notes-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn request(
    method: &str,
    path: &str,
    body: serde_json::Value,
    document: Option<&str>,
    attendance: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if let Some(document) = document {
        builder = builder.header("x-caduceus-document", document);
    }
    if let Some(attendance) = attendance {
        builder = builder.header("x-caduceus-attendance", attendance);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn network_notes_attendance_write_is_atomic_durable_and_readable() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = root();
    let bin = root.join("bin");
    fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(
        root.join("etc/caduceus/profile.yaml"),
        "profile: homeserver\ncommands:\n- network notes\n- network notes write\n",
    )
    .unwrap();
    let sudo = bin.join("sudo");
    fs::write(
        &sudo,
        "#!/bin/sh\n[ \"$1\" = -n ] || exit 9\ncase \"$2/$3/$4\" in\n/usr/local/sbin/agathodaimon/cli.py/attendance/bind) printf '%s\\n' '{\"ok\":true,\"publicKey\":\"fixture-public\",\"epoch\":\"1\"}' ;;\n/usr/local/sbin/agathodaimon/cli.py/attendance/verify) payload=$(cat); case \"$payload\" in *'\"pin\":\"2468\"'*'\"publicKey\":\"fixture-public\"'*) printf '%s\\n' '{\"ok\":true,\"verified\":true}' ;; *) printf '%s\\n' '{\"ok\":false,\"verified\":false}' ;; esac ;;\n*) exit 8 ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();

    let old_path = std::env::var("PATH").unwrap();
    let old_incarnation = std::env::var_os("CADUCEUS_DOCUMENT_INCARNATION");
    std::env::set_var("PATH", format!("{}:{old_path}", bin.display()));
    std::env::set_var("CADUCEUS_ROOT", &root);
    std::env::remove_var("CADUCEUS_DOCUMENT_INCARNATION");
    attendance::reset_for_tests();
    attendance::bind();
    let opened = attendance::open_json(&serde_json::json!({
        "documentId": "stats-document",
        "documentIncarnation": "inc-1",
        "pin": "2468"
    }))
    .unwrap();
    let attendance = opened["attendance"].as_str().unwrap();

    let app = serve::router();
    let initial = app
        .clone()
        .oneshot(request(
            "GET",
            "/api/v1/network/notes",
            serde_json::json!({}),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(initial.status(), StatusCode::OK);
    assert_eq!(body_json(initial).await["notes"], serde_json::json!({}));

    let written = app
        .clone()
        .oneshot(request(
            "PUT",
            "/api/v1/network/notes",
            serde_json::json!({"mac":"aa-bb-cc-dd-ee-ff","note":"Kitchen tablet"}),
            Some("stats-document"),
            Some(attendance),
        ))
        .await
        .unwrap();
    assert_eq!(written.status(), StatusCode::OK);
    let receipt = body_json(written).await;
    assert_eq!(receipt["mutationPerformed"], true);
    assert_eq!(receipt["completed"], true);
    assert_eq!(
        receipt["notes"],
        serde_json::json!({"AA:BB:CC:DD:EE:FF":"Kitchen tablet"})
    );
    assert!(!receipt.to_string().contains(attendance));
    assert!(!receipt.to_string().contains("inc-1"));
    let state_path = root.join("var/lib/caduceus/state.json");
    let persisted = fs::read(&state_path).unwrap();
    assert_eq!(
        fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        fs::metadata(state_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o750
    );

    let readback = app
        .clone()
        .oneshot(request(
            "GET",
            "/api/v1/network/notes",
            serde_json::json!({}),
            None,
            None,
        ))
        .await
        .unwrap();
    assert_eq!(readback.status(), StatusCode::OK);
    assert_eq!(body_json(readback).await["notes"], receipt["notes"]);

    for body in [
        serde_json::json!({"mac":"not-a-mac","note":"Nope"}),
        serde_json::json!({"mac":"AA:BB:CC:DD:EE:FF","note":"x".repeat(4097)}),
    ] {
        let refused = app
            .clone()
            .oneshot(request(
                "PUT",
                "/api/v1/network/notes",
                body,
                Some("stats-document"),
                Some(attendance),
            ))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
        assert!(body_json(refused).await.get("completed").is_none());
        assert_eq!(fs::read(&state_path).unwrap(), persisted);
    }

    for (document, token) in [
        (None, None),
        (Some("other-document"), Some(attendance)),
        (Some("stats-document"), None),
    ] {
        let refused = app
            .clone()
            .oneshot(request(
                "PUT",
                "/api/v1/network/notes",
                serde_json::json!({"mac":"AA:BB:CC:DD:EE:FF","note":"Denied"}),
                document,
                token,
            ))
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert!(body_json(refused).await.get("completed").is_none());
        assert_eq!(fs::read(&state_path).unwrap(), persisted);
    }

    let cleared = app
        .clone()
        .oneshot(request(
            "PUT",
            "/api/v1/network/notes",
            serde_json::json!({"mac":"AA:BB:CC:DD:EE:FF","note":""}),
            Some("stats-document"),
            Some(attendance),
        ))
        .await
        .unwrap();
    assert_eq!(cleared.status(), StatusCode::OK);
    let cleared = body_json(cleared).await;
    assert_eq!(cleared["mutationPerformed"], true);
    assert_eq!(cleared["completed"], true);
    assert_eq!(cleared["notes"], serde_json::json!({}));

    attendance::reset_for_tests();
    match old_incarnation {
        Some(value) => std::env::set_var("CADUCEUS_DOCUMENT_INCARNATION", value),
        None => std::env::remove_var("CADUCEUS_DOCUMENT_INCARNATION"),
    }
    std::env::set_var("PATH", old_path);
    let _ = fs::remove_dir_all(root);
}
