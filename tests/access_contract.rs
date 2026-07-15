use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use caduceus::bands::serve;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

fn request(peer: &str, body: Body) -> Request<Body> {
    static PROFILE: OnceLock<()> = OnceLock::new();
    PROFILE.get_or_init(|| {
        std::env::set_var(
            "CADUCEUS_ROOT",
            concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/homeserver"),
        );
    });
    let mut request = Request::builder()
        .method("POST")
        .uri("/api/v1/access/sessions/mint")
        .header("content-type", "application/json")
        .body(body)
        .unwrap();
    request
        .extensions_mut()
        .insert(ConnectInfo(peer.parse::<std::net::SocketAddr>().unwrap()));
    request
}

fn environment_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

fn socket(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "caduceus-http-{name}-{}-{}.sock",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn access_loopback_is_admitted_before_secret_body_is_dispatched() {
    let response = serve::router()
        .oneshot(request("127.0.0.1:40231", Body::from("{malformed")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "current_thread")]
async fn nonloopback_access_is_refused_before_malformed_or_oversize_body_parsing() {
    for body in [Body::from("{malformed"), Body::from(vec![b'x'; 32 * 1024])] {
        let response = serve::router()
            .oneshot(request("192.0.2.44:40231", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["firstMissingSignal"], "caduceus-access-non-loopback");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn loopback_oversize_is_rejected_before_staff() {
    let response = serve::router()
        .oneshot(request("127.0.0.1:40231", Body::from(vec![b'x'; 8193])))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test(flavor = "current_thread")]
async fn five_access_routes_forward_exact_operation_mapping_and_safe_context() {
    let _environment = environment_lock();
    let paths = [
        (
            "/api/v1/access/challenges/mint",
            "challenge.mint",
            serde_json::json!({"purpose":"document-attendance","context":{"document_public_key":"public"}}),
        ),
        (
            "/api/v1/access/sessions/mint",
            "session.mint",
            serde_json::json!({"pin":"fixture-pin-981"}),
        ),
        (
            "/api/v1/access/sessions/prove",
            "session.prove",
            serde_json::json!({"challenge_id":"challenge-id","signature":"webcrypto-signature"}),
        ),
        (
            "/api/v1/access/sessions/clear",
            "session.clear",
            serde_json::json!({"challenge_id":"challenge-id","signature":"webcrypto-signature"}),
        ),
        (
            "/api/v1/access/capabilities/mint",
            "capability.mint",
            serde_json::json!({"challenge_id":"challenge-id","signature":"webcrypto-signature","ticket":"server-ticket"}),
        ),
    ];
    let path = socket("operations");
    let listener = UnixListener::bind(&path).unwrap();
    let expected = paths.clone().map(|(_, op, body)| (op.to_string(), body));
    let worker = thread::spawn(move || {
        for (wanted, expected_body) in expected {
            let (peer, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(peer.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let observed = serde_json::from_str::<serde_json::Value>(&line).unwrap();
            assert_eq!(observed["op"], wanted);
            for (key, value) in expected_body.as_object().unwrap() {
                assert_eq!(&observed[key], value, "staff context field {key}");
            }
            let mut peer = peer;
            peer.write_all(b"{\"ok\":false,\"code\":\"attendance-refused\",\"pin\":\"fixture-pin-981\",\"ticket\":\"server-ticket\",\"signature\":\"webcrypto-signature\",\"capability\":\"secret-capability\",\"challenge\":\"secret-challenge\"}\n")
                .unwrap();
        }
    });
    std::env::set_var("CADUCEUS_ACCESS_SOCKET", &path);
    for (route, _, body) in paths {
        let mut local = request("127.0.0.1:40231", Body::from(body.to_string()));
        *local.uri_mut() = route.parse().unwrap();
        let response = serve::router().oneshot(local).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "route {route}");
        let response = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let response = String::from_utf8(response.to_vec()).unwrap();
        for secret in [
            "fixture-pin-981",
            "server-ticket",
            "webcrypto-signature",
            "secret-capability",
            "secret-challenge",
        ] {
            assert!(
                !response.contains(secret),
                "public response leaked {secret}"
            );
        }
    }
    std::env::remove_var("CADUCEUS_ACCESS_SOCKET");
    worker.join().unwrap();
    let _ = std::fs::remove_file(path);
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_challenge_and_missing_staff_refuse_without_secret_reflection() {
    let _environment = environment_lock();
    let mut malformed = request(
        "127.0.0.1:40231",
        Body::from(r#"{"purpose":"unknown-purpose","context":{}}"#),
    );
    *malformed.uri_mut() = "/api/v1/access/challenges/mint".parse().unwrap();
    let response = serve::router().oneshot(malformed).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert!(String::from_utf8(response.to_vec())
        .unwrap()
        .contains("caduceus-attendance-challenge-malformed"));

    std::env::set_var("CADUCEUS_ACCESS_SOCKET", socket("absent"));
    let response = serve::router()
        .oneshot(request(
            "127.0.0.1:40231",
            Body::from(r#"{"pin":"fixture-pin-981"}"#),
        ))
        .await
        .unwrap();
    std::env::remove_var("CADUCEUS_ACCESS_SOCKET");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response = String::from_utf8(response.to_vec()).unwrap();
    assert!(response.contains("caduceus-staff-unavailable"));
    assert!(!response.contains("fixture-pin-981"));
}

#[test]
fn access_route_census_retires_refresh_and_duration_lease() {
    let serve = include_str!("../src/bands/serve.rs");
    let access = include_str!("../src/tools/access.rs");
    for route in [
        "/api/v1/access/challenges/mint",
        "/api/v1/access/sessions/mint",
        "/api/v1/access/sessions/prove",
        "/api/v1/access/sessions/clear",
        "/api/v1/access/capabilities/mint",
    ] {
        assert!(serve.contains(route), "missing access route {route}");
    }
    assert_eq!(serve.matches("post(access_route)").count(), 5);
    assert!(!serve.contains("sessions/refresh"));
    assert!(!access.contains("session.refresh"));
    assert!(!access.contains("SESSION_SECONDS"));
    assert!(!access.contains(&["18", "00"].concat()));
}

#[tokio::test(flavor = "current_thread")]
async fn blocked_staff_socket_does_not_block_unrelated_http() {
    let _environment = environment_lock();
    let path = socket("stalled");
    let listener = UnixListener::bind(&path).unwrap();
    let worker = thread::spawn(move || {
        let (_peer, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(6));
    });
    std::env::set_var("CADUCEUS_ACCESS_SOCKET", &path);
    let access = serve::router().oneshot(request(
        "127.0.0.1:40231",
        Body::from(r#"{"pin":"fixture-pin-981"}"#),
    ));
    let health = serve::router().oneshot(
        Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap(),
    );
    let (_, health) = tokio::join!(access, health);
    assert_eq!(health.unwrap().status(), StatusCode::OK);
    std::env::remove_var("CADUCEUS_ACCESS_SOCKET");
    worker.join().unwrap();
    let _ = std::fs::remove_file(path);
}
