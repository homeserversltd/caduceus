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

const CHALLENGE_ID: &str = "fixture-challenge-id";
const CHALLENGE_BYTES: &str = "fixture-challenge-bytes";
const TICKET: &str = "fixture-attendance-ticket";
const CAPABILITY: &str = "fixture-one-use-capability";
const PIN: &str = "fixture-pin-981";
const SIGNATURE: &str = "fixture-document-signature";

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

fn proof() -> serde_json::Value {
    serde_json::json!({"challenge_id": CHALLENGE_ID, "signature": SIGNATURE})
}

fn success_response(op: &str) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "challenge_id": CHALLENGE_ID,
        "challenge": CHALLENGE_BYTES,
        "expires_at": 1_700_000_000u64,
        "ticket": TICKET,
        "capability": CAPABILITY,
        "pin": PIN,
        "signature": SIGNATURE,
        "op": op,
    })
}

async fn json_response(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
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
        let value = json_response(response).await;
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
async fn direct_success_allowlists_only_matching_attendance_material() {
    let _environment = environment_lock();
    let paths = [
        (
            "/api/v1/access/challenges/mint",
            "challenge.mint",
            serde_json::json!({"purpose":"session.mint","context":{"document_public_key":"fixture-public-key"}}),
        ),
        (
            "/api/v1/access/sessions/mint",
            "session.mint",
            serde_json::json!({"pin": PIN, "challenge_id": CHALLENGE_ID, "signature": SIGNATURE}),
        ),
        (
            "/api/v1/access/sessions/prove",
            "session.prove",
            serde_json::json!({"ticket": TICKET, "challenge_id": CHALLENGE_ID, "signature": SIGNATURE}),
        ),
        (
            "/api/v1/access/sessions/clear",
            "session.clear",
            serde_json::json!({"ticket": TICKET, "challenge_id": CHALLENGE_ID, "signature": SIGNATURE}),
        ),
        (
            "/api/v1/access/capabilities/mint",
            "capability.mint",
            serde_json::json!({"ticket": TICKET, "challenge_id": CHALLENGE_ID, "signature": SIGNATURE, "action":"pin.change", "target":"homeserver"}),
        ),
        (
            "/api/v1/access/pin/change",
            "pin.change",
            serde_json::json!({"ticket": TICKET, "challenge_id": CHALLENGE_ID, "signature": SIGNATURE, "capability": CAPABILITY, "new_pin":"fixture-new-pin"}),
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
            peer.write_all(success_response(&wanted).to_string().as_bytes())
                .unwrap();
            peer.write_all(b"\n").unwrap();
        }
    });
    std::env::set_var("CADUCEUS_ACCESS_SOCKET", &path);
    for (route, operation, body) in paths {
        let mut local = request("127.0.0.1:40231", Body::from(body.to_string()));
        *local.uri_mut() = route.parse().unwrap();
        let response = serve::router().oneshot(local).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK, "route {route}");
        let response = json_response(response).await;
        assert_eq!(response["ok"], true);
        match operation {
            "challenge.mint" => {
                assert_eq!(response["challenge_id"], CHALLENGE_ID);
                assert_eq!(response["challenge"], CHALLENGE_BYTES);
                assert_eq!(response["expires_at"], 1_700_000_000u64);
            }
            "session.mint" => assert_eq!(response["ticket"], TICKET),
            "capability.mint" => assert_eq!(response["capability"], CAPABILITY),
            _ => {
                assert!(response.get("challenge_id").is_none());
                assert!(response.get("ticket").is_none());
                assert!(response.get("capability").is_none());
            }
        }
        for secret in [PIN, SIGNATURE] {
            assert!(
                !response.to_string().contains(secret),
                "direct response leaked {secret}"
            );
        }
        if operation != "challenge.mint" {
            assert!(!response.to_string().contains(CHALLENGE_BYTES));
        }
        if operation != "session.mint" {
            assert!(!response.to_string().contains(TICKET));
        }
        if operation != "capability.mint" {
            assert!(!response.to_string().contains(CAPABILITY));
        }
    }
    std::env::remove_var("CADUCEUS_ACCESS_SOCKET");
    worker.join().unwrap();
    let _ = std::fs::remove_file(path);
    let diagnostic_and_hyalos_payload =
        serde_json::to_string(&serve::recorded_access_diagnostics()).unwrap();
    for secret in [
        CHALLENGE_ID,
        CHALLENGE_BYTES,
        TICKET,
        CAPABILITY,
        PIN,
        SIGNATURE,
    ] {
        assert!(
            !diagnostic_and_hyalos_payload.contains(secret),
            "recorded diagnostic/Hyalos-safe payload leaked {secret}"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_proofs_and_unknown_challenge_purpose_refuse_before_staff() {
    let _environment = environment_lock();
    let cases = [
        (
            "/api/v1/access/challenges/mint",
            serde_json::json!({"purpose":"document-attendance","context":{"document_public_key":"fixture"}}),
        ),
        (
            "/api/v1/access/challenges/mint",
            serde_json::json!({"purpose":"unknown","context":{"document_public_key":"fixture"}}),
        ),
        (
            "/api/v1/access/sessions/mint",
            serde_json::json!({"pin": PIN}),
        ),
        ("/api/v1/access/sessions/prove", proof()),
        ("/api/v1/access/sessions/clear", proof()),
        (
            "/api/v1/access/capabilities/mint",
            serde_json::json!({"ticket":TICKET,"challenge_id":CHALLENGE_ID,"signature":SIGNATURE}),
        ),
        (
            "/api/v1/access/pin/change",
            serde_json::json!({"ticket":TICKET,"challenge_id":CHALLENGE_ID,"signature":SIGNATURE,"new_pin":"fixture-new-pin"}),
        ),
    ];
    std::env::set_var("CADUCEUS_ACCESS_SOCKET", socket("must-not-connect"));
    for (route, body) in cases {
        let mut local = request("127.0.0.1:40231", Body::from(body.to_string()));
        *local.uri_mut() = route.parse().unwrap();
        let response = serve::router().oneshot(local).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN, "route {route}");
        let response = json_response(response).await;
        assert_ne!(response["firstMissingSignal"], "caduceus-staff-unavailable");
        let rendered = response.to_string();
        for secret in [PIN, SIGNATURE, TICKET, CAPABILITY] {
            assert!(!rendered.contains(secret), "refusal leaked {secret}");
        }
    }
    std::env::remove_var("CADUCEUS_ACCESS_SOCKET");
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
        "/api/v1/access/pin/change",
    ] {
        assert!(serve.contains(route), "missing access route {route}");
    }
    assert_eq!(serve.matches("post(access_route)").count(), 6);
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
        Body::from(
            serde_json::json!({"pin":PIN,"challenge_id":CHALLENGE_ID,"signature":SIGNATURE})
                .to_string(),
        ),
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
