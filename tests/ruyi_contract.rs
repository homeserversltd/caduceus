use axum::{
    body::{to_bytes, Body},
    extract::ConnectInfo,
    http::{Request, StatusCode},
};
use caduceus::{gate::ConnectionInfo, routes::serve};
use serde_json::{json, Value};
use std::{
    env,
    ffi::OsString,
    fs,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    root: PathBuf,
    prior_root: Option<OsString>,
    prior_profile: Option<OsString>,
}

impl Fixture {
    fn new() -> Self {
        let root = env::temp_dir().join(format!(
            "caduceus-ruyi-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let prior_root = env::var_os("CADUCEUS_ROOT");
        let prior_profile = env::var_os("CADUCEUS_PROFILE");
        env::set_var("CADUCEUS_ROOT", &root);
        env::set_var("CADUCEUS_PROFILE", "homeserver");
        Self {
            root,
            prior_root,
            prior_profile,
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        match &self.prior_root {
            Some(value) => env::set_var("CADUCEUS_ROOT", value),
            None => env::remove_var("CADUCEUS_ROOT"),
        }
        match &self.prior_profile {
            Some(value) => env::set_var("CADUCEUS_PROFILE", value),
            None => env::remove_var("CADUCEUS_PROFILE"),
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn row(mac: &str) -> Value {
    json!({
        "schema": "caduceus.ruyi-row.v1",
        "mac": mac,
        "hostname": "fixture-host",
        "canonical_name": "fixture-host.home.arpa",
        "ipv4": "192.0.2.44",
        "profile": "homeserver",
        "gui_face": null,
        "caduceus_sha": "0123456789abcdef0123456789abcdef01234567",
        "env_sha": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "harmonia_sha": "abcdef0123456789abcdef0123456789abcdef01",
        "syzygy_sha": null,
        "last_seen": 1,
        "last_update": {"run_id": "run-1", "converged": true},
        "spine": "client-input"
    })
}

fn request(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    builder
        .body(body.map_or_else(Body::empty, |value| Body::from(value.to_string())))
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_door_stores_observed_peer_and_lists_rows() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let mut loopback_row = row(mac);
    loopback_row.as_object_mut().unwrap().remove("last_seen");
    loopback_row.as_object_mut().unwrap().remove("spine");
    let mut loopback_put = request("PUT", "/api/v1/ruyi/aa:bb:cc:dd:ee:ff", Some(loopback_row));
    loopback_put
        .extensions_mut()
        .insert(ConnectInfo(ConnectionInfo::Tcp(
            "127.0.0.1:4567".parse().unwrap(),
        )));
    let response = serve::router().oneshot(loopback_put).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let loopback_written = body_json(response).await;
    assert_eq!(loopback_written["stored"]["ipv4"], "192.0.2.44");
    assert_eq!(loopback_written["stored"]["spine"], "client-claimed");

    let mut put = request("PUT", "/api/v1/ruyi/aa:bb:cc:dd:ee:ff", Some(row(mac)));
    put.extensions_mut().insert(ConnectInfo(ConnectionInfo::Tcp(
        "192.0.2.17:4567".parse().unwrap(),
    )));
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let response = serve::router().oneshot(put).await.unwrap();
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(response.status(), StatusCode::OK);
    let written = body_json(response).await;
    assert_eq!(written["stored"]["ipv4"], "192.0.2.17");
    assert_eq!(written["stored"]["spine"], "observed-peer");
    let stored_last_seen = written["stored"]["last_seen"].as_u64().unwrap();
    assert!(stored_last_seen >= before && stored_last_seen <= after);
    assert_ne!(stored_last_seen, 1);

    let response = serve::router()
        .oneshot(request("GET", "/api/v1/ruyi", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let listed = body_json(response).await;
    assert_eq!(listed["schema"], "caduceus.ruyi.v1");
    assert_eq!(listed["ok"], true);
    assert_eq!(listed["service"], "caduceus");
    assert_eq!(listed["seat"]["profile"], "homeserver");
    assert!(listed["seat"]["caduceus_sha"].is_string());
    assert_eq!(listed["staves"].as_array().unwrap().len(), 1);
    assert_eq!(listed["staves"][0]["mac"], mac);
    assert_eq!(listed["staves"][0]["last_seen"], stored_last_seen);

    let mismatch = serve::router()
        .oneshot(request(
            "PUT",
            "/api/v1/ruyi/aa:bb:cc:dd:ee:00",
            Some(row(mac)),
        ))
        .await
        .unwrap();
    assert_eq!(mismatch.status(), StatusCode::BAD_REQUEST);
    let mismatch_body = body_json(mismatch).await;
    assert_eq!(
        mismatch_body["firstMissingSignal"],
        "caduceus-ruyi-mac-mismatch"
    );
    assert!(fixture
        .root
        .join("var/lib/caduceus/stats.sqlite3")
        .is_file());
}
