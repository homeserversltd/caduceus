use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use caduceus::{routes::serve, stats};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
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
        "schema": "caduceus.ruyi.v1",
        "mac": mac,
        "hostname": "fixture-host",
        "canonical_name": "fixture-host.home.arpa",
        "ipv4": "192.0.2.44",
        "profile": "homeserver",
        "gui_face": "Coronatio",
        "caduceus_sha": "0123456789abcdef0123456789abcdef01234567",
        "env_sha": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "harmonia_sha": "abcdef0123456789abcdef0123456789abcdef01",
        "syzygy_sha": null,
        "last_seen": 1,
        "last_update": {"run_id": "run-1", "converged": true}
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

async fn put(path_mac: &str, body: Value) -> (StatusCode, Value) {
    let response = serve::router()
        .oneshot(request(
            "PUT",
            &format!("/api/v1/ruyi/{path_mac}"),
            Some(body),
        ))
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

async fn list() -> (StatusCode, Value) {
    let response = serve::router()
        .oneshot(request("GET", "/api/v1/ruyi", None))
        .await
        .unwrap();
    let status = response.status();
    (status, body_json(response).await)
}

fn keys(value: &Value) -> BTreeSet<String> {
    value.as_object().unwrap().keys().cloned().collect()
}

fn assert_keys(value: &Value, expected: &[&str]) {
    let expected = expected.iter().map(|key| (*key).to_owned()).collect();
    assert_eq!(keys(value), expected);
}

async fn assert_invalid(path_mac: &str, body: Value) {
    let (status, value) = put(path_mac, body).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["firstMissingSignal"], "caduceus-ruyi-row-invalid");
}

const ROW_KEYS: &[&str] = &[
    "schema",
    "mac",
    "hostname",
    "canonical_name",
    "ipv4",
    "profile",
    "gui_face",
    "caduceus_sha",
    "env_sha",
    "harmonia_sha",
    "syzygy_sha",
    "last_seen",
    "last_update",
];

#[tokio::test(flavor = "current_thread")]
async fn ruyi_exact_shapes_timestamp_and_local_put() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let before = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut initial = row(mac);
    initial.as_object_mut().unwrap().remove("last_seen");
    let (status, written) = put(mac, initial).await;
    let after = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert_eq!(status, StatusCode::OK);
    assert_keys(&written, ROW_KEYS);
    assert_keys(&written["last_update"], &["run_id", "converged"]);
    assert_eq!(
        written["last_update"],
        json!({"run_id":"run-1","converged":true})
    );
    assert!(written["last_seen"].as_u64().unwrap() >= before);
    assert!(written["last_seen"].as_u64().unwrap() <= after);

    let mut null_face = row(mac);
    null_face["gui_face"] = Value::Null;
    assert_eq!(put(mac, null_face).await.0, StatusCode::OK);

    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert_keys(&listed, &["schema", "ok", "service", "seat", "staves"]);
    assert_keys(&listed["seat"], &["mac", "hostname"]);
    assert!(listed["seat"]["mac"].is_string());
    assert!(listed["seat"]["hostname"].is_string());
    assert_eq!(listed["staves"].as_array().unwrap().len(), 1);
    assert_keys(&listed["staves"][0], ROW_KEYS);
    assert!(!listed["staves"][0]
        .as_object()
        .unwrap()
        .contains_key("spine"));
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_rejects_unknown_and_invalid_contract_values() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";

    let mut unknown = row(mac);
    unknown["spine"] = json!("legacy");
    assert_invalid(mac, unknown).await;
    let mut invalid = row(mac);
    invalid["schema"] = json!("wrong");
    assert_invalid(mac, invalid).await;
    assert_invalid("AA:BB:CC:DD:EE:FF", row("AA:BB:CC:DD:EE:FF")).await;
    assert_invalid("aa-bb-cc-dd-ee-ff", row("aa-bb-cc-dd-ee-ff")).await;

    let mut invalid = row(mac);
    invalid["hostname"] = json!("Fixture.Host");
    assert_invalid(mac, invalid).await;
    let mut invalid = row(mac);
    invalid["canonical_name"] = json!("other.home.arpa");
    assert_invalid(mac, invalid).await;
    let mut invalid = row(mac);
    invalid["ipv4"] = json!("192.0.2.999");
    assert_invalid(mac, invalid).await;
    for (field, value) in [("profile", json!("")), ("gui_face", json!(""))] {
        let mut invalid = row(mac);
        invalid[field] = value;
        assert_invalid(mac, invalid).await;
        let mut invalid = row(mac);
        invalid[field] = json!("x".repeat(65));
        assert_invalid(mac, invalid).await;
    }
    let mut invalid = row(mac);
    invalid["profile"] = json!("HomeServer");
    assert_invalid(mac, invalid).await;
    let mut invalid = row(mac);
    invalid["gui_face"] = json!("coronatio");
    assert_invalid(mac, invalid).await;
    let mut invalid = row(mac);
    invalid["last_update"]["run_id"] = json!("");
    assert_invalid(mac, invalid).await;
    let mut invalid = row(mac);
    invalid["last_update"]["run_id"] = json!("x".repeat(65));
    assert_invalid(mac, invalid).await;

    for (field, width) in [("caduceus_sha", 40), ("harmonia_sha", 40), ("env_sha", 64)] {
        let mut invalid = row(mac);
        invalid[field] = json!("0".repeat(width - 1));
        assert_invalid(mac, invalid).await;
        let mut invalid = row(mac);
        invalid[field] = json!("g".repeat(width));
        assert_invalid(mac, invalid).await;
        let mut invalid = row(mac);
        invalid[field] = json!("A".repeat(width));
        assert_invalid(mac, invalid).await;
    }
    let mut invalid = row(mac);
    invalid["syzygy_sha"] = json!("0".repeat(63));
    assert_invalid(mac, invalid).await;
    let mut invalid = row(mac);
    invalid["syzygy_sha"] = json!("g".repeat(64));
    assert_invalid(mac, invalid).await;
    let mut invalid = row(mac);
    invalid["syzygy_sha"] = json!("A".repeat(64));
    assert_invalid(mac, invalid).await;

    let mut mismatch = row(mac);
    mismatch["mac"] = json!("aa:bb:cc:dd:ee:00");
    let (status, value) = put(mac, mismatch).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(value["firstMissingSignal"], "caduceus-ruyi-mac-mismatch");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_mac_upsert_order_and_old_timestamp_survive_later_write() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let first = "aa:bb:cc:dd:ee:ff";
    let second = "bb:cc:dd:ee:ff:00";
    let old_mac = "cc:dd:ee:ff:00:11";
    assert_eq!(put(first, row(first)).await.0, StatusCode::OK);
    let mut update = row(first);
    update["hostname"] = json!("updated-host");
    update["canonical_name"] = json!("updated-host.home.arpa");
    update["ipv4"] = json!("192.0.2.45");
    update["last_update"]["run_id"] = json!("run-2");
    assert_eq!(put(first, update).await.0, StatusCode::OK);
    let mut old = row(old_mac);
    old["spine"] = json!("legacy-persisted-only");
    stats::ruyi_upsert(old_mac, &old.to_string(), 7).unwrap();
    assert_eq!(put(second, row(second)).await.0, StatusCode::OK);

    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    let staves = listed["staves"].as_array().unwrap();
    assert_eq!(staves.len(), 3);
    assert_eq!(staves[0]["mac"], first);
    assert_eq!(staves[0]["hostname"], "updated-host");
    assert_eq!(staves[1]["mac"], second);
    let preserved = staves.iter().find(|value| value["mac"] == old_mac).unwrap();
    assert_eq!(preserved["last_seen"], 7);
    assert!(!preserved.as_object().unwrap().contains_key("spine"));
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_gateway_projection_needs_dhcp_and_dns_and_reads_confd() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let kea = fixture.root.join("etc/kea/kea-dhcp4.conf");
    let unbound_dir = fixture.root.join("etc/unbound/unbound.conf.d");
    fs::create_dir_all(kea.parent().unwrap()).unwrap();
    fs::create_dir_all(&unbound_dir).unwrap();
    fs::write(
        &kea,
        r#"{"Dhcp4":{"subnet4":[{"reservations":[{"hw-address":"AA-BB-CC-DD-EE-FF","hostname":"gateway-host","ip-address":"192.0.2.99"}]}]}}"#,
    )
    .unwrap();
    fs::write(
        unbound_dir.join("projection.conf"),
        "server:\n  local-data: \"gateway-host.home.arpa. IN A 192.0.2.99\"\n",
    )
    .unwrap();
    let (status, projected) = put(mac, row(mac)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(projected["hostname"], "gateway-host");
    assert_eq!(projected["canonical_name"], "gateway-host.home.arpa");
    assert_eq!(projected["ipv4"], "192.0.2.99");

    fs::remove_file(unbound_dir.join("projection.conf")).unwrap();
    let mut dhcp_only = row(mac);
    dhcp_only["last_update"]["run_id"] = json!("run-dhcp-only");
    let (status, retained) = put(mac, dhcp_only).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(retained["hostname"], "fixture-host");
    assert_eq!(retained["canonical_name"], "fixture-host.home.arpa");
    assert_eq!(retained["ipv4"], "192.0.2.44");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_path_body_mismatch_is_refused() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let (status, body) = put("aa:bb:cc:dd:ee:00", row("aa:bb:cc:dd:ee:ff")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["firstMissingSignal"], "caduceus-ruyi-mac-mismatch");
}
