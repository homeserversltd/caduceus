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
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    root: PathBuf,
    prior_root: Option<OsString>,
    prior_profile: Option<OsString>,
    prior_peer_port: Option<OsString>,
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
        fs::create_dir_all(root.join("etc/appliance")).unwrap();
        fs::write(
            root.join("etc/appliance/profile.json"),
            r#"{"profile":"homeserver"}"#,
        )
        .unwrap();
        fs::write(
            root.join("etc/appliance/config.json"),
            r#"{"caduceus":{"bind":"127.0.0.1:8787"}}"#,
        )
        .unwrap();
        fs::write(root.join("etc/hostname"), "fixture-host\n").unwrap();
        let lo = root.join("sys/class/net/lo");
        fs::create_dir_all(&lo).unwrap();
        fs::write(lo.join("address"), "aa:bb:cc:dd:ee:ff\n").unwrap();
        let unbound_root = root.join("etc/unbound");
        let dns_dir = unbound_root.join("unbound.conf.d");
        fs::create_dir_all(&dns_dir).unwrap();
        fs::write(
            unbound_root.join("unbound.conf"),
            "server:\n  local-data: \"fixture-host.home.arpa. IN A 192.0.2.44\"\n",
        )
        .unwrap();
        fs::write(
            dns_dir.join("fixture.conf"),
            "server:\n  local-data: \"updated-host.home.arpa. IN A 192.0.2.45\"\n",
        )
        .unwrap();
        let prior_root = env::var_os("CADUCEUS_ROOT");
        let prior_profile = env::var_os("CADUCEUS_PROFILE");
        let prior_peer_port = env::var_os("CADUCEUS_RUYI_TEST_PEER_PORT");
        env::set_var("CADUCEUS_ROOT", &root);
        env::set_var("CADUCEUS_PROFILE", "homeserver");
        Self {
            root,
            prior_root,
            prior_profile,
            prior_peer_port,
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
        match &self.prior_peer_port {
            Some(value) => env::set_var("CADUCEUS_RUYI_TEST_PEER_PORT", value),
            None => env::remove_var("CADUCEUS_RUYI_TEST_PEER_PORT"),
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

fn kea_candidate(fixture: &Fixture, mac: &str, hostname: &str) {
    let root = fixture.root.join("etc/kea");
    fs::create_dir_all(&root).unwrap();
    let reservation_mac = mac.replace(':', "-");
    fs::write(
        root.join("kea-dhcp4.conf"),
        format!(r#"{{"Dhcp4":{{"lease-database":{{"name":"/var/lib/kea/test.csv"}},"reservations":[{{"hw-address":"{reservation_mac}","hostname":"reserved-host","ip-address":"127.0.0.2"}}]}}}}"#),
    ).unwrap();
    let leases = fixture.root.join("var/lib/kea");
    fs::create_dir_all(&leases).unwrap();
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    fs::write(
        leases.join("test.csv"),
        format!("address,hwaddr,expire,hostname,state\n127.0.0.1,{mac},{expires},{hostname},0\n"),
    )
    .unwrap();
}

async fn fake_peer(beam: Value, roster_status: u16, roster_body: Value) -> JoinHandle<()> {
    fake_peer_with_beam_status(200, beam, roster_status, roster_body).await
}

async fn fake_peer_with_beam_status(
    beam_status: u16,
    beam: Value,
    roster_status: u16,
    roster_body: Value,
) -> JoinHandle<()> {
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    env::set_var(
        "CADUCEUS_RUYI_TEST_PEER_PORT",
        listener.local_addr().unwrap().port().to_string(),
    );
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let beam = beam.clone();
            let roster_body = roster_body.clone();
            tokio::spawn(async move {
                let mut request = [0u8; 2048];
                let count = socket.read(&mut request).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..count]);
                let (status, body) = if request.starts_with("GET /api/v1/beam ") {
                    (beam_status, beam)
                } else {
                    (roster_status, roster_body)
                };
                let text = body.to_string();
                let response = format!("HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}", text.len());
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    })
}

fn fake_beam() -> Value {
    json!({"schema":"caduceus.beam.v1","ok":true,"service":"caduceus","profile":"homeserver","gui_face":"Coronatio","caduceus_sha":"0123456789abcdef0123456789abcdef01234567","env_sha":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","rustc_version":"rustc test-build","syzygy_sha":"ABCDEF"})
}

fn peer_roster(hostname: &str) -> Value {
    json!({"schema":"caduceus.ruyi.v1","ok":true,"service":"caduceus","seat":{"mac":"aa:bb:cc:dd:ee:ff","hostname":hostname,"ipv4":"127.0.0.1","ipv4_source":"bind-lan-fallback"},"staves":[]})
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
    "ipv4_source",
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
    assert_keys(
        &listed,
        &[
            "schema",
            "ok",
            "service",
            "seat",
            "staves",
            "perspectives",
            "trust",
            "dns_unresolved",
        ],
    );
    assert_keys(&listed["seat"], &["mac", "hostname", "ipv4", "ipv4_source"]);
    assert!(listed["seat"]["mac"].is_string());
    assert!(listed["seat"]["hostname"].is_string());
    assert!(listed["seat"]["ipv4"].is_string());
    assert_eq!(listed["seat"]["ipv4_source"], "bind-lan-fallback");
    assert_eq!(listed["staves"].as_array().unwrap().len(), 1);
    assert_keys(&listed["staves"][0], ROW_KEYS);
    assert!(!listed["staves"][0]
        .as_object()
        .unwrap()
        .contains_key("spine"));
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_accepts_foreign_and_rejects_invalid_contract_values() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";

    let mut foreign = row(mac);
    foreign["zzz"] = json!(1);
    let (status, accepted) = put(mac, foreign).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!accepted.as_object().unwrap().contains_key("zzz"));
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
async fn ruyi_home_hostname_accepts_apex_and_rejects_nested_canonical_name() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    fs::write(
        fixture.root.join("etc/unbound/unbound.conf"),
        "server:\n  local-data: \"fixture-host.home.arpa. IN A 192.0.2.44\"\n  local-data: \"home.arpa. IN A 192.0.2.46\"\n",
    )
    .unwrap();

    let mut apex = row(mac);
    apex["hostname"] = json!("home");
    apex["canonical_name"] = json!("home.arpa");
    let (status, written) = put(mac, apex).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(written["canonical_name"], "home.arpa");
    assert_eq!(written["ipv4"], "192.0.2.46");
    assert_eq!(written["ipv4_source"], "dns");

    let mut nested = row(mac);
    nested["hostname"] = json!("home");
    nested["canonical_name"] = json!("home.home.arpa");
    assert_invalid(mac, nested).await;

    let mut ordinary = row(mac);
    ordinary["hostname"] = json!("arch-tv");
    ordinary["canonical_name"] = json!("arch-tv.home.arpa");
    let (status, written) = put(mac, ordinary).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(written["canonical_name"], "arch-tv.home.arpa");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_caduceus_port_round_trips_and_absence_is_omitted() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    fs::write(
        fixture.root.join("etc/unbound/unbound.conf"),
        "server:\n  local-data: \"fixture-host.home.arpa. IN A 127.0.0.1\"\n",
    )
    .unwrap();
    fs::write(fixture.root.join("etc/hostname"), "fixture-host\n").unwrap();
    let net_dir = fixture.root.join("sys/class/net/lo");
    fs::create_dir_all(&net_dir).unwrap();
    fs::write(net_dir.join("address"), format!("{mac}\n")).unwrap();

    let mut submitted = row(mac);
    submitted["caduceus_port"] = json!(8787);
    let (status, written) = put(mac, submitted).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(written["caduceus_port"], 8787);

    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["staves"][0]["caduceus_port"], 8787);

    let peer = fake_peer(fake_beam(), 404, json!({"unneeded":"roster"})).await;
    let peer_port = env::var("CADUCEUS_RUYI_TEST_PEER_PORT")
        .unwrap()
        .parse::<u16>()
        .unwrap();
    let peer_mac = "02:00:00:00:00:04";
    let mut peer_row = row(peer_mac);
    peer_row["caduceus_port"] = json!(peer_port);
    assert_eq!(put(peer_mac, peer_row).await.0, StatusCode::OK);
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed["staves"]
        .as_array()
        .unwrap()
        .iter()
        .any(|staff| staff["mac"] == peer_mac));
    peer.abort();

    let (status, absent) = put(mac, row(mac)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!absent.as_object().unwrap().contains_key("caduceus_port"));

    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert!(!listed["staves"][0]
        .as_object()
        .unwrap()
        .contains_key("caduceus_port"));

    let mut invalid = row(mac);
    invalid["caduceus_port"] = json!(0);
    assert_invalid(mac, invalid).await;
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_mac_upsert_order_and_old_timestamp_survive_later_write() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let first = "aa:bb:cc:dd:ee:ff";
    let second = "bb:cc:dd:ee:ff:00";
    let old_mac = "cc:dd:ee:ff:00:11";
    assert_eq!(put(first, row(first)).await.0, StatusCode::OK);
    fs::write(
        fixture.root.join("etc/unbound/unbound.conf.d/fixture.conf"),
        "server:\n  local-data: \"updated-host.home.arpa. IN A 192.0.2.46\"\n  local-data: \"fixture-host.home.arpa. IN A 192.0.2.44\"\n",
    )
    .unwrap();
    let mut update = row(first);
    update["hostname"] = json!("updated-host");
    update["canonical_name"] = json!("updated-host.home.arpa");
    update["ipv4"] = json!("192.0.2.45");
    update["last_update"]["run_id"] = json!("run-2");
    assert_eq!(put(first, update).await.0, StatusCode::OK);
    let mut old = row(old_mac);
    old["spine"] = json!("legacy-persisted-only");
    let (status, projected) = put(old_mac, old.clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!projected.as_object().unwrap().contains_key("spine"));
    stats::ruyi_upsert(old_mac, &old.to_string(), 7).unwrap();
    assert_eq!(put(second, row(second)).await.0, StatusCode::OK);

    let snapshot = stats::ruyi_snapshot().unwrap();
    assert_eq!(snapshot.rows.len(), 3);
    assert_eq!(snapshot.rows[0].0, first);
    let first_row: Value = serde_json::from_str(&snapshot.rows[0].1).unwrap();
    assert_eq!(first_row["hostname"], "updated-host");
    assert_eq!(snapshot.rows[1].0, second);
    assert_eq!(snapshot.rows[2].0, old_mac);
    assert_eq!(snapshot.rows[2].2, 7);
    let preserved: Value =
        serde_json::from_str(&stats::ruyi_row(old_mac).unwrap().unwrap()).unwrap();
    assert_eq!(preserved["spine"], "legacy-persisted-only");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_dns_replaces_claimed_ipv4_and_preserves_submitted_identity() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let mut submitted = row(mac);
    submitted["hostname"] = json!("updated-host");
    submitted["canonical_name"] = json!("updated-host.home.arpa");
    submitted["ipv4"] = json!("192.0.2.99");
    let (status, resolved) = put(mac, submitted).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resolved["hostname"], "updated-host");
    assert_eq!(resolved["canonical_name"], "updated-host.home.arpa");
    assert_eq!(resolved["ipv4"], "192.0.2.45");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_missing_dns_accepts_declared_ipv4_and_marks_unresolved() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let (status, _) = put(mac, row(mac)).await;
    assert_eq!(status, StatusCode::OK);

    let mut attempted = row(mac);
    attempted["hostname"] = json!("missing-host");
    attempted["canonical_name"] = json!("missing-host.home.arpa");
    attempted["ipv4"] = json!("192.0.2.99");
    let (status, value) = put(mac, attempted).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ipv4"], "192.0.2.99");
    assert_eq!(value["ipv4_source"], "declared");
    let stored: Value = serde_json::from_str(&stats::ruyi_row(mac).unwrap().unwrap()).unwrap();
    assert_eq!(stored["hostname"], "missing-host");
    assert_eq!(stored["ipv4_source"], "declared");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_dhcp_conflict_does_not_override_submitted_identity_or_dns_ipv4() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let kea = fixture.root.join("etc/kea/kea-dhcp4.conf");
    let unbound_dir = fixture.root.join("etc/unbound/unbound.conf.d");
    fs::create_dir_all(kea.parent().unwrap()).unwrap();
    fs::remove_file(unbound_dir.join("fixture.conf")).unwrap();
    fs::write(
        &kea,
        r#"{"Dhcp4":{"subnet4":[{"reservations":[{"hw-address":"AA-BB-CC-DD-EE-FF","hostname":"gateway-host","ip-address":"192.0.2.99"}]}]}}"#,
    )
    .unwrap();
    fs::write(
        unbound_dir.join("projection.conf"),
        "server:\n  local-data: \"confd-host.home.arpa. IN A 192.0.2.88\"\n",
    )
    .unwrap();
    let mut submitted = row(mac);
    submitted["hostname"] = json!("confd-host");
    submitted["canonical_name"] = json!("confd-host.home.arpa");
    submitted["ipv4"] = json!("192.0.2.77");
    let (status, resolved) = put(mac, submitted).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resolved["hostname"], "confd-host");
    assert_eq!(resolved["canonical_name"], "confd-host.home.arpa");
    assert_eq!(resolved["ipv4"], "192.0.2.88");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_no_dns_view_non_seat_put_succeeds_and_persists_claimed_ipv4() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    fs::remove_file(fixture.root.join("etc/unbound/unbound.conf")).unwrap();
    fs::remove_file(fixture.root.join("etc/unbound/unbound.conf.d/fixture.conf")).unwrap();
    let mut attempted = row(mac);
    attempted["ipv4"] = json!("192.0.2.99");
    attempted["last_update"]["run_id"] = json!("run-2");
    let (status, value) = put(mac, attempted).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ipv4"], "192.0.2.99");

    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["staves"].as_array().unwrap().len(), 1);
    let stored = &listed["staves"][0];
    assert_eq!(stored["hostname"], "fixture-host");
    assert_eq!(stored["canonical_name"], "fixture-host.home.arpa");
    assert_eq!(stored["ipv4"], "192.0.2.99");
    assert_eq!(stored["ipv4_source"], "declared");
    assert_eq!(stored["last_update"]["run_id"], "run-2");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_seat_dns_view_accepts_submitted_hostname_without_a_record() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let mut attempted = row(mac);
    attempted["hostname"] = json!("missing-host");
    attempted["canonical_name"] = json!("missing-host.home.arpa");
    attempted["ipv4"] = json!("192.0.2.99");
    let (status, value) = put(mac, attempted).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["ipv4"], "192.0.2.99");
    assert_eq!(value["ipv4_source"], "declared");
    let stored: Value = serde_json::from_str(&stats::ruyi_row(mac).unwrap().unwrap()).unwrap();
    assert_eq!(stored["hostname"], "missing-host");
    assert_eq!(stored["ipv4_source"], "declared");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_seat_dns_view_replaces_distinct_claimed_ipv4_with_dns_answer() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let mut submitted = row(mac);
    submitted["hostname"] = json!("updated-host");
    submitted["canonical_name"] = json!("updated-host.home.arpa");
    submitted["ipv4"] = json!("192.0.2.99");
    let (status, resolved) = put(mac, submitted).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resolved["hostname"], "updated-host");
    assert_eq!(resolved["canonical_name"], "updated-host.home.arpa");
    assert_eq!(resolved["ipv4"], "192.0.2.45");
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

#[tokio::test(flavor = "current_thread")]
async fn ruyi_announced_form_stays_strict_while_roster_has_discovered_form() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    let mut discovered = row(mac);
    discovered.as_object_mut().unwrap().remove("harmonia_sha");
    discovered.as_object_mut().unwrap().remove("last_update");
    discovered["ipv4_source"] = json!("declared");
    discovered["discovered_via"] = json!("lease-sweep");
    let (status, body) = put(mac, discovered).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["firstMissingSignal"], "caduceus-ruyi-row-invalid");

    for field in ["harmonia_sha", "last_update"] {
        let mut missing = row(mac);
        missing.as_object_mut().unwrap().remove(field);
        assert_invalid(mac, missing).await;
        let mut null = row(mac);
        null[field] = Value::Null;
        assert_invalid(mac, null).await;
    }

    let mut announced = row(mac);
    announced["caduceus_port"] = json!(3015);
    assert_eq!(put(mac, announced).await.0, StatusCode::OK);
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["staves"][0]["caduceus_port"], 3015);
    let schema = fs::read_to_string("schema/caduceus.ruyi.v1.json").unwrap();
    let schema: Value = serde_json::from_str(&schema).unwrap();
    assert_eq!(schema["schema_version"], "1.0.3");
    assert!(schema["forms"]["row"]["required"]
        .as_array()
        .unwrap()
        .contains(&json!("harmonia_sha")));
    assert_eq!(
        schema["forms"]["discovered"]["required"]
            .as_array()
            .unwrap()
            .contains(&json!("discovered_via")),
        true
    );
    assert_eq!(schema["fields"]["harmonia_sha"]["type"], json!(["string", "null"]));
    assert_eq!(schema["fields"]["last_update"]["type"], json!(["object", "null"]));
    assert!(schema["forms"]["row"]["required"].as_array().unwrap().contains(&json!("last_update")));
    assert_eq!(schema["fields"]["staves"]["items"]["form"], "roster-staff");
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_lease_sweep_discovers_from_beam_and_keeps_discovery_ephemeral() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "02:00:00:00:00:01";
    kea_candidate(&fixture, mac, "lease-host");
    let peer = fake_peer(fake_beam(), 404, json!({"not":"a roster"})).await;
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["staves"].as_array().unwrap().len(), 1);
    let discovered = &listed["staves"][0];
    assert_eq!(discovered["mac"], mac);
    assert_eq!(discovered["hostname"], "lease-host");
    assert_eq!(discovered["discovered_via"], "lease-sweep");
    assert_eq!(discovered["profile"], "homeserver");
    assert_eq!(discovered["gui_face"], "Coronatio");
    assert_eq!(discovered["rustc_version"], "rustc test-build");
    assert_eq!(discovered["syzygy_sha"], "ABCDEF");
    assert_eq!(discovered["harmonia_sha"], Value::Null);
    assert_eq!(discovered["last_update"], Value::Null);
    assert!(
        stats::ruyi_row(mac).unwrap().is_none(),
        "GET discovery must not persist a row"
    );
    assert!(stats::ruyi_snapshot().unwrap().rows.iter().all(|(stored_mac, _, _)| stored_mac != mac),
        "GET discovery must leave no candidate MAC in the persistent snapshot");

    fs::write(
        fixture.root.join("etc/unbound/unbound.conf"),
        r#"server:
  local-data: "fixture-host.home.arpa. IN A 127.0.0.1"
"#,
    )
    .unwrap();
    assert_eq!(put(mac, row(mac)).await.0, StatusCode::OK);
    let (status, after_put) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after_put["staves"].as_array().unwrap().len(), 1);
    assert!(after_put["staves"][0].get("discovered_via").is_none());
    peer.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_lease_sweep_uses_peer_hostname_then_kea_and_refuses_invalid_beam() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "02:00:00:00:00:02";
    kea_candidate(&fixture, mac, "lease-host");
    let peer = fake_peer(fake_beam(), 200, peer_roster("peer-host")).await;
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["staves"][0]["hostname"], "peer-host");
    peer.abort();

    let peer = fake_peer(
        json!({"schema":"foreign","ok":true,"service":"caduceus"}),
        200,
        peer_roster("peer-host"),
    )
    .await;
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed["staves"].as_array().unwrap().is_empty());
    peer.abort();

    let peer = fake_peer_with_beam_status(503, fake_beam(), 200, peer_roster("peer-host")).await;
    let started = std::time::Instant::now();
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed["staves"].as_array().unwrap().is_empty());
    assert!(started.elapsed() < std::time::Duration::from_millis(500));
    peer.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_lease_reader_failure_is_stored_only_and_lease_wins_reservation_dedupe() {
    let _lock = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "aa:bb:cc:dd:ee:ff";
    assert_eq!(put(mac, row(mac)).await.0, StatusCode::OK);
    fs::create_dir_all(fixture.root.join("etc/kea")).unwrap();
    fs::write(fixture.root.join("etc/kea/kea-dhcp4.conf"), "invalid").unwrap();
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listed["staves"].as_array().unwrap().len(), 1);

    let candidate_mac = "02:00:00:00:00:03";
    kea_candidate(&fixture, candidate_mac, "lease-host");
    // A lease and reservation share a MAC. The lease hostname must win; the
    // response includes one stored row and one discovered row for distinct MACs.
    let peer = fake_peer(fake_beam(), 200, json!({"bad":"roster"})).await;
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    let candidate_rows: Vec<_> = listed["staves"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|staff| staff["mac"] == candidate_mac)
        .collect();
    assert_eq!(candidate_rows.len(), 1);
    assert_eq!(candidate_rows[0]["hostname"], "lease-host");
    assert_eq!(candidate_rows[0]["ipv4"], "127.0.0.1");
    assert_eq!(candidate_rows[0]["ipv4_source"], "declared");
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    fs::write(
        fixture.root.join("var/lib/kea/test.csv"),
        format!("address,hwaddr,expire,hostname,state\n127.0.0.1,{candidate_mac},{expires},,0\n"),
    )
    .unwrap();
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    let fallback = listed["staves"]
        .as_array()
        .unwrap()
        .iter()
        .find(|staff| staff["mac"] == candidate_mac)
        .unwrap();
    assert_eq!(fallback["hostname"], "reserved-host");
    assert_eq!(fallback["ipv4"], "127.0.0.1");

    fs::write(
        fixture.root.join("var/lib/kea/test.csv"),
        "address,hwaddr,expire,hostname,state\n",
    ).unwrap();
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    let reservation_only = listed["staves"]
        .as_array()
        .unwrap()
        .iter()
        .find(|staff| staff["mac"] == candidate_mac)
        .unwrap();
    assert_eq!(reservation_only["hostname"], "reserved-host");
    assert_eq!(reservation_only["ipv4"], "127.0.0.2");
    peer.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_lease_sweep_refuses_closed_peer_connection_without_errors() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "02:00:00:00:00:05";
    kea_candidate(&fixture, mac, "lease-host");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    env::set_var("CADUCEUS_RUYI_TEST_PEER_PORT", port.to_string());

    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed["staves"].as_array().unwrap().is_empty());
    assert!(listed["dns_unresolved"].as_array().unwrap().is_empty());
    assert!(stats::ruyi_snapshot().unwrap().rows.iter().all(|(stored_mac, _, _)| stored_mac != mac));
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_lease_sweep_uses_peer_hostname_dns_precedence_and_unresolved_fallback() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "02:00:00:00:00:06";
    kea_candidate(&fixture, mac, "lease-host");
    fs::write(
        fixture.root.join("etc/unbound/unbound.conf"),
        "server:\n  local-data: \"peer-host.home.arpa. IN A 192.0.2.86\"\n  local-data: \"fixture-host.home.arpa. IN A 192.0.2.44\"\n",
    ).unwrap();
    let peer = fake_peer(fake_beam(), 200, peer_roster("peer-host")).await;
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    let discovered = listed["staves"].as_array().unwrap().iter().find(|staff| staff["mac"] == mac).unwrap();
    assert_eq!(discovered["hostname"], "peer-host");
    assert_eq!(discovered["ipv4"], "192.0.2.86");
    assert_eq!(discovered["ipv4_source"], "dns");
    assert!(listed["dns_unresolved"].as_array().unwrap().is_empty());
    peer.abort();

    kea_candidate(&fixture, "02:00:00:00:00:07", "missing-host");
    let peer = fake_peer(fake_beam(), 404, json!({"not":"a roster"})).await;
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    let fallback = listed["staves"].as_array().unwrap().iter().find(|staff| staff["mac"] == "02:00:00:00:00:07").unwrap();
    assert_eq!(fallback["hostname"], "missing-host");
    assert_eq!(fallback["ipv4"], "127.0.0.1");
    assert_eq!(fallback["ipv4_source"], "declared");
    assert!(listed["dns_unresolved"].as_array().unwrap().iter().any(|entry| entry["mac"] == "02:00:00:00:00:07"));
    peer.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_lease_sweep_ignores_identity_invalid_roster_but_accepts_caduceus_roster() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let fixture = Fixture::new();
    let mac = "02:00:00:00:00:08";
    kea_candidate(&fixture, mac, "lease-host");

    for invalid_roster in [
        {
            let mut roster = peer_roster("false-roster-host");
            roster["ok"] = json!(false);
            roster
        },
        {
            let mut roster = peer_roster("foreign-service-host");
            roster["service"] = json!("not-caduceus");
            roster
        },
    ] {
        let peer = fake_peer(fake_beam(), 200, invalid_roster).await;
        let (status, listed) = list().await;
        assert_eq!(status, StatusCode::OK);
        let candidate = listed["staves"]
            .as_array()
            .unwrap()
            .iter()
            .find(|staff| staff["mac"] == mac)
            .unwrap();
        assert_eq!(candidate["hostname"], "lease-host");
        peer.abort();
    }

    let peer = fake_peer(fake_beam(), 200, peer_roster("valid-peer-host")).await;
    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    let candidate = listed["staves"]
        .as_array()
        .unwrap()
        .iter()
        .find(|staff| staff["mac"] == mac)
        .unwrap();
    assert_eq!(candidate["hostname"], "valid-peer-host");
    peer.abort();
}

#[tokio::test(flavor = "current_thread")]
async fn ruyi_stored_probe_falls_back_to_canonical_name_for_legacy_invalid_ipv4() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let _fixture = Fixture::new();
    let peer = fake_peer(fake_beam(), 404, json!({})).await;
    let mac = "02:00:00:00:00:09";
    let mut legacy = row(mac);
    legacy["ipv4"] = json!("legacy-unparseable-address");
    legacy["canonical_name"] = json!("127.0.0.1");
    stats::ruyi_upsert(mac, &legacy.to_string(), 1).unwrap();

    let (status, listed) = list().await;
    assert_eq!(status, StatusCode::OK);
    assert!(listed["staves"]
        .as_array()
        .unwrap()
        .iter()
        .any(|staff| staff["mac"] == mac),
        "legacy row remains visible when its canonical-name probe host answers");
    peer.abort();
}
