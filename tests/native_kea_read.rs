use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use caduceus::routes::serve;
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    env, fs,
    path::PathBuf,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());
const LEASES_PATH: &str = "/api/v1/network/dhcp/leases";
const RESERVATIONS_PATH: &str = "/api/v1/network/dhcp/reservations";
const STAFF_SCHEMA: &str = "caduceus.staff.network.dhcp.v1";

struct Fixture {
    root: PathBuf,
    old_root: Option<std::ffi::OsString>,
    old_command: Option<std::ffi::OsString>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl Fixture {
    fn new() -> Self {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let root = env::temp_dir().join(format!(
            "native-kea-read-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let fixture = PathBuf::from("tests/fixtures/native-kea-read");
        for relative in [
            "etc/kea/kea-dhcp4.conf",
            "etc/caduceus/profile.yaml",
            "var/lib/kea/kea-leases4.csv.2",
            "var/lib/kea/kea-leases4.csv.1",
            "var/lib/kea/kea-leases4.csv",
        ] {
            let destination = root.join(relative);
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::copy(fixture.join(relative), destination).unwrap();
        }
        let old_root = env::var_os("CADUCEUS_ROOT");
        let old_command = env::var_os("CADUCEUS_NETWORK_READ_CMD");
        env::set_var("CADUCEUS_ROOT", &root);
        let absent_staff = root.join("deliberately-absent-staff-launcher");
        env::set_var("CADUCEUS_NETWORK_READ_CMD", absent_staff);
        Self {
            root,
            old_root,
            old_command,
            _guard: guard,
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        match self.old_root.take() {
            Some(value) => env::set_var("CADUCEUS_ROOT", value),
            None => env::remove_var("CADUCEUS_ROOT"),
        }
        match self.old_command.take() {
            Some(value) => env::set_var("CADUCEUS_NETWORK_READ_CMD", value),
            None => env::remove_var("CADUCEUS_NETWORK_READ_CMD"),
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn native_kea_http_reads_match_staff_contract_and_refuse_bad_inputs() {
    let fixture = Fixture::new();
    let app = serve::router();

    // The base file wins over .1/.2 for MAC A, while distinct MACs B and D
    // prove base/.1 data survive. Malformed, wrong-width, empty-MAC (including
    // the declined state=1 row), and invalid-number rows in .2 are skipped.
    let leases_response = app.clone().oneshot(get(LEASES_PATH)).await.unwrap();
    assert_eq!(leases_response.status(), StatusCode::OK);
    let leases = body_json(leases_response).await;
    assert_eq!(keys(&leases), BTreeSet::from([
        "actuatorId", "command", "firstMissingSignal", "ok", "payload", "schema",
    ]));
    assert_eq!(keys(&leases["payload"]), BTreeSet::from([
        "action", "actuator", "firstMissingSignal", "mutationPerformed", "ok", "result", "schema",
    ]));
    assert_eq!(leases["schema"], "caduceus.network.read.v1");
    assert_eq!(leases["command"], "network dhcp leases");
    assert_eq!(leases["actuatorId"], "network.dhcp.leases");
    assert_eq!(leases["firstMissingSignal"], "none");
    assert_eq!(leases["ok"], true);
    assert_eq!(leases["payload"]["action"], "leases");
    assert_eq!(leases["payload"]["actuator"], "network.dhcp.leases");
    assert_eq!(leases["payload"]["firstMissingSignal"], "none");
    assert_eq!(leases["payload"]["mutationPerformed"], false);
    assert_eq!(leases["payload"]["ok"], true);
    assert_eq!(leases["payload"]["schema"], STAFF_SCHEMA);
    assert_eq!(leases["payload"]["result"], json!([
        {"mac":"aa:bb:cc:dd:ee:01", "ip":"192.0.2.5", "hostname":"new-a", "last_activity":"4102444800", "provenance":"observed"},
        {"mac":"aa:bb:cc:dd:ee:02", "ip":"192.0.2.3", "hostname":"base-b", "last_activity":"4102444800", "provenance":"observed"},
        {"mac":"aa:bb:cc:dd:ee:04", "ip":"192.0.2.6", "hostname":"rollover-d", "last_activity":"4102444800", "provenance":"observed"}
    ]));
    for row in leases["payload"]["result"].as_array().unwrap() {
        assert_eq!(keys(row), BTreeSet::from([
            "hostname", "ip", "last_activity", "mac", "provenance",
        ]));
        assert_eq!(row["provenance"], "observed");
    }

    // An unreadable newest rollover file is skipped while readable .1/base
    // candidates still contribute their records.
    fs::write(
        fixture.path("var/lib/kea/kea-leases4.csv.2"),
        [0xff, 0xfe, 0xfd],
    )
    .unwrap();
    let unreadable_rollover = app.clone().oneshot(get(LEASES_PATH)).await.unwrap();
    assert_eq!(unreadable_rollover.status(), StatusCode::OK);
    let unreadable_rollover = body_json(unreadable_rollover).await;
    assert_eq!(unreadable_rollover["payload"]["result"], json!([
        {"mac":"aa:bb:cc:dd:ee:01", "ip":"192.0.2.5", "hostname":"new-a", "last_activity":"4102444800", "provenance":"observed"},
        {"mac":"aa:bb:cc:dd:ee:02", "ip":"192.0.2.3", "hostname":"base-b", "last_activity":"4102444800", "provenance":"observed"},
        {"mac":"aa:bb:cc:dd:ee:04", "ip":"192.0.2.6", "hostname":"rollover-d", "last_activity":"4102444800", "provenance":"observed"}
    ]));

    // If every candidate is unreadable, the route reports invalid leases.
    for suffix in ["", ".1", ".2"] {
        fs::write(
            fixture.path(&format!("var/lib/kea/kea-leases4.csv{suffix}")),
            [0xff, 0xfe, 0xfd],
        )
        .unwrap();
    }
    let all_unreadable = app.clone().oneshot(get(LEASES_PATH)).await.unwrap();
    assert_eq!(all_unreadable.status(), StatusCode::SERVICE_UNAVAILABLE);
    let all_unreadable = body_json(all_unreadable).await;
    assert_eq!(all_unreadable["schema"], "caduceus.api.error.v1");
    assert_eq!(all_unreadable["ok"], false);
    assert_eq!(
        all_unreadable["firstMissingSignal"],
        "caduceus-network-dhcp-leases-invalid"
    );
    for relative in [
        "var/lib/kea/kea-leases4.csv",
        "var/lib/kea/kea-leases4.csv.1",
        "var/lib/kea/kea-leases4.csv.2",
    ] {
        fs::copy(
            PathBuf::from("tests/fixtures/native-kea-read").join(relative),
            fixture.path(relative),
        )
        .unwrap();
    }

    let reservations_response = app.clone().oneshot(get(RESERVATIONS_PATH)).await.unwrap();
    assert_eq!(reservations_response.status(), StatusCode::OK);
    let reservations = body_json(reservations_response).await;
    assert_eq!(keys(&reservations), BTreeSet::from([
        "actuatorId", "command", "firstMissingSignal", "ok", "payload", "schema",
    ]));
    assert_eq!(reservations["schema"], "caduceus.network.read.v1");
    assert_eq!(reservations["command"], "network dhcp reservations list");
    assert_eq!(reservations["actuatorId"], "network.dhcp.reservations");
    assert_eq!(reservations["firstMissingSignal"], "none");
    assert_eq!(reservations["ok"], true);
    assert_eq!(reservations["payload"]["action"], "reservations");
    assert_eq!(reservations["payload"]["actuator"], "network.dhcp.reservations");
    assert_eq!(reservations["payload"]["firstMissingSignal"], "none");
    assert_eq!(reservations["payload"]["mutationPerformed"], false);
    assert_eq!(reservations["payload"]["ok"], true);
    assert_eq!(reservations["payload"]["schema"], STAFF_SCHEMA);
    assert_eq!(reservations["payload"]["result"], json!([
        {"mac":"aa:bb:cc:dd:ee:10", "ip":"192.0.2.10", "hostname":"global", "provenance":"declared"},
        {"mac":"aa:bb:cc:dd:ee:11", "ip":"192.0.2.11", "hostname":"subnet", "provenance":"declared"}
    ]));
    for row in reservations["payload"]["result"].as_array().unwrap() {
        assert_eq!(keys(row), BTreeSet::from(["hostname", "ip", "mac", "provenance"]));
        assert_eq!(row["provenance"], "declared");
    }

    // All malformed/missing host inputs cross the handlers as typed non-2xx
    // API errors, with the original firstMissingSignal preserved.
    for (path, relative, contents, expected_signal) in [
        (LEASES_PATH, "var/lib/kea/kea-leases4.csv", None, "caduceus-network-dhcp-leases-missing"),
        (LEASES_PATH, "var/lib/kea/kea-leases4.csv", Some("not,a,valid,lease\n"), "caduceus-network-dhcp-leases-invalid"),
        (RESERVATIONS_PATH, "etc/kea/kea-dhcp4.conf", Some("{ malformed"), "caduceus-network-dhcp-config-invalid"),
    ] {
        let target = fixture.path(relative);
        match contents {
            Some(contents) => fs::write(&target, contents).unwrap(),
            None => {
                for suffix in ["", ".1", ".2"] {
                    let _ = fs::remove_file(fixture.path(&format!("var/lib/kea/kea-leases4.csv{suffix}")));
                }
            }
        }
        let response = app.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let error = body_json(response).await;
        assert_eq!(error["schema"], "caduceus.api.error.v1");
        assert_eq!(error["ok"], false);
        assert_eq!(error["firstMissingSignal"], expected_signal);
        // Restore clean source before checking the next case.
        if relative.ends_with("kea-dhcp4.conf") {
            fs::copy(
                "tests/fixtures/native-kea-read/etc/kea/kea-dhcp4.conf",
                &target,
            )
            .unwrap();
        } else {
            fs::copy(
                "tests/fixtures/native-kea-read/var/lib/kea/kea-leases4.csv",
                &target,
            )
            .unwrap();
        }
    }

    fs::write(
        fixture.path("etc/caduceus/profile.yaml"),
        "profile: homeserver\ncommands:\n- help\n",
    )
    .unwrap();
    for (path, command) in [
        (LEASES_PATH, "network dhcp leases"),
        (RESERVATIONS_PATH, "network dhcp reservations list"),
    ] {
        let response = app.clone().oneshot(get(path)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let error = body_json(response).await;
        assert_eq!(error["schema"], "caduceus.api.error.v1");
        assert_eq!(error["ok"], false);
        assert_eq!(error["command"], command);
        assert_eq!(error["firstMissingSignal"], "caduceus-public-action-not-allowed");
    }
}
