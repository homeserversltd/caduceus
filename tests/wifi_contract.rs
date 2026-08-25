use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use caduceus::routes::serve;
use std::{
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};
use tower::ServiceExt;
static LOCK: Mutex<()> = Mutex::new(());
fn temp() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "wifi-http-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
struct Guard {
    root: PathBuf,
    root0: Option<std::ffi::OsString>,
    nm0: Option<std::ffi::OsString>,
}
impl Guard {
    fn new(root: PathBuf, nm: &Path) -> Self {
        let root0 = env::var_os("CADUCEUS_ROOT");
        let nm0 = env::var_os("CADUCEUS_NMCLI");
        env::set_var("CADUCEUS_ROOT", "tests/fixtures/console");
        env::set_var("CADUCEUS_NMCLI", nm);
        Self { root, root0, nm0 }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        match &self.root0 {
            Some(v) => env::set_var("CADUCEUS_ROOT", v),
            None => env::remove_var("CADUCEUS_ROOT"),
        };
        match &self.nm0 {
            Some(v) => env::set_var("CADUCEUS_NMCLI", v),
            None => env::remove_var("CADUCEUS_NMCLI"),
        };
        let _ = fs::remove_dir_all(&self.root);
    }
}
async fn json(r: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(r.into_body(), 65536).await.unwrap()).unwrap()
}
fn req(m: &str, p: &str, b: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(m)
        .uri(p)
        .header("content-type", "application/json")
        .body(Body::from(b.to_string()))
        .unwrap()
}
fn args(p: &Path) -> Vec<Vec<String>> {
    fs::read_to_string(p)
        .unwrap_or_default()
        .lines()
        .map(|l| {
            l.split('\u{1f}')
                .filter(|x| !x.is_empty())
                .map(|x| x.trim_start_matches('[').trim_end_matches(']').to_string())
                .collect()
        })
        .collect()
}
fn stamps(b: &serde_json::Value, p: &str, a: &str, m: bool) {
    assert_eq!(b["schema"], "caduceus.staff.v1");
    assert_eq!(b["admittance"], "open");
    assert_eq!(b["attendance"], "absent");
    assert_eq!(b["registers_lit"], true);
    assert_eq!(b["route"], p.trim_start_matches("/api/v1/"));
    assert_eq!(b["action"], a);
    assert_eq!(b["ok"], true);
    assert_eq!(b["mutationPerformed"], m);
}
#[tokio::test(flavor = "current_thread")]
async fn wifi_http_contract_and_exact_argv() {
    let _l = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let root = temp();
    fs::create_dir_all(&root).unwrap();
    let log = root.join("argv.log");
    let input = root.join("stdin");
    let bin = root.join("nmcli");
    fs::write(&bin,format!(r#"#!/bin/sh
printf '[%s]\037' "$@" >> '{}'
printf '\n' >> '{}'
if [ "$1" = "--ask" ]; then cat > '{}'; else cat >/dev/null; fi
if [ "$1" = "-t" ] && [ "$3" = "SSID,SECURITY,SIGNAL,DEVICE" ]; then printf 'Cafe:WPA2:80:wlan0\n'
elif [ "$1" = "-t" ] && [ "$2" = "-f" ] && [ "$3" = "NAME,UUID,TYPE,DEVICE" ]; then printf 'Home:123e4567-e89b-12d3-a456-426614174000:802-11-wireless:wlan0\nWired:999e4567-e89b-12d3-a456-426614174000:802-3-ethernet:eth0\n'
elif [ "$1" = "-t" ] && [ "$2" = "-f" ] && [ "$3" = "NAME,UUID,TYPE" ]; then printf 'SavedWifi:123e4567-e89b-12d3-a456-426614174000:802-11-wireless\nSavedWired:999e4567-e89b-12d3-a456-426614174000:802-3-ethernet\n'
elif [ "$1" = "device" ] && [ "$2" = "disconnect" ] && [ "$3" = "fail0" ]; then printf 'RAW-CHILD-SECRET\n' >&2; exit 7; fi
exit 0
"#,log.display(),log.display(),input.display())).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let _g = Guard::new(root.clone(), &bin);
    let app = serve::router();
    let u = "123e4567-e89b-12d3-a456-426614174000";
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/network/device/wifi/connect",
            serde_json::json!({"ssid":"Cafe","password":"secret"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let b = json(r).await;
    stamps(&b, "/api/v1/network/device/wifi/connect", "connect", true);
    assert!(!b.to_string().contains("secret"));
    assert_eq!(fs::read_to_string(&input).unwrap(), "secret\n");
    for (p, b, a) in [
        (
            "/api/v1/network/device/wifi/disconnect",
            serde_json::json!({"interface":"wlan0"}),
            "disconnect",
        ),
        (
            "/api/v1/network/device/wifi/forget",
            serde_json::json!({"uuid":u}),
            "forget",
        ),
    ] {
        let r = app.clone().oneshot(req("POST", p, b)).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        stamps(&json(r).await, p, a, true);
    }
    let p = "/api/v1/network/device/wifi/ipv4";
    for b in [
        serde_json::json!({"uuid":u,"method":"static","address":"192.0.2.4/24","gateway":"192.0.2.1","dns":"192.0.2.53"}),
        serde_json::json!({"uuid":u,"method":"auto"}),
    ] {
        let r = app.clone().oneshot(req("POST", p, b)).await.unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        stamps(&json(r).await, p, "ipv4", true);
    }
    for (p, a) in [
        ("/api/v1/network/device/wifi/scan", "scan"),
        ("/api/v1/network/device/wifi/status", "status"),
        ("/api/v1/network/device/wifi/saved", "saved"),
    ] {
        let r = app
            .clone()
            .oneshot(req("GET", p, serde_json::json!({})))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let b = json(r).await;
        stamps(&b, p, a, false);
        if a == "scan" {
            assert_eq!(
                b["result"]["entries"],
                serde_json::json!([["Cafe", "WPA2", "80", "wlan0"]])
            );
        } else if a == "status" {
            assert_eq!(
                b["result"]["entries"],
                serde_json::json!([["Home", u, "802-11-wireless", "wlan0"]])
            );
            assert!(!b.to_string().contains("Wired"));
        } else {
            assert_eq!(
                b["result"]["entries"],
                serde_json::json!([["SavedWifi", u, "802-11-wireless"]])
            );
            assert!(!b.to_string().contains("SavedWired"));
        }
    }
    for (m, p) in [
        ("POST", "/api/v1/network/device/wifi/scan"),
        ("GET", "/api/v1/network/device/wifi/connect"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(req(m, p, serde_json::json!({})))
                .await
                .unwrap()
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    let d = json(
        app.clone()
            .oneshot(req("GET", "/api/v1/doors", serde_json::json!({})))
            .await
            .unwrap(),
    )
    .await;
    let rs = d["routes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>();
    for p in [
        "/api/v1/network/device/wifi/scan",
        "/api/v1/network/device/wifi/status",
        "/api/v1/network/device/wifi/saved",
        "/api/v1/network/device/wifi/connect",
        "/api/v1/network/device/wifi/disconnect",
        "/api/v1/network/device/wifi/forget",
        "/api/v1/network/device/wifi/ipv4",
    ] {
        assert!(rs.contains(&p));
    }
    assert_eq!(
        args(&log),
        vec![
            vec!["--ask", "device", "wifi", "connect", "Cafe"],
            vec!["device", "disconnect", "wlan0"],
            vec!["connection", "delete", "uuid", u],
            vec![
                "connection",
                "modify",
                "uuid",
                u,
                "ipv4.method",
                "manual",
                "ipv4.addresses",
                "192.0.2.4/24",
                "ipv4.gateway",
                "192.0.2.1",
                "ipv4.dns",
                "192.0.2.53"
            ],
            vec!["connection", "down", "uuid", u],
            vec!["connection", "up", "uuid", u],
            vec![
                "connection",
                "modify",
                "uuid",
                u,
                "ipv4.method",
                "auto",
                "ipv4.addresses",
                "",
                "ipv4.gateway",
                "",
                "ipv4.dns",
                ""
            ],
            vec!["connection", "down", "uuid", u],
            vec!["connection", "up", "uuid", u],
            vec![
                "-t",
                "-f",
                "SSID,SECURITY,SIGNAL,DEVICE",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes"
            ],
            vec![
                "-t",
                "-f",
                "NAME,UUID,TYPE,DEVICE",
                "connection",
                "show",
                "--active"
            ],
            vec!["-t", "-f", "NAME,UUID,TYPE", "connection", "show"]
        ]
    );
    assert!(!fs::read_to_string(&log).unwrap().contains("secret"));
    fs::remove_file(&log).unwrap();
    env::set_var("CADUCEUS_ROOT", "tests/fixtures/locked");
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/network/device/wifi/connect",
            serde_json::json!({"ssid":"Cafe","password":"secret"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let b = json(r).await;
    assert_eq!(b["schema"], "caduceus.api.error.v1");
    assert_eq!(b["first_missing_signal"], "caduceus-command-not-allowed");
    assert!(!b.to_string().contains("secret"));
    assert!(!log.exists());
    env::set_var("CADUCEUS_ROOT", "tests/fixtures/console");
    let r = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/network/device/wifi/disconnect",
            serde_json::json!({"interface":"wlan0\nmarker"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
    let b = json(r).await;
    assert_eq!(b["schema"], "caduceus.api.error.v1");
    assert_eq!(b["first_missing_signal"], "wifi-interface-invalid");
    assert!(!b.to_string().contains("marker"));
    assert!(!log.exists());
    let r = app
        .oneshot(req(
            "POST",
            "/api/v1/network/device/wifi/disconnect",
            serde_json::json!({"interface":"fail0"}),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let b = json(r).await;
    assert_eq!(b["schema"], "caduceus.staff.v1");
    assert_eq!(b["first_missing_signal"], "wifi-nmcli-failed");
    assert!(!b.to_string().contains("RAW-CHILD-SECRET"));
    assert!(!b.to_string().contains("fail0"));
    assert_eq!(args(&log), vec![vec!["device", "disconnect", "fail0"]]);
}

#[tokio::test(flavor = "current_thread")]
async fn network_device_routes_and_open_wifi_contract() {
    let _l = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let root = temp();
    fs::create_dir_all(&root).unwrap();
    let log = root.join("argv.log");
    let input = root.join("stdin");
    let bin = root.join("nmcli");
    fs::write(&bin, format!(r#"#!/bin/sh
printf '[%s]\037' "$@" >> '{}'
printf '\n' >> '{}'
if [ "$1" = "--ask" ]; then cat > '{}'; else cat >/dev/null; fi
if [ "$1" = "-t" ] && [ "$3" = "NAME,UUID,TYPE,DEVICE" ]; then printf 'Home:123e4567-e89b-12d3-a456-426614174000:802-11-wireless:wlan0\n'; fi
exit 0
"#, log.display(), log.display(), input.display())).unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o700)).unwrap();
    let _g = Guard::new(root.clone(), &bin);
    let app = serve::router();
    for (path, body, action) in [
        (
            "/api/v1/network/device/wifi/radio",
            serde_json::json!({"enabled":true}),
            "radio",
        ),
        (
            "/api/v1/network/device/wifi/radio",
            serde_json::json!({"enabled":false}),
            "radio",
        ),
        (
            "/api/v1/network/device/connect",
            serde_json::json!({"interface":"wlan0"}),
            "connect",
        ),
        (
            "/api/v1/network/device/disconnect",
            serde_json::json!({"interface":"wlan0"}),
            "disconnect",
        ),
        (
            "/api/v1/network/device/ipv4",
            serde_json::json!({"interface":"wlan0","method":"static","address":"192.0.2.4/24","gateway":"192.0.2.1"}),
            "ipv4",
        ),
    ] {
        let response = app.clone().oneshot(req("POST", path, body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        stamps(&json(response).await, path, action, true);
    }
    let auto = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/network/device/ipv4",
            serde_json::json!({"interface":"wlan0","method":"auto"}),
        ))
        .await
        .unwrap();
    assert_eq!(auto.status(), StatusCode::OK);
    stamps(
        &json(auto).await,
        "/api/v1/network/device/ipv4",
        "ipv4",
        true,
    );
    let open = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/network/device/wifi/connect",
            serde_json::json!({"ssid":"Cafe"}),
        ))
        .await
        .unwrap();
    assert_eq!(open.status(), StatusCode::OK);
    stamps(
        &json(open).await,
        "/api/v1/network/device/wifi/connect",
        "connect",
        true,
    );
    assert!(!input.exists());
    let open_empty = app
        .clone()
        .oneshot(req(
            "POST",
            "/api/v1/network/device/wifi/connect",
            serde_json::json!({"ssid":"Cafe","password":""}),
        ))
        .await
        .unwrap();
    assert_eq!(open_empty.status(), StatusCode::OK);
    stamps(
        &json(open_empty).await,
        "/api/v1/network/device/wifi/connect",
        "connect",
        true,
    );
    assert!(!input.exists());
    assert_eq!(
        args(&log),
        vec![
            vec!["radio", "wifi", "on"],
            vec!["radio", "wifi", "off"],
            vec!["device", "connect", "wlan0"],
            vec!["device", "disconnect", "wlan0"],
            vec![
                "-t",
                "-f",
                "NAME,UUID,TYPE,DEVICE",
                "connection",
                "show",
                "--active"
            ],
            vec![
                "connection",
                "modify",
                "uuid",
                "123e4567-e89b-12d3-a456-426614174000",
                "ipv4.method",
                "manual",
                "ipv4.addresses",
                "192.0.2.4/24",
                "ipv4.gateway",
                "192.0.2.1"
            ],
            vec![
                "connection",
                "down",
                "uuid",
                "123e4567-e89b-12d3-a456-426614174000"
            ],
            vec![
                "connection",
                "up",
                "uuid",
                "123e4567-e89b-12d3-a456-426614174000"
            ],
            vec![
                "-t",
                "-f",
                "NAME,UUID,TYPE,DEVICE",
                "connection",
                "show",
                "--active"
            ],
            vec![
                "connection",
                "modify",
                "uuid",
                "123e4567-e89b-12d3-a456-426614174000",
                "ipv4.method",
                "auto",
                "ipv4.addresses",
                "",
                "ipv4.gateway",
                "",
                "ipv4.dns",
                ""
            ],
            vec![
                "connection",
                "down",
                "uuid",
                "123e4567-e89b-12d3-a456-426614174000"
            ],
            vec![
                "connection",
                "up",
                "uuid",
                "123e4567-e89b-12d3-a456-426614174000"
            ],
            vec!["device", "wifi", "connect", "Cafe"],
            vec!["device", "wifi", "connect", "Cafe"],
        ]
    );
    for (path, body, signal) in [
        (
            "/api/v1/network/device/wifi/radio",
            serde_json::json!({"enabled":"yes"}),
            "wifi-enabled-required",
        ),
        (
            "/api/v1/network/device/connect",
            serde_json::json!({"interface":"wlan0\nmarker"}),
            "wifi-interface-invalid",
        ),
        (
            "/api/v1/network/device/ipv4",
            serde_json::json!({"interface":"wlan0","method":"bogus"}),
            "wifi-ipv4-method-invalid",
        ),
        (
            "/api/v1/network/device/wifi/connect",
            serde_json::json!({"ssid":"Cafe","password":123}),
            "wifi-password-invalid",
        ),
    ] {
        let before = args(&log);
        let response = app.clone().oneshot(req("POST", path, body)).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(json(response).await["first_missing_signal"], signal);
        assert_eq!(args(&log), before);
    }
    for path in [
        "/api/v1/network/device/wifi/radio",
        "/api/v1/network/device/connect",
        "/api/v1/network/device/disconnect",
        "/api/v1/network/device/ipv4",
    ] {
        assert_eq!(
            app.clone()
                .oneshot(req("GET", path, serde_json::json!({})))
                .await
                .unwrap()
                .status(),
            StatusCode::METHOD_NOT_ALLOWED
        );
    }
    let doors = json(
        app.oneshot(req("GET", "/api/v1/doors", serde_json::json!({})))
            .await
            .unwrap(),
    )
    .await;
    for path in [
        "/api/v1/network/device/wifi/radio",
        "/api/v1/network/device/connect",
        "/api/v1/network/device/disconnect",
        "/api/v1/network/device/ipv4",
    ] {
        assert!(doors["routes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == path));
    }
}
