// Child-device staff command, crossed only through agathodaimon network child-device.
use serde_json::{json, Value};

pub fn command_json(metadata: Value) -> Result<Value, String> {
    crate::routes::staff::named_actuator_json("child-device", metadata)
}

pub fn invoke(args: &[String]) -> Result<Value, String> {
    if args.is_empty() {
        return Err("child-device-command-missing".into());
    }
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    let invalid = || "child-device-request-invalid".to_string();
    let plain = |s: &str| !s.starts_with('-');
    let (stop, fields) = match words.as_slice() {
        ["observed"] => ("network/child-device/observed", json!({})),
        ["list"] => ("network/child-device/list", json!({})),
        ["apply"] => ("network/child-device/apply", json!({})),
        ["register", mac] if plain(mac) => ("network/child-device/register", json!({"mac": mac})),
        ["register", mac, "--name", name] if plain(mac) && plain(name) =>
            ("network/child-device/register", json!({"mac": mac, "name": name})),
        ["unregister", mac] if plain(mac) => ("network/child-device/unregister", json!({"mac": mac})),
        ["whitelist", "get", mac] if plain(mac) => ("network/child-device/whitelist/get", json!({"mac": mac})),
        ["whitelist", "set", mac, hosts] if plain(mac) && plain(hosts) =>
            ("network/child-device/whitelist/set", json!({"mac": mac, "hosts": hosts})),
        ["whitelist", verb, ..] if *verb != "get" && *verb != "set" =>
            return Err("child-device-action-invalid".into()),
        ["observed" | "list" | "apply" | "register" | "unregister" | "whitelist", ..] => return Err(invalid()),
        _ => return Err("child-device-action-invalid".into()),
    };
    crate::routes::gate_receipts::stop_receipt(stop, fields)
}
pub fn command(args: &[String]) -> i32 {
    match invoke(args) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

use crate::gate::ApiErrorBody;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    Router,
};

async fn child_device_named_actuator_route(
    _headers: HeaderMap,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    // The exact mounted leaf is checked against its profile namespace, not its wire URL.
    if !crate::gate::roster_allows("POST", "settings/child-device").unwrap_or(false) {
        return Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-route-off-roster",
        ));
    }
    match crate::shared::policy::allows_command("staff intent") {
        Ok(true) => {
            let result = crate::gate::blocking_task("staff intent", move || command_json(metadata))
                .await?;
            result
                .map(|value| (crate::gate::mutation_status(&value), Json(value)))
                .map_err(|signal| crate::gate::api_error_signal("staff intent", &signal))
        }
        Ok(false) => Err(crate::gate::api_error("staff intent")),
        Err(_) => Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-carapace-desync",
        )),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/settings/child-device",
        axum::routing::post(child_device_named_actuator_route),
    )
}
