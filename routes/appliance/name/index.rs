// Staff-backed network device naming commands.

use serde_json::{json, Value};

fn invoke(band: &str, payload: Value) -> Result<Value, String> {
    crate::gate::snake::crossing_path_receipt(band, &payload)
}

pub fn command_admission(args: &[String]) -> Option<(&'static str, &'static str)> {
    match args {
        [verb, action, ..] if verb == "device-name" && action == "create" => Some((
            "network dns device-name create",
            "/api/dns/device-name/create",
        )),
        [verb, action, ..] if verb == "device-name" && action == "remove" => Some((
            "network dns device-name remove",
            "/api/dns/device-name/remove",
        )),
        [verb, action, ..] if verb == "alias" && action == "create" => {
            Some(("network dns alias create", "/api/dns/alias/create"))
        }
        [verb, action, ..] if verb == "alias" && action == "remove" => {
            Some(("network dns alias remove", "/api/dns/alias/remove"))
        }
        _ => None,
    }
}

pub fn command_json(args: &[String]) -> Result<Value, String> {
    match args {
        [verb, action, hostname_flag, hostname, ip_flag, ip]
            if verb == "device-name"
                && ["create", "remove"].contains(&action.as_str())
                && hostname_flag == "--hostname"
                && ip_flag == "--ip" =>
        {
            device_name_json(action, hostname, ip)
        }
        [verb, action, label_flag, label, hostname_flag, hostname]
            if verb == "alias"
                && ["create", "remove"].contains(&action.as_str())
                && label_flag == "--label"
                && hostname_flag == "--hostname" =>
        {
            alias_json(action, label, hostname)
        }
        [] => Err("caduceus-network-dns-command-missing".into()),
        _ => Err("caduceus-network-dns-command-invalid".into()),
    }
}

pub fn command(args: &[String]) -> i32 {
    match command_json(args) {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            if crate::gate::receipt_succeeded(&value) { 0 } else { 1 }
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

pub fn device_name_json(action: &str, hostname: &str, ip: &str) -> Result<Value, String> {
    if !["create", "remove"].contains(&action) {
        return Err("dns-verb-unknown".into());
    }
    if hostname.is_empty() || ip.is_empty() {
        return Err("caduceus-network-dns-device-name-invalid".into());
    }
    invoke(&format!("network/dns/device-name/{action}"), json!({"hostname": hostname, "ip": ip}))
}

pub fn device_name_create_json(
    hostname: &str,
    ip: Option<&str>,
    move_name: Option<bool>,
    adopt: Option<bool>,
) -> Result<Value, String> {
    if hostname.is_empty() || (ip.is_none_or(str::is_empty) && adopt != Some(true)) {
        return Err("caduceus-network-dns-device-name-invalid".into());
    }
    let mut payload = serde_json::Map::new();
    payload.insert("hostname".into(), json!(hostname));
    if let Some(ip) = ip {
        payload.insert("ip".into(), json!(ip));
    }
    if let Some(move_name) = move_name {
        payload.insert("move".into(), json!(move_name));
    }
    if let Some(adopt) = adopt {
        payload.insert("adopt".into(), json!(adopt));
    }
    invoke("network/dns/device-name/create", Value::Object(payload))
}

pub fn alias_json(action: &str, label: &str, hostname: &str) -> Result<Value, String> {
    if !["create", "remove"].contains(&action) {
        return Err("dns-verb-unknown".into());
    }
    if label.is_empty() || hostname.is_empty() {
        return Err("caduceus-network-dns-alias-invalid".into());
    }
    invoke(&format!("network/dns/alias/{action}"), json!({"label": label, "hostname": hostname}))
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
