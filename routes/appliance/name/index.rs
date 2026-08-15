// Staff-backed network device naming commands.

use serde_json::{json, Value};

fn invoke(args: &[String]) -> Result<Value, String> {
    crate::gate::snake::crossing_path("network/dns", &json!({"args": args}))
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
            0
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

pub fn device_name_json(action: &str, hostname: &str, ip: &str) -> Result<Value, String> {
    if !["create", "remove"].contains(&action) || hostname.is_empty() || ip.is_empty() {
        return Err("caduceus-network-dns-device-name-invalid".into());
    }
    invoke(&[
        "device-name".into(),
        action.into(),
        "--hostname".into(),
        hostname.into(),
        "--ip".into(),
        ip.into(),
    ])
}

pub fn alias_json(action: &str, label: &str, hostname: &str) -> Result<Value, String> {
    if !["create", "remove"].contains(&action) || label.is_empty() || hostname.is_empty() {
        return Err("caduceus-network-dns-alias-invalid".into());
    }
    invoke(&[
        "alias".into(),
        action.into(),
        "--label".into(),
        label.into(),
        "--hostname".into(),
        hostname.into(),
    ])
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
