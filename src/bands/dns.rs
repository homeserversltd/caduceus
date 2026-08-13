//! Caduceus network-DNS band — public Rust face over
//! `agathodaimon.network.dns`.
//!
//! This band deliberately delegates execution to the staff launcher/module. It
//! does not touch Unbound, DNS sockets, or UFW itself.

use serde_json::{json, Value};
use std::{
    env,
    process::{Command, Stdio},
};

const DNS_INTENT_METHOD: &str = "POST";
const DNS_INTENT_ROUTE: &str = "/api/dns/unbound/drop-in";

fn dns_cmd() -> (String, Vec<String>) {
    if let Ok(command) = env::var("CADUCEUS_DNS_CMD") {
        let parts: Vec<String> = command.split_whitespace().map(str::to_string).collect();
        if let Some((program, prefix)) = parts.split_first() {
            return (program.clone(), prefix.to_vec());
        }
    }
    if Command::new("sh")
        .args(["-c", "command -v caduceus-network-dns >/dev/null 2>&1"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
    {
        return ("caduceus-network-dns".into(), vec![]);
    }
    (
        "python3".into(),
        vec!["-m".into(), "agathodaimon.network.dns".into()],
    )
}

fn public_receipt(value: Value) -> Value {
    // The staff receipt remains authoritative, but its paths and command output
    // do not cross the Rust public membrane.
    let primitive = value
        .get("actuator")
        .or_else(|| value.get("action"))
        .cloned()
        .unwrap_or_else(|| json!("network.dns"));
    let reload = value
        .get("reload")
        .or_else(|| value.get("reload_outcome"))
        .or_else(|| value.pointer("/verification/reload_outcome"))
        .cloned()
        .unwrap_or_else(|| json!("not-run"));
    let proof = json!({
        "stagedValidation": value.get("stagedValidation").cloned().unwrap_or(Value::Null),
        "liveValidation": value.get("liveValidation").cloned().unwrap_or(Value::Null),
        "rollback": value.get("rollback").cloned().unwrap_or(Value::Null),
        "restorationVerified": value.get("restoration_verified").cloned().unwrap_or(Value::Null),
        "state": value.get("state").cloned().unwrap_or(Value::Null),
    });
    json!({
        "schema": "caduceus.network.dns.public_receipt.v1",
        "ok": value.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "primitive": primitive,
        "changed": value.get("mutationPerformed").or_else(|| value.get("changed")).and_then(Value::as_bool).unwrap_or(false),
        "reloadOutcome": reload,
        "proof": proof,
        "firstMissingSignal": value.get("firstMissingSignal").or_else(|| value.get("error")).cloned().unwrap_or_else(|| json!("none")),
    })
}

fn invoke(args: &[String]) -> Result<Value, String> {
    let (program, prefix) = dns_cmd();
    let output = Command::new(program)
        .args(prefix)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("caduceus-network-dns-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let value: Value = serde_json::from_str(&stdout)
        .map_err(|_| "caduceus-network-dns-invalid-receipt".to_string())?;
    if !output.status.success() || value.get("ok") == Some(&json!(false)) {
        return Err(value
            .get("firstMissingSignal")
            .or_else(|| value.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("caduceus-network-dns-failed")
            .to_string());
    }
    Ok(public_receipt(value))
}

pub fn command_admission(args: &[String]) -> Option<(&'static str, &'static str)> {
    match args {
        [verb] if verb == "status" => Some(("network dns status", "/api/dns/status")),
        [verb] if verb == "read" => Some(("network dns read", "/api/dns/read")),
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
        [verb, ..] if verb == "intent" => Some(("network dns intent", "/api/dns/unbound/drop-in")),
        _ => None,
    }
}

pub fn command_json(args: &[String]) -> Result<Value, String> {
    match args {
        [verb] if verb == "status" => status_json(),
        [verb] if verb == "read" => read_json(),
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
        [verb, method, route, flag, metadata] if verb == "intent" && flag == "--metadata-json" => {
            let metadata = serde_json::from_str(metadata)
                .map_err(|err| format!("caduceus-network-dns-metadata-invalid: {err}"))?;
            intent_json(method, route, metadata)
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

pub fn status_json() -> Result<Value, String> {
    invoke(&["status".into()])
}

pub fn read_json() -> Result<Value, String> {
    invoke(&["read".into()])
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

pub fn resolver_json(action: &str, metadata: Option<Value>) -> Result<Value, String> {
    if !["adblock", "blocklist-update", "upstream"].contains(&action) {
        return Err("caduceus-network-dns-resolver-action-invalid".into());
    }
    let mut args = vec!["resolver".into(), action.into()];
    if let Some(metadata) = metadata {
        args.push("--metadata-json".into());
        args.push(
            serde_json::to_string(&metadata)
                .map_err(|_| "caduceus-network-dns-metadata-invalid")?,
        );
    }
    invoke(&args)
}

pub fn intent_json(method: &str, route: &str, metadata: Value) -> Result<Value, String> {
    if method != DNS_INTENT_METHOD || route != DNS_INTENT_ROUTE {
        return Err("caduceus-network-dns-intent-route-refused".into());
    }
    let metadata = serde_json::to_string(&metadata)
        .map_err(|err| format!("caduceus-network-dns-metadata-invalid: {err}"))?;
    invoke(&[
        "intent".into(),
        method.into(),
        route.into(),
        "--metadata-json".into(),
        metadata,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    #[test]
    fn delegates_status_and_intent_without_touching_dns() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("dns-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let args_log = root.join("args");
        let stdin_log = root.join("stdin");
        let script = root.join("staff-dns");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s' \"$*\" > {}\ncat > {}\nprintf '{{\"schema\":\"caduceus.network.dns.intent.v1\",\"ok\":true,\"mutationPerformed\":false}}\\n'\n",
                args_log.display(),
                stdin_log.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        std::env::set_var("CADUCEUS_DNS_CMD", script.to_str().unwrap());
        let result =
            intent_json("POST", "/api/dns/unbound/drop-in", json!({"dryRun":true})).unwrap();
        assert_eq!(result["schema"], "caduceus.network.dns.public_receipt.v1");
        assert_eq!(
            std::fs::read_to_string(args_log).unwrap(),
            "intent POST /api/dns/unbound/drop-in --metadata-json {\"dryRun\":true}"
        );
        assert_eq!(std::fs::read_to_string(stdin_log).unwrap(), "");
        std::env::remove_var("CADUCEUS_DNS_CMD");
        let _ = std::fs::remove_dir_all(root);
    }
}
