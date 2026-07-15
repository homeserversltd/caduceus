//! Caduceus network-DNS band — public Rust face over
//! `caduceus_staff.network.dns`.
//!
//! This band deliberately delegates execution to the staff launcher/module. It
//! does not touch Unbound, DNS sockets, or UFW itself.

use serde_json::{json, Value};
use std::{env, process::Command};

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
        vec!["-m".into(), "caduceus_staff.network.dns".into()],
    )
}

pub fn invoke(args: &[String]) -> Result<Value, String> {
    let (program, prefix) = dns_cmd();
    let output = Command::new(program)
        .args(prefix)
        .args(args)
        .output()
        .map_err(|err| format!("caduceus-network-dns-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "caduceus-network-dns-empty: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("caduceus-network-dns-invalid-json: {err}"))?;
    if !output.status.success() || value.get("ok") == Some(&json!(false)) {
        return Err(format!(
            "caduceus-network-dns-failed: {}",
            value
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .unwrap_or("nonzero-exit")
        ));
    }
    Ok(value)
}

pub fn command_json(args: &[String]) -> Result<Value, String> {
    if args.is_empty() {
        return Err("caduceus-network-dns-command-missing".into());
    }
    invoke(args)
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

pub fn intent_json(method: &str, route: &str, metadata: Value) -> Result<Value, String> {
    invoke(&[
        "intent".into(),
        method.into(),
        route.into(),
        "--metadata-json".into(),
        serde_json::to_string(&metadata)
            .map_err(|err| format!("caduceus-network-dns-metadata-invalid: {err}"))?,
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
        let log = root.join("args");
        let script = root.join("staff-dns");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\nprintf '{{\"schema\":\"caduceus.network.dns.intent.v1\",\"ok\":true,\"mutationPerformed\":false}}\\n'\n",
                log.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        std::env::set_var("CADUCEUS_DNS_CMD", script.to_str().unwrap());
        let result =
            intent_json("POST", "/api/dns/unbound/drop-in", json!({"dryRun":true})).unwrap();
        assert_eq!(result["schema"], "caduceus.network.dns.intent.v1");
        assert!(std::fs::read_to_string(log)
            .unwrap()
            .contains("intent POST /api/dns/unbound/drop-in"));
        std::env::remove_var("CADUCEUS_DNS_CMD");
        let _ = std::fs::remove_dir_all(root);
    }
}
