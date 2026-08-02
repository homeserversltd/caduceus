//! Caduceus network-DNS band — public Rust face over
//! `caduceus_staff.network.dns`.
//!
//! This band deliberately delegates execution to the staff launcher/module. It
//! does not touch Unbound, DNS sockets, or UFW itself.

use serde_json::{json, Value};
use std::{
    env,
    io::Write,
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
        vec!["-m".into(), "caduceus_staff.network.dns".into()],
    )
}

pub fn invoke(intent: &Value) -> Result<Value, String> {
    let (program, prefix) = dns_cmd();
    let encoded = serde_json::to_vec(intent)
        .map_err(|err| format!("caduceus-network-dns-intent-invalid: {err}"))?;
    let mut child = Command::new(program)
        .args(prefix)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("caduceus-network-dns-unavailable: {err}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "caduceus-network-dns-stdin-unavailable".to_string())?
        .write_all(&encoded)
        .map_err(|err| format!("caduceus-network-dns-stdin-failed: {err}"))?;
    let output = child
        .wait_with_output()
        .map_err(|err| format!("caduceus-network-dns-wait-failed: {err}"))?;
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
                .or_else(|| value.get("error"))
                .and_then(Value::as_str)
                .unwrap_or("nonzero-exit")
        ));
    }
    Ok(value)
}

pub fn command_json(args: &[String]) -> Result<Value, String> {
    match args {
        [verb] if verb == "status" => status_json(),
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
    invoke(&json!({"action":"status"}))
}

pub fn intent_json(method: &str, route: &str, metadata: Value) -> Result<Value, String> {
    if method != DNS_INTENT_METHOD || route != DNS_INTENT_ROUTE {
        return Err("caduceus-network-dns-intent-route-refused".into());
    }
    invoke(&metadata)
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
        assert_eq!(result["schema"], "caduceus.network.dns.intent.v1");
        assert_eq!(std::fs::read_to_string(args_log).unwrap(), "");
        let forwarded: Value =
            serde_json::from_str(&std::fs::read_to_string(stdin_log).unwrap()).unwrap();
        assert_eq!(forwarded, json!({"dryRun":true}));
        std::env::remove_var("CADUCEUS_DNS_CMD");
        let _ = std::fs::remove_dir_all(root);
    }
}
