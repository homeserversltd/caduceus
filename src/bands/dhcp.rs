//! Caduceus DHCP band — public Rust face over `caduceus_staff.network.dhcp`.

use serde_json::{json, Value};
use std::{env, process::Command};

fn dhcp_cmd() -> (String, Vec<String>) {
    if let Ok(command) = env::var("CADUCEUS_DHCP_CMD") {
        let parts: Vec<String> = command.split_whitespace().map(str::to_string).collect();
        if let Some((program, prefix)) = parts.split_first() {
            return (program.clone(), prefix.to_vec());
        }
    }
    if Command::new("sh")
        .args(["-c", "command -v caduceus-network-dhcp >/dev/null 2>&1"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
    {
        return ("caduceus-network-dhcp".into(), vec![]);
    }
    (
        "python3".into(),
        vec!["-m".into(), "caduceus_staff.network.dhcp".into()],
    )
}

pub fn invoke(args: &[String]) -> Result<Value, String> {
    let (program, prefix) = dhcp_cmd();
    let output = Command::new(program)
        .args(prefix)
        .args(args)
        .output()
        .map_err(|err| format!("caduceus-network-dhcp-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "caduceus-network-dhcp-empty: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("caduceus-network-dhcp-invalid-json: {err}"))?;
    if !output.status.success() || value.get("ok") == Some(&json!(false)) {
        return Err(format!(
            "caduceus-network-dhcp-failed: {}",
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
        return Err("caduceus-network-dhcp-command-missing".into());
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
            .map_err(|err| format!("caduceus-network-dhcp-metadata-invalid: {err}"))?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn fixture_executes_status_and_api_intent() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/staff");
        env::set_var("PYTHONPATH", fixture);
        env::set_var(
            "CADUCEUS_DHCP_CMD",
            "python3 -m caduceus_staff.network.dhcp",
        );
        let status = status_json().unwrap();
        assert_eq!(status["schema"], "caduceus.network.dhcp.status.v1");
        let intent = intent_json(
            "POST",
            "/api/dhcp/reservations",
            json!({"ip":"192.168.1.7"}),
        )
        .unwrap();
        assert_eq!(intent["classification"], "network-control");
        assert_eq!(intent["mutationPerformed"], true);
    }
}
