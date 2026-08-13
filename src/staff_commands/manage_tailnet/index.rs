use chrono::Utc;
use serde_json::{json, Value};
use std::fs;
use std::process::Command;

pub fn status_json() -> Result<Value, String> {
    let interface = fs::metadata("/sys/class/net/tailscale0").is_ok();
    if !interface {
        return Ok(status(
            "disconnected",
            false,
            false,
            "caduceus-tailscale-interface-missing",
        ));
    }

    let interface_up = Command::new("ip")
        .args(["-details", "address", "show", "tailscale0"])
        .output()
        .map(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("LOWER_UP")
        })
        .unwrap_or(false);

    let output = match Command::new("tailscale")
        .args(["status", "--json"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(_) => {
            return Ok(status(
                "disconnected",
                true,
                false,
                "caduceus-tailscale-inactive",
            ))
        }
        Err(_) => {
            return Ok(status(
                "disconnected",
                true,
                false,
                "caduceus-tailscale-cli-missing",
            ))
        }
    };
    let value: Value = match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(_) => {
            return Ok(status(
                "error",
                true,
                false,
                "caduceus-tailscale-status-invalid",
            ))
        }
    };
    let running = value.get("BackendState").and_then(Value::as_str) == Some("Running");
    let has_ipv4 = value
        .get("TailscaleIPs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|address| address.starts_with("100."));
    let connected = running && interface_up && has_ipv4;
    Ok(status(
        if connected {
            "connected"
        } else {
            "disconnected"
        },
        true,
        connected,
        if connected {
            "none"
        } else if !running {
            "caduceus-tailscale-inactive"
        } else if !interface_up {
            "caduceus-tailscale-interface-down"
        } else {
            "caduceus-tailscale-address-missing"
        },
    ))
}

fn status(state: &str, interface: bool, ok: bool, first_missing_signal: &str) -> Value {
    json!({
        "schema": "caduceus.tailscale.status.v1",
        "ok": ok,
        "status": state,
        "interface": interface,
        "timestamp": Utc::now().timestamp(),
        "firstMissingSignal": first_missing_signal,
    })
}
