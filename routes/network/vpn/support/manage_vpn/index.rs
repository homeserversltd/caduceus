use chrono::Utc;
use serde_json::{json, Value};
use std::fs;
use std::process::Command;

pub fn status_json() -> Result<Value, String> {
    let vpn_running = process_running("openvpn");
    let transmission_running = process_running("transmission");
    let is_enabled = Command::new("systemctl")
        .args(["is-enabled", "transmissionPIA.service"])
        .output()
        .map(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "enabled"
        })
        .unwrap_or(false);
    Ok(json!({
        "schema": "caduceus.vpn.status.v1",
        "ok": vpn_running && transmission_running,
        "vpnStatus": if vpn_running { "running" } else { "stopped" },
        "transmissionStatus": if transmission_running { "running" } else { "stopped" },
        "isEnabled": is_enabled,
        "timestamp": Utc::now().timestamp(),
        "firstMissingSignal": if !vpn_running {
            "caduceus-vpn-openvpn-stopped"
        } else if !transmission_running {
            "caduceus-vpn-transmission-stopped"
        } else {
            "none"
        },
    }))
}

fn process_running(needle: &str) -> bool {
    fs::read_dir("/proc")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_name()
                .to_str()
                .filter(|name| name.chars().all(|character| character.is_ascii_digit()))
                .map(|_| entry.path())
        })
        .any(|pid_path| {
            fs::read_to_string(pid_path.join("comm"))
                .map(|name| {
                    let name = name.trim();
                    name == needle || (needle == "transmission" && name.starts_with("transmission"))
                })
                .unwrap_or(false)
        })
}
