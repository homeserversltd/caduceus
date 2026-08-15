// Caduceus speedtest band — runs the speedtest-cli package installed into
// the Caduceus staff venv and returns a typed Mbps/ms projection.

use serde_json::{json, Value};
use std::{env, process::Command};

fn speedtest_python() -> String {
    env::var("CADUCEUS_SPEEDTEST_PYTHON")
        .unwrap_or_else(|_| "/var/lib/caduceus/venv/bin/python3".to_string())
}

pub fn run_json() -> Result<Value, String> {
    let program = speedtest_python();
    let output = Command::new(&program)
        .args(["-m", "speedtest", "--json"])
        .output()
        .map_err(|err| format!("caduceus-network-speedtest-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() || stdout.is_empty() {
        return Err(format!(
            "caduceus-network-speedtest-failed: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let raw: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("caduceus-network-speedtest-invalid-json: {err}"))?;
    let download_bps = raw
        .get("download")
        .and_then(Value::as_f64)
        .ok_or("caduceus-network-speedtest-download-missing")?;
    let upload_bps = raw
        .get("upload")
        .and_then(Value::as_f64)
        .ok_or("caduceus-network-speedtest-upload-missing")?;
    let ping_ms = raw
        .get("ping")
        .and_then(Value::as_f64)
        .ok_or("caduceus-network-speedtest-ping-missing")?;
    Ok(json!({
        "schema": "caduceus.network.speedtest.v1",
        "ok": true,
        "download": (download_bps / 1_000_000.0 * 10.0).round() / 10.0,
        "upload": (upload_bps / 1_000_000.0 * 10.0).round() / 10.0,
        "latency": (ping_ms * 10.0).round() / 10.0,
        "mutationPerformed": false,
        "firstMissingSignal": "none"
    }))
}

async fn http() -> Result<axum::Json<Value>, (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> { crate::gate::gated_json("network speedtest", run_json).await }

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/network/bandwidth/measure", axum::routing::get(http))
}
