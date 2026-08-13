//! Fixed-path source-map reseed public membrane.
//!
//! The staff actuator owns boundary validation and the atomic splice.  This
//! band takes no certificate, source-map, component, or payload argument.

use serde_json::{json, Value};
use std::{env, process::Command};

const COMMAND: &str = "profile sources reseed";
const TARGET: &str = "profile-sources";
const LAUNCHER: &str = "/usr/local/sbin/agathodaimon/cli.py profile-sources-reseed";

fn launcher_command() -> String {
    env::var("CADUCEUS_PROFILE_SOURCES_RESEED_CMD").unwrap_or_else(|_| LAUNCHER.to_string())
}

pub fn reseed_json() -> Result<Value, String> {
    let output = Command::new(launcher_command())
        .arg("reseed")
        .output()
        .map_err(|err| format!("caduceus-source-map-reseed-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err("caduceus-source-map-reseed-empty".into());
    }
    let value: Value = serde_json::from_str(&stdout)
        .map_err(|_| "caduceus-source-map-reseed-invalid-json".to_string())?;
    if !output.status.success() || value.get("ok") != Some(&json!(true)) {
        return Err(value
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-source-map-reseed-failed")
            .to_string());
    }
    Ok(value)
}

pub fn command() -> i32 {
    match reseed_json() {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

pub const fn public_command() -> &'static str {
    COMMAND
}

pub const fn target() -> &'static str {
    TARGET
}
