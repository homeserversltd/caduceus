//! Public Caduceus membrane for the staff-owned child-device actuator.
use serde_json::Value;
use std::{env, process::Command};

const LAUNCHER: &str = "/usr/local/sbin/caduceus-child-device";

fn launcher_command() -> (String, Vec<String>) {
    if let Ok(path) = env::var("CADUCEUS_CHILD_DEVICE_LAUNCHER") {
        if path.starts_with('/') && !path.contains('\0') {
            return (path, vec![]);
        }
    }
    (LAUNCHER.into(), vec![])
}

pub fn invoke(args: &[String]) -> Result<Value, String> {
    if args.is_empty() {
        return Err("child-device-command-missing".into());
    }
    let (program, prefix) = launcher_command();
    let output = Command::new(program)
        .args(prefix)
        .args(args)
        .output()
        .map_err(|err| format!("child-device-staff-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "child-device-staff-empty: status={}",
            output.status
        ));
    }
    let value: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("child-device-staff-invalid-json: {err}"))?;
    if !output.status.success() || value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(format!(
            "child-device-staff-refused: {}",
            value
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .unwrap_or("nonzero-exit")
        ));
    }
    Ok(value)
}

pub fn command(args: &[String]) -> i32 {
    match invoke(args) {
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
