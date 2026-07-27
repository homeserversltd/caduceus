//! Caduceus household-time band — bounded Rust face over `caduceus_staff.household_time`.
//!
//! The public read endpoint is only admitted from a LAN peer and only when a
//! future profile explicitly admits `time state`; time mutation commands are
//! likewise profile-gated, but this slice adds no appliance admission entries.

use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::{env, process::Command};

fn time_cmd() -> (String, Vec<String>) {
    if let Ok(command) = env::var("CADUCEUS_TIME_CMD") {
        let parts: Vec<String> = command.split_whitespace().map(str::to_string).collect();
        if let Some((program, prefix)) = parts.split_first() {
            return (program.clone(), prefix.to_vec());
        }
    }
    const SYSTEM_LAUNCHER: &str = "/usr/local/sbin/caduceus-household-time";
    if std::fs::metadata(SYSTEM_LAUNCHER)
        .map(|metadata| metadata.is_file() && metadata.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
    {
        return (SYSTEM_LAUNCHER.into(), vec![]);
    }
    if Command::new("sh")
        .args(["-c", "command -v caduceus-household-time >/dev/null 2>&1"])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
    {
        return ("caduceus-household-time".into(), vec![]);
    }
    (
        "python3".into(),
        vec!["-m".into(), "caduceus_staff.household_time".into()],
    )
}

pub fn invoke(args: &[String]) -> Result<Value, String> {
    let (program, prefix) = time_cmd();
    let output = Command::new(program)
        .args(prefix)
        .args(args)
        .output()
        .map_err(|err| format!("caduceus-household-time-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "caduceus-household-time-empty: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let value: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("caduceus-household-time-invalid-json: {err}"))?;
    if !output.status.success() || value.get("ok") == Some(&json!(false)) {
        return Err(format!(
            "caduceus-household-time-failed: {}",
            value
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .unwrap_or("nonzero-exit")
        ));
    }
    Ok(value)
}

pub fn state_json() -> Result<Value, String> {
    invoke(&["state".into()])
}

pub fn command(args: &[String]) -> i32 {
    match invoke(args) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegates_to_named_launcher_without_time_mutation_in_rust() {
        let root =
            std::env::temp_dir().join(format!("caduceus-time-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let log = root.join("args");
        let launcher = root.join("launcher");
        std::fs::write(&launcher, format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\nprintf '{{\"schema\":\"caduceus.household-time.receipt.v1\",\"ok\":true,\"primitive\":\"state\"}}\\n'\n",
            log.display()
        )).unwrap();
        let mut permissions = std::fs::metadata(&launcher).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&launcher, permissions).unwrap();
        std::env::set_var("CADUCEUS_TIME_CMD", launcher.to_str().unwrap());
        let state = state_json().unwrap();
        assert_eq!(state["primitive"], "state");
        assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "state");
        std::env::remove_var("CADUCEUS_TIME_CMD");
        let _ = std::fs::remove_dir_all(root);
    }
}
