//! Typed firewall delegation: Rust owns admission; staff owns host mutation.
use serde_json::Value;
use std::{
    env,
    io::{Read, Write},
    process::{Command, Stdio},
};

const LAUNCHER: &str = "/usr/local/sbin/agathodaimon/caduceus-network-firewall";
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

fn launcher() -> String {
    // Test override is a single absolute launcher path, never a shell command.
    env::var("CADUCEUS_FIREWALL_LAUNCHER")
        .ok()
        .filter(|path| path.starts_with('/') && !path.contains('\0'))
        .unwrap_or_else(|| LAUNCHER.to_string())
}

pub fn invoke(intent: Value) -> Result<Value, Value> {
    let encoded = match serde_json::to_vec(&intent) {
        Ok(value) => value,
        Err(_) => {
            return Err(
                serde_json::json!({"ok":false,"firstMissingSignal":"firewall-intent-invalid"}),
            )
        }
    };
    let mut child = match Command::new(launcher())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => {
            return Err(
                serde_json::json!({"ok":false,"firstMissingSignal":"firewall-staff-unavailable"}),
            )
        }
    };
    if child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(&encoded))
        .map_or(true, |result| result.is_err())
    {
        return Err(
            serde_json::json!({"ok":false,"firstMissingSignal":"firewall-staff-unavailable"}),
        );
    }
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return Err(
                serde_json::json!({"ok":false,"firstMissingSignal":"firewall-staff-unavailable"}),
            )
        }
    };
    // Drain concurrently so a noisy launcher cannot deadlock behind its pipe;
    // retain at most the protocol's 64 KiB custody limit.
    let reader = std::thread::spawn(move || -> Result<(Vec<u8>, bool), ()> {
        let mut stdout = stdout;
        let mut retained = Vec::new();
        let mut buffer = [0_u8; 8192];
        let mut oversized = false;
        loop {
            let count = stdout.read(&mut buffer).map_err(|_| ())?;
            if count == 0 {
                break;
            }
            let remaining = MAX_OUTPUT_BYTES
                .saturating_add(1)
                .saturating_sub(retained.len());
            let copied = count.min(remaining);
            retained.extend_from_slice(&buffer[..copied]);
            oversized |= count > copied || retained.len() > MAX_OUTPUT_BYTES;
        }
        Ok((retained, oversized))
    });
    let output = match child.wait() {
        Ok(output) => output,
        Err(_) => {
            return Err(
                serde_json::json!({"ok":false,"firstMissingSignal":"firewall-staff-unavailable"}),
            )
        }
    };
    let (stdout, oversized) = match reader.join() {
        Ok(Ok(value)) => value,
        _ => {
            return Err(
                serde_json::json!({"ok":false,"firstMissingSignal":"firewall-staff-unavailable"}),
            )
        }
    };
    if oversized {
        return Err(
            serde_json::json!({"ok":false,"firstMissingSignal":"firewall-staff-output-too-large"}),
        );
    }
    let value: Value = match serde_json::from_slice::<Value>(&stdout) {
        Ok(value) if value.is_object() => value,
        _ => {
            return Err(
                serde_json::json!({"ok":false,"firstMissingSignal":"firewall-staff-invalid-json"}),
            )
        }
    };
    if output.success() && value.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(value)
    } else {
        let signal = value
            .get("firstMissingSignal")
            .or_else(|| value.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("firewall-staff-refused")
            .to_string();
        let mut body = value;
        body["ok"] = Value::Bool(false);
        if body.get("firstMissingSignal").is_none() {
            body["firstMissingSignal"] = Value::String(signal);
        }
        Err(body)
    }
}

pub fn command_json(intent: Value) -> Result<Value, Value> {
    invoke(intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
    #[test]
    fn delegates_exact_stdin_without_shell_split() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("firewall-fixture-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let log = root.join("stdin");
        let script = root.join("staff");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\ncat > {}\nprintf '{{\"ok\":true}}\\n'\n",
                log.display()
            ),
        )
        .unwrap();
        let mut p = fs::metadata(&script).unwrap().permissions();
        p.set_mode(0o755);
        fs::set_permissions(&script, p).unwrap();
        env::set_var("CADUCEUS_FIREWALL_LAUNCHER", script.to_str().unwrap());
        let result = invoke(serde_json::json!({"action":"status"})).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(fs::read_to_string(log).unwrap(), "{\"action\":\"status\"}");
        env::remove_var("CADUCEUS_FIREWALL_LAUNCHER");
        let _ = fs::remove_dir_all(root);
    }
}
