use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

const CLI: &str = "/usr/local/sbin/agathodaimon/cli.py";

/// Cross the privileged agathodaimon Python CLI using its noun/verb grammar.
/// JSON is kept on stdin so the helper does not reinterpret command payloads.
pub(crate) fn crossing(noun: &str, verb: &str, input: &Value) -> Result<Value, String> {
    let cli = std::env::var("CADUCEUS_AGATHODAIMON_CLI").unwrap_or_else(|_| CLI.to_string());
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg(cli)
        .arg(noun)
        .arg(verb)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    let payload =
        serde_json::to_vec(input).map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    child
        .stdin
        .take()
        .ok_or_else(|| "caduceus-pin-not-yet-provisioned".to_string())?
        .write_all(&payload)
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    if !output.status.success() || value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(value
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-pin-not-yet-provisioned")
            .to_string());
    }
    Ok(value)
}
