use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};

const CLI: &str = "/usr/local/sbin/agathodaimon/cli.py";
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Cross the privileged agathodaimon Python CLI using its noun/verb grammar.
/// JSON is kept on stdin so the helper does not reinterpret command payloads.
pub(crate) fn crossing_value(noun: &str, verb: &str, input: &Value) -> Result<Value, Value> {
    if noun == "time" {
        if let Ok(command) = std::env::var("CADUCEUS_TIME_CMD") {
            let parts: Vec<String> = command.split_whitespace().map(str::to_string).collect();
            if let Some((program, prefix)) = parts.split_first() {
                let args = input
                    .get("args")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str);
                let output = Command::new(program).args(prefix).arg(verb).args(args).output().map_err(|_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}))?;
                let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}))?;
                return if output.status.success()
                    && value.get("ok").and_then(Value::as_bool) == Some(true)
                {
                    Ok(value)
                } else {
                    Err(value)
                };
            }
        }
    }
    if noun == "network" && verb == "dns" {
        if let Ok(command) = std::env::var("CADUCEUS_DNS_CMD") {
            let parts: Vec<String> = command.split_whitespace().map(str::to_string).collect();
            if let Some((program, prefix)) = parts.split_first() {
                let args = input
                    .get("args")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str);
                let output = Command::new(program).args(prefix).args(args).output().map_err(|_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}))?;
                let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}))?;
                return if output.status.success()
                    && value.get("ok").and_then(Value::as_bool) == Some(true)
                {
                    Ok(value)
                } else {
                    Err(value)
                };
            }
        }
    }
    let cli = std::env::var("CADUCEUS_AGATHODAIMON_CLI").unwrap_or_else(|_| CLI.to_string());
    let override_cli = std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some();
    let mut command = if override_cli {
        let mut command = Command::new(&cli);
        command.args([noun, verb]);
        command
    } else {
        let mut command = Command::new("sudo");
        command.args(["-n", &cli, noun, verb]);
        command
    };
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}))?;
    let payload = serde_json::to_vec(input).map_err(
        |_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}),
    )?;
    child
        .stdin
        .take()
        .ok_or_else(|| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}))?
        .write_all(&payload)
        .map_err(|_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}))?;
    let output = child.wait_with_output().map_err(
        |_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}),
    )?;
    if output.stdout.len() > MAX_OUTPUT_BYTES {
        return Err(
            serde_json::json!({"ok":false,"firstMissingSignal":"firewall-staff-output-too-large"}),
        );
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(
        |_| serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-pin-not-yet-provisioned"}),
    )?;
    if !output.status.success() || value.get("ok").and_then(Value::as_bool) != Some(true) {
        if value.get("ok").is_none() {
            return Err(
                serde_json::json!({"ok": false, "error": value.get("error").cloned().unwrap_or(value)}),
            );
        }
        return Err(if noun == "cert" && verb == "house-ca" {
            let mut mapped = value;
            if mapped.get("firstMissingSignal").is_none() {
                mapped["firstMissingSignal"] = serde_json::json!("caduceus-house-ca-refused");
            }
            mapped
        } else {
            value
        });
    }
    Ok(value)
}

/// Cross the same membrane while preserving the staff refusal envelope.
pub(crate) fn crossing(noun: &str, verb: &str, input: &Value) -> Result<Value, String> {
    crossing_value(noun, verb, input).map_err(|value| {
        value
            .get("firstMissingSignal")
            .or_else(|| value.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("caduceus-pin-not-yet-provisioned")
            .to_string()
    })
}
