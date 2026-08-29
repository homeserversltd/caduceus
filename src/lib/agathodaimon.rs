use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const CLI: &str = "/usr/local/sbin/agathodaimon/cli.py";
const HOUSE_CA_LAUNCHER: &str = "/usr/local/sbin/caduceus-house-ca";
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_STDERR_BYTES: usize = 8 * 1024;

fn first_stderr_line(stderr: &[u8]) -> String {
    String::from_utf8_lossy(&stderr[..stderr.len().min(MAX_STDERR_BYTES)])
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .take(1024)
        .collect()
}

fn reflect_failure(noun: &str, verb: &str, class: &str, exit: Option<i32>, stderr: &str) {
    // Reflection is deliberately best effort: it must never replace the crossing result.
    let _ = crate::shared::hyalos::reflect_json(json!({
        "organ": "agathodaimon",
        "kind": "crossing-failure",
        "level": "error",
        "ok": false,
        "message": format!("agathodaimon crossing failed: {noun} {verb}"),
        "attributes_redacted": {
            "noun": noun,
            "verb": verb,
            "class": class,
            "exit": exit,
            "stderr": stderr,
        }
    }));
}

fn failure(
    noun: &str,
    verb: &str,
    class: &str,
    exit: Option<i32>,
    stderr: &str,
    signal: &str,
) -> Value {
    reflect_failure(noun, verb, class, exit, stderr);
    json!({
        "ok": false,
        "noun": noun,
        "verb": verb,
        "class": class,
        "exit": exit,
        "stderr": stderr,
        "firstMissingSignal": signal,
    })
}

fn failure_from_value(
    noun: &str,
    verb: &str,
    class: &str,
    exit: Option<i32>,
    stderr: &str,
    mut value: Value,
) -> Value {
    reflect_failure(noun, verb, class, exit, stderr);
    if let Some(object) = value.as_object_mut() {
        object.insert("class".into(), Value::String(class.to_string()));
        object.insert("exit".into(), exit.map_or(Value::Null, |code| json!(code)));
        object.insert("stderr".into(), Value::String(stderr.to_string()));
        if noun == "cert" && verb == "house-ca" {
            object
                .entry("firstMissingSignal")
                .or_insert_with(|| Value::String("caduceus-house-ca-refused".to_string()));
        }
        return value;
    }
    let signal = if noun == "cert" && verb == "house-ca" {
        "caduceus-house-ca-refused"
    } else {
        "caduceus-pin-not-yet-provisioned"
    };
    json!({
        "ok": false,
        "error": value,
        "noun": noun,
        "verb": verb,
        "class": class,
        "exit": exit,
        "stderr": stderr,
        "firstMissingSignal": signal,
    })
}

fn args(input: &Value) -> impl Iterator<Item = &str> {
    input
        .get("args")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn run_command(
    mut command: Command,
    noun: &str,
    verb: &str,
    input: &Value,
    write_input: bool,
) -> Result<Value, Value> {
    let mut child = command
        .stdin(if write_input {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            failure(
                noun,
                verb,
                "spawn",
                None,
                &err.to_string(),
                "caduceus-pin-not-yet-provisioned",
            )
        })?;
    if write_input {
        let payload = serde_json::to_vec(input).map_err(|err| {
            failure(
                noun,
                verb,
                "stdin",
                None,
                &err.to_string(),
                "caduceus-pin-not-yet-provisioned",
            )
        })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            failure(
                noun,
                verb,
                "stdin",
                None,
                "",
                "caduceus-pin-not-yet-provisioned",
            )
        })?;
        if let Err(err) = stdin.write_all(&payload) {
            return Err(failure(
                noun,
                verb,
                "stdin",
                None,
                &err.to_string(),
                "caduceus-pin-not-yet-provisioned",
            ));
        }
        drop(stdin);
    }
    let output = child.wait_with_output().map_err(|err| {
        failure(
            noun,
            verb,
            "exit",
            None,
            &err.to_string(),
            "caduceus-pin-not-yet-provisioned",
        )
    })?;
    let exit = output.status.code();
    let stderr = first_stderr_line(&output.stderr);
    if output.stdout.len() > MAX_OUTPUT_BYTES {
        return Err(failure(
            noun,
            verb,
            "parse",
            exit,
            &stderr,
            "firewall-staff-output-too-large",
        ));
    }
    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        if !output.status.success() {
            failure(
                noun,
                verb,
                "exit",
                exit,
                &stderr,
                "caduceus-pin-not-yet-provisioned",
            )
        } else {
            failure(
                noun,
                verb,
                "parse",
                exit,
                &stderr,
                "caduceus-pin-not-yet-provisioned",
            )
        }
    })?;
    if !output.status.success() {
        return Err(failure_from_value(noun, verb, "exit", exit, &stderr, value));
    }
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(failure_from_value(noun, verb, "exit", exit, &stderr, value));
    }
    Ok(value)
}

/// Cross the privileged agathodaimon Python CLI using its noun/verb grammar.
/// JSON is kept on stdin so the helper does not reinterpret command payloads.
pub(crate) fn crossing_value(noun: &str, verb: &str, input: &Value) -> Result<Value, Value> {
    for (selector, variable) in [
        (noun == "time", "CADUCEUS_TIME_CMD"),
        (noun == "network" && verb == "dns", "CADUCEUS_DNS_CMD"),
    ] {
        if selector {
            if let Ok(command_line) = std::env::var(variable) {
                let parts: Vec<String> = command_line
                    .split_whitespace()
                    .map(str::to_string)
                    .collect();
                if let Some((program, prefix)) = parts.split_first() {
                    let mut command = Command::new(program);
                    command.args(prefix);
                    if noun == "time" {
                        command.arg(verb);
                    }
                    command.args(args(input));
                    return run_command(command, noun, verb, input, false);
                }
            }
        }
    }
    let cli = std::env::var("CADUCEUS_AGATHODAIMON_CLI").unwrap_or_else(|_| CLI.to_string());
    let override_cli = std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some();
    let mut command = if override_cli {
        let mut command = Command::new(&cli);
        command.args([noun, verb]);
        command
    } else if noun == "cert" && verb == "house-ca" {
        let mut command = Command::new("/usr/bin/sudo");
        command.args(["-n", HOUSE_CA_LAUNCHER]);
        command.args(args(input));
        command
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.args(["-n", &cli, noun, verb]);
        command
    };
    run_command(command, noun, verb, input, true)
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
