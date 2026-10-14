use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const CLI: &str = "/usr/local/sbin/agathodaimon/cli.py";
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

fn reflect_failure(
    noun: &str,
    verb: &str,
    outcome: &str,
    signal: &str,
    first_missing_field: Option<&str>,
    duration_ms: u64,
    record_failure: bool,
) {
    // Public bundle reads are observational and must not emit Hyalos writes.
    if !record_failure || (noun == "cert" && verb == "house-ca") {
        return;
    }
    // Reflection is deliberately best effort: it must never replace the crossing result.
    let _ = crate::shared::hyalos::reflect_json(json!({
        "organ": "agathodaimon",
        "kind": "crossing-failure",
        "level": "error",
        "ok": false,
        "message": "agathodaimon crossing failed",
        "attributes_redacted": {
            "who": "agathodaimon",
            "verb": verb,
            "target": noun,
            "outcome": outcome,
            "duration_ms": duration_ms,
            "signal": signal,
            "first_missing_field": first_missing_field,
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
    duration_ms: u64,
    record_failure: bool,
) -> Value {
    reflect_failure(
        noun,
        verb,
        "failure",
        signal,
        None,
        duration_ms,
        record_failure,
    );
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
    duration_ms: u64,
    record_failure: bool,
) -> Value {
    let signal = value
        .get("firstMissingSignal")
        .and_then(Value::as_str)
        .unwrap_or(if noun == "cert" && verb == "house-ca" {
            "caduceus-house-ca-refused"
        } else {
            "caduceus-agathodaimon-cli-refused"
        });
    let first_missing_field = value
        .get("firstMissingField")
        .or_else(|| value.get("field"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    reflect_failure(
        noun,
        verb,
        "failure",
        signal,
        first_missing_field.as_deref(),
        duration_ms,
        record_failure,
    );
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
        "caduceus-agathodaimon-cli-response-not-object"
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

fn record_staff_refusal(
    noun: &str,
    verb: &str,
    value: &Value,
    duration_ms: u64,
    record_failure: bool,
) {
    let signal = value
        .get("firstMissingSignal")
        .or_else(|| value.get("first_missing_signal"))
        .and_then(Value::as_str)
        .unwrap_or("caduceus-agathodaimon-cli-refused");
    let first_missing_field = value
        .get("firstMissingField")
        .or_else(|| value.get("field"))
        .and_then(Value::as_str);
    reflect_failure(
        noun,
        verb,
        "failure",
        signal,
        first_missing_field,
        duration_ms,
        record_failure,
    );
}

fn elapsed_ms(started: &std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
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
    record_failure: bool,
    preserve_staff_receipt: bool,
) -> Result<Value, Value> {
    let started = std::time::Instant::now();
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
                "caduceus-agathodaimon-cli-unavailable",
                elapsed_ms(&started),
                record_failure,
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
                "caduceus-agathodaimon-cli-input-serialization-failed",
                elapsed_ms(&started),
                record_failure,
            )
        })?;
        let mut stdin = child.stdin.take().ok_or_else(|| {
            failure(
                noun,
                verb,
                "stdin",
                None,
                "",
                "caduceus-agathodaimon-cli-stdin-unavailable",
                elapsed_ms(&started),
                record_failure,
            )
        })?;
        if let Err(err) = stdin.write_all(&payload) {
            return Err(failure(
                noun,
                verb,
                "stdin",
                None,
                &err.to_string(),
                "caduceus-agathodaimon-cli-stdin-write-failed",
                elapsed_ms(&started),
                record_failure,
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
            "caduceus-agathodaimon-cli-wait-failed",
            elapsed_ms(&started),
            record_failure,
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
            elapsed_ms(&started),
            record_failure,
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
                "caduceus-agathodaimon-cli-nonzero-output-invalid-json",
                elapsed_ms(&started),
                record_failure,
            )
        } else {
            failure(
                noun,
                verb,
                "parse",
                exit,
                &stderr,
                "caduceus-agathodaimon-cli-output-invalid-json",
                elapsed_ms(&started),
                record_failure,
            )
        }
    })?;
    if !output.status.success() {
        if preserve_staff_receipt {
            record_staff_refusal(
                noun,
                verb,
                &value,
                elapsed_ms(&started),
                record_failure,
            );
            return Ok(value);
        }
        return Err(failure_from_value(
            noun,
            verb,
            "exit",
            exit,
            &stderr,
            value,
            elapsed_ms(&started),
            record_failure,
        ));
    }
    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        if preserve_staff_receipt {
            record_staff_refusal(
                noun,
                verb,
                &value,
                elapsed_ms(&started),
                record_failure,
            );
            return Ok(value);
        }
        return Err(failure_from_value(
            noun,
            verb,
            "exit",
            exit,
            &stderr,
            value,
            elapsed_ms(&started),
            record_failure,
        ));
    }
    Ok(value)
}

fn is_read_crossing(noun: &str, verb: &str, input: &Value) -> bool {
    matches!(
        verb,
        "status"
            | "list"
            | "get"
            | "poll"
            | "observe"
            | "health"
            | "inspect"
            | "validate"
            | "query"
            | "read"
            | "show"
            | "check"
    ) || (noun == "settings" && args(input).next() == Some("get"))
}

/// Cross the privileged agathodaimon Python CLI using its noun/verb grammar.
/// JSON is kept on stdin so the helper does not reinterpret command payloads.
pub(crate) fn crossing_value(noun: &str, verb: &str, input: &Value) -> Result<Value, Value> {
    crossing_value_with_record(noun, verb, input, !is_read_crossing(noun, verb, input))
}

pub(crate) fn crossing_value_with_record(
    noun: &str,
    verb: &str,
    input: &Value,
    record_failure: bool,
) -> Result<Value, Value> {
    crossing_value_mode(noun, verb, input, record_failure, false)
}

/// Cross while returning parsed staff refusals without changing their receipt body.
pub(crate) fn crossing_value_preserving_receipt(
    noun: &str,
    verb: &str,
    input: &Value,
    record_failure: bool,
) -> Result<Value, Value> {
    crossing_value_mode(noun, verb, input, record_failure, true)
}

fn crossing_value_mode(
    noun: &str,
    verb: &str,
    input: &Value,
    record_failure: bool,
    preserve_staff_receipt: bool,
) -> Result<Value, Value> {
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
                    return run_command(
                        command,
                        noun,
                        verb,
                        input,
                        false,
                        record_failure,
                        preserve_staff_receipt,
                    );
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
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.args(["-n", &cli, noun, verb]);
        command
    };
    run_command(
        command,
        noun,
        verb,
        input,
        true,
        record_failure,
        preserve_staff_receipt,
    )
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
