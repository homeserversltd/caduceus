use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{config, policy};
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};

pub const NAMESPACE: &str = "update/history";
const COMMAND: &str = "update history";
const LOG_PATH: &str = "var/log/appliance/appliance.log";
const MAX_SCAN_BYTES: u64 = 1024 * 1024;
const CHUNK_BYTES: usize = 4096;
const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_RUNS: usize = 10;
const SCHEMA: &str = "caduceus.update.history.v1";

fn is_run_profile_kind(kind: &str) -> bool {
    let kind = kind.strip_prefix("schema=").unwrap_or(kind);
    matches!(kind, "harmonia.run_profile" | "schemaharmonia.run_profile")
        || ["harmonia.run_profile.v", "schemaharmonia.run_profile.v"]
            .iter()
            .any(|prefix| {
                kind.strip_prefix(prefix).is_some_and(|version| {
                    !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
}

fn string_field<'a>(record: &'a Value, attributes: Option<&'a Value>, field: &str) -> Option<&'a str> {
    record
        .get(field)
        .and_then(Value::as_str)
        .or_else(|| attributes.and_then(|value| value.get(field)).and_then(Value::as_str))
}

fn is_integer(value: &Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}

fn integer_field(record: &Value, attributes: Option<&Value>, field: &str) -> Value {
    record
        .get(field)
        .filter(|value| is_integer(value))
        .or_else(|| {
            attributes
                .and_then(|value| value.get(field))
                .filter(|value| is_integer(value))
        })
        .cloned()
        .unwrap_or(Value::Null)
}

fn array_field<'a>(record: &'a Value, attributes: Option<&'a Value>, field: &str) -> Option<&'a Vec<Value>> {
    record
        .get(field)
        .and_then(Value::as_array)
        .or_else(|| attributes.and_then(|value| value.get(field)).and_then(Value::as_array))
}

fn project_run(record: &Value) -> Option<Value> {
    let kind = record.get("kind").and_then(Value::as_str)?;
    if !is_run_profile_kind(kind) {
        return None;
    }
    let attributes = record.get("attributes_redacted");
    let run_id = string_field(record, attributes, "run_id")
        .or_else(|| string_field(record, attributes, "correlation_id"))?;
    if run_id.is_empty() {
        return None;
    }
    let outcome = string_field(record, attributes, "outcome")
        .map(str::to_ascii_lowercase)
        .and_then(|value| match value.as_str() {
            "ok" | "success" => Some("ok"),
            "failed" | "failure" => Some("failed"),
            _ => None,
        });
    let finished_at = string_field(record, attributes, "finished_at")
        .or_else(|| string_field(record, attributes, "timestamp"));
    let failures = array_field(record, attributes, "failures")
        .into_iter()
        .flatten()
        .filter_map(|failure| {
            let module = failure.get("module")?.as_str()?;
            let signal = failure.get("signal")?.as_str()?;
            Some(json!({"module": module, "signal": signal}))
        })
        .collect::<Vec<_>>();
    Some(json!({
        "run_id": run_id,
        "profile": string_field(record, attributes, "profile"),
        "finished_at": finished_at,
        "outcome": outcome,
        "duration_ms": integer_field(record, attributes, "duration_ms"),
        "module_count": integer_field(record, attributes, "module_count"),
        "updated_count": integer_field(record, attributes, "updated_count"),
        "failures": failures
    }))
}

fn consume_line(
    reversed_line: &mut Vec<u8>,
    oversized: &mut bool,
    runs: &mut Vec<Value>,
) {
    if !*oversized && runs.len() < MAX_RUNS && !reversed_line.is_empty() {
        reversed_line.reverse();
        if reversed_line.last() == Some(&b'\r') {
            reversed_line.pop();
        }
        if let Ok(record) = serde_json::from_slice::<Value>(reversed_line) {
            if let Some(run) = project_run(&record) {
                runs.push(run);
            }
        }
    }
    reversed_line.clear();
    *oversized = false;
}

fn read_runs() -> Result<Vec<Value>, &'static str> {
    let path = config::path(LOG_PATH);
    let mut file = File::open(&path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            "caduceus-update-history-log-missing"
        } else {
            "caduceus-update-history-log-unreadable"
        }
    })?;
    let mut position = file
        .metadata()
        .map_err(|_| "caduceus-update-history-log-unreadable")?
        .len();
    let mut scanned = 0_u64;
    let mut reversed_line = Vec::with_capacity(256);
    let mut oversized = false;
    let mut runs = Vec::with_capacity(MAX_RUNS);

    while position > 0 && scanned < MAX_SCAN_BYTES {
        let count = position
            .min(CHUNK_BYTES as u64)
            .min(MAX_SCAN_BYTES - scanned) as usize;
        let start = position - count as u64;
        file.seek(SeekFrom::Start(start))
            .map_err(|_| "caduceus-update-history-log-unreadable")?;
        let mut chunk = vec![0_u8; count];
        file.read_exact(&mut chunk)
            .map_err(|_| "caduceus-update-history-log-unreadable")?;
        for byte in chunk.iter().rev() {
            if *byte == b'\n' {
                consume_line(&mut reversed_line, &mut oversized, &mut runs);
            } else if !oversized {
                if reversed_line.len() < MAX_LINE_BYTES {
                    reversed_line.push(*byte);
                } else {
                    reversed_line.clear();
                    oversized = true;
                }
            }
        }
        position = start;
        scanned += count as u64;
    }
    if position == 0 {
        consume_line(&mut reversed_line, &mut oversized, &mut runs);
    }
    Ok(runs)
}

fn history_json() -> Value {
    match read_runs() {
        Ok(runs) => json!({"ok": true, "schema": SCHEMA, "runs": runs}),
        Err(signal) => json!({
            "ok": false,
            "schema": SCHEMA,
            "runs": [],
            "firstMissingSignal": signal
        }),
    }
}

pub(crate) async fn route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(COMMAND) {
        Ok(true) => Ok(Json(history_json())),
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/update/history", axum::routing::get(route))
}
