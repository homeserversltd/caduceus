// Canonical appliance log readback and clear doors.
//
// Every appliance speaks through one path.  The appliance profile identifies
// the speaker; this band never selects a body-specific fallback log.

use serde_json::{json, Value};
use std::{fs, io, path::Path};

pub const LOG_PATH: &str = "/var/log/appliance/appliance.log";
pub const DEFAULT_LIMIT: usize = 1000;
pub const MAX_LIMIT: usize = 5000;

pub fn read_json(offset: usize, limit: usize) -> Value {
    let limit = limit.min(MAX_LIMIT);
    match fs::read(LOG_PATH) {
        Ok(bytes) => {
            let file_size = bytes.len() as u64;
            let text = String::from_utf8_lossy(&bytes);
            let mut lines: Vec<String> = text.split_inclusive('\n').map(str::to_owned).collect();
            if text.is_empty() {
                lines.clear();
            }
            lines.reverse();
            let total_lines = lines.len();
            let selected: Vec<String> = lines.into_iter().skip(offset).take(limit).collect();
            json!({
                "schema": "caduceus.appliance.logs.read.v1",
                "status": "success",
                "ok": true,
                "lines": selected,
                "logs": selected,
                "offset": offset,
                "limit": limit,
                "returned_lines": selected.len(),
                "total_lines": total_lines,
                "file_size": file_size,
                "file_path": LOG_PATH,
                "firstMissingSignal": "none"
            })
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => missing_receipt("read"),
        Err(error) => failure_receipt("read", &error),
    }
}

pub fn clear_json() -> Value {
    match fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(LOG_PATH)
    {
        Ok(file) => match file.metadata() {
            Ok(metadata) => json!({
                "schema": "caduceus.appliance.logs.clear.v1",
                "status": "success",
                "ok": true,
                "message": "Logs cleared successfully",
                "cleared": true,
                "file_size": metadata.len(),
                "file_path": LOG_PATH,
                "firstMissingSignal": "none"
            }),
            Err(error) => failure_receipt("clear", &error),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => missing_receipt("clear"),
        Err(error) => failure_receipt("clear", &error),
    }
}

pub fn is_missing(value: &Value) -> bool {
    value.get("firstMissingSignal").and_then(Value::as_str)
        == Some("caduceus-appliance-log-missing")
}

pub fn is_failure(value: &Value) -> bool {
    value.get("ok").and_then(Value::as_bool) == Some(false) && !is_missing(value)
}

pub fn show(offset: usize, limit: usize) -> i32 {
    println!("{}", read_json(offset, limit));
    0
}

pub fn clear() -> i32 {
    let receipt = clear_json();
    let status = if receipt.get("ok").and_then(Value::as_bool) == Some(true) {
        0
    } else {
        1
    };
    println!("{receipt}");
    status
}

fn missing_receipt(action: &str) -> Value {
    json!({
        "schema": format!("caduceus.appliance.logs.{action}.v1"),
        "status": "error",
        "ok": false,
        "message": format!("Canonical appliance log is absent: {LOG_PATH}"),
        "lines": [],
        "logs": [],
        "total_lines": 0,
        "file_size": 0,
        "file_path": LOG_PATH,
        "firstMissingSignal": "caduceus-appliance-log-missing"
    })
}

fn failure_receipt(action: &str, error: &io::Error) -> Value {
    json!({
        "schema": format!("caduceus.appliance.logs.{action}.v1"),
        "status": "error",
        "ok": false,
        "message": format!("Canonical appliance log {action} failed: {error}"),
        "lines": [],
        "logs": [],
        "total_lines": 0,
        "file_size": Path::new(LOG_PATH).metadata().map(|metadata| metadata.len()).unwrap_or(0),
        "file_path": LOG_PATH,
        "firstMissingSignal": "caduceus-appliance-log-unavailable"
    })
}
