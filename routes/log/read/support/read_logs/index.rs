use crate::shared::hyalos::{self, LogFilters, DB_PATH};
use serde_json::{json, Value};

pub const LOG_PATH: &str = DB_PATH;
pub const DEFAULT_LIMIT: usize = 1000;
pub const MAX_LIMIT: usize = 5000;
const SCHEMA: &str = "caduceus.appliance.logs.read.v1";

pub fn read_json(offset: usize, limit: usize) -> Value {
    read_filtered(offset, limit, LogFilters::default())
}

pub(crate) fn read_filtered(offset: usize, limit: usize, filters: LogFilters) -> Value {
    let limit = limit.min(MAX_LIMIT);
    match hyalos::read_page(offset, limit, filters) {
        Ok(page) => {
            let lines: Vec<String> = page.rows.iter().map(|row| format!("{row}\n")).collect();
            json!({
                "schema": SCHEMA,
                "status": "success",
                "ok": true,
                "lines": lines,
                "logs": lines,
                "rows": page.rows,
                "offset": offset,
                "limit": limit,
                "returned_lines": lines.len(),
                "total_lines": page.total,
                "file_size": page.file_size,
                "file_path": LOG_PATH,
                "last_rotation_timestamp": null,
                "firstMissingSignal": "none",
            })
        }
        Err(signal) => json!({
            "schema": SCHEMA,
            "status": "error",
            "ok": false,
            "message": format!("Hyalos database read failed: {signal}"),
            "lines": [],
            "logs": [],
            "rows": [],
            "offset": offset,
            "limit": limit,
            "returned_lines": 0,
            "total_lines": 0,
            "file_size": 0,
            "file_path": LOG_PATH,
            "last_rotation_timestamp": null,
            "firstMissingSignal": "caduceus-appliance-log-unavailable",
        }),
    }
}

pub fn is_failure(value: &Value) -> bool {
    value.get("ok").and_then(Value::as_bool) == Some(false)
}

pub fn show(offset: usize, limit: usize) -> i32 {
    println!("{}", read_json(offset, limit));
    0
}
