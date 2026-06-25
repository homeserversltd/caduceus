use crate::tools::{harmonia, receipts};
use serde_json::{json, Value};

pub fn read_json() -> Result<Value, String> {
    match harmonia::route("sync_now") {
        Ok(_) => Ok(json!({
            "schema": "caduceus.sync.status.v1",
            "routePresent": true,
            "firstMissingSignal": "none",
            "ok": true
        })),
        Err(err) => Ok(json!({
            "schema": "caduceus.sync.status.v1",
            "routePresent": false,
            "firstMissingSignal": err,
            "ok": false
        })),
    }
}

pub fn invoke_now_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("sync_now", &flags, dry_run);
    if !dry_run {
        let _ = receipts::write_latest(&body);
    }
    harmonia::invoke_body_to_json("sync_now", code, &body)
}

pub fn status() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.sync.status.v1");
            println!("route_present={}", value["routePresent"]);
            println!("first_missing_signal={}", value["firstMissingSignal"]);
            if value["ok"].as_bool() == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("caduceus-sync-status-failed: {err}");
            1
        }
    }
}

pub fn now(rest: &[String]) -> i32 {
    let value = invoke_now_json(rest);
    if let Some(body) = value.get("body").and_then(Value::as_str) {
        print!("{body}");
    } else {
        println!(
            "schema={}",
            value.get("schema").and_then(Value::as_str).unwrap_or("")
        );
        if let Some(route) = value.get("route").and_then(Value::as_str) {
            println!("route={route}");
        }
        if let Some(ok) = value.get("ok") {
            println!("ok={ok}");
        }
        if let Some(signal) = value.get("firstMissingSignal").and_then(Value::as_str) {
            println!("first_missing_signal={signal}");
        }
    }
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        0
    } else {
        1
    }
}
