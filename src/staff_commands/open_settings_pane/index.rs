use crate::shared::agathodaimon;
use serde_json::Value;

pub fn invoke_update_now_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let input = serde_json::json!({"args": flags, "dryRun": dry_run});
    match agathodaimon::crossing_value("gui", "update", &input) {
        Ok(value) => value,
        Err(value) => value,
    }
}

pub fn update_now(rest: &[String]) -> i32 {
    let value = invoke_update_now_json(rest);
    if let Some(body) = value.get("body").and_then(Value::as_str) {
        print!("{body}");
    } else {
        println!(
            "schema={}",
            value.get("schema").and_then(Value::as_str).unwrap_or("")
        );
        if let Some(ok) = value.get("ok") {
            println!("ok={ok}");
        }
    }
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        0
    } else {
        1
    }
}
