use crate::tools::{harmonia, receipts};
use serde_json::Value;

pub fn invoke_update_now_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("gui_update_now", &flags, dry_run);
    if !dry_run {
        let _ = receipts::write_latest(&body);
    }
    harmonia::invoke_body_to_json("gui_update_now", code, &body)
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
