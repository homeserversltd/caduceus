use crate::tools::{config, harmonia, receipts};
use serde_json::{json, Value};
use std::path::Path;

const LLAMA_SERVER_BIN: &str = "/usr/local/bin/llama-server";
const LLAMA_CLI_BIN: &str = "/usr/local/bin/llama-cli";
const DEFAULT_RUNTIME_RECEIPT: &str =
    "/var/lib/harmonia/receipts/local-ai-runtime-latest/run.json";

fn runtime_receipt_path() -> String {
    harmonia::load_profile_value()
        .ok()
        .and_then(|profile| {
            profile
                .get("services")
                .and_then(|services| services.get("local_ai"))
                .and_then(|local_ai| local_ai.get("latest_receipt"))
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| DEFAULT_RUNTIME_RECEIPT.to_string())
}

fn binary_present(path: &str) -> bool {
    Path::new(path).is_file()
}

pub fn runtime_status_json() -> Result<Value, String> {
    let route_ok = harmonia::route("local_ai_update_now").is_ok();
    let server_present = binary_present(LLAMA_SERVER_BIN);
    let cli_present = binary_present(LLAMA_CLI_BIN);
    let receipt_path = runtime_receipt_path();
    let receipt = config::read_file_at(&receipt_path).ok();
    let receipt_ok = receipt
        .as_ref()
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| value.get("ok").and_then(Value::as_bool))
        .unwrap_or(false);
    let installed = server_present && cli_present;
    let first_missing_signal = if !route_ok {
        "caduceus-harmonia-route-missing:local_ai_update_now".to_string()
    } else if installed {
        "none".to_string()
    } else if receipt.is_some() && !receipt_ok {
        "local-ai-runtime-incomplete".to_string()
    } else {
        "local-ai-runtime-missing".to_string()
    };
    Ok(json!({
        "schema": "caduceus.local_ai.runtime.status.v1",
        "routePresent": route_ok,
        "installed": installed,
        "serverPresent": server_present,
        "cliPresent": cli_present,
        "receiptPresent": receipt.is_some(),
        "receiptOk": receipt_ok,
        "receiptPath": receipt_path,
        "firstMissingSignal": first_missing_signal,
        "ok": route_ok && installed
    }))
}

pub fn invoke_runtime_update_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("local_ai_update_now", &flags, dry_run);
    if !dry_run {
        let _ = receipts::write_latest(&body);
    }
    harmonia::invoke_body_to_json("local_ai_update_now", code, &body)
}

pub fn runtime_status() -> i32 {
    match runtime_status_json() {
        Ok(value) => {
            println!("schema=caduceus.local_ai.runtime.status.v1");
            println!("installed={}", value["installed"]);
            println!("route_present={}", value["routePresent"]);
            println!("first_missing_signal={}", value["firstMissingSignal"]);
            if value["ok"].as_bool() == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("caduceus-local-ai-runtime-status-failed: {err}");
            1
        }
    }
}

pub fn runtime_update(rest: &[String]) -> i32 {
    let value = invoke_runtime_update_json(rest);
    if let Some(body) = value.get("body").and_then(Value::as_str) {
        print!("{body}");
    } else {
        println!("schema={}", value.get("schema").and_then(Value::as_str).unwrap_or(""));
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