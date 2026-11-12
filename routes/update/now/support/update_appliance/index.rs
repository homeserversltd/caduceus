use crate::shared::{config, harmonia, receipts};
use serde_json::{json, Value};
use std::time::Instant;

pub fn read_json() -> Result<Value, String> {
    let profile_ok = config::carapace().is_object();
    let state_present = config::harmonia_profile_index_path()
        .map(|profile_path| {
            let path = config::path(&profile_path);
            path.is_file() && std::fs::File::open(path).is_ok()
        })
        .unwrap_or(false);
    let route_ok = harmonia::route("update_now").is_ok();
    let first_missing_signal = if profile_ok && route_ok {
        "none"
    } else if !profile_ok {
        "caduceus-carapace-desync"
    } else {
        "caduceus-harmonia-route-missing:update_now"
    };
    Ok(json!({
        "schema": "caduceus.update.status.v1",
        "profilePresent": profile_ok,
        "statePresent": state_present,
        "routePresent": route_ok,
        "firstMissingSignal": first_missing_signal,
        "ok": profile_ok && route_ok
    }))
}

pub fn invoke_now_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    if dry_run {
        let flags: Vec<String> = rest
            .iter()
            .filter(|arg| *arg != "--dry-run")
            .cloned()
            .collect();
        let (code, body) = harmonia::invoke("update_now", &flags, true);
        return harmonia::invoke_body_to_json("update_now", code, &body);
    }

    let started = Instant::now();
    let response = harmonia::start_update_now_json();
    let receipt_body = match (
        response.get("state").and_then(Value::as_str),
        response.get("ok").and_then(Value::as_bool),
    ) {
        (Some("started"), _) | (Some("unknown"), Some(true)) => {
            let mut body =
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute=update_now\n".to_string();
            if let Some(invocation_id) = response.get("invocationId").and_then(Value::as_str) {
                body.push_str(&format!("correlation_id={invocation_id}\n"));
            }
            if let Some(signal) = response.get("firstMissingSignal").and_then(Value::as_str) {
                body.push_str(&format!("first_missing_signal={signal}\n"));
            }
            body
        }
        _ => response
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    };
    let _ = receipts::write_latest_with_duration(
        &receipt_body,
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    );
    response
}

pub fn invoke_check_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    if !dry_run {
        return crate::stats::run_update_check();
    }
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("update_check", &flags, dry_run);
    harmonia::invoke_body_to_json("update_check", code, &body)
}

fn update_timer_name() -> Result<String, String> {
    let profile = harmonia::load_profile_value()?;
    profile
        .get("services")
        .and_then(|services| services.get("update"))
        .and_then(|update| update.get("timer"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "caduceus-update-timer-missing".to_string())
}

const UPDATE_SERVICE_BAND: &str = "update/service";

pub(crate) fn service_bound(value: &Value) -> bool {
    value.get("schema").and_then(Value::as_str) == Some("caduceus.staff.receipt.v1")
        && value.pointer("/stop/noun").and_then(Value::as_str) == Some("update")
        && value.pointer("/stop/verb").and_then(Value::as_str) == Some("service")
}

pub(crate) fn service_native(action: &str, signal: &str, attempted: bool, step: &str) -> Value {
    let mut answer = json!({
        "schema": "caduceus.staff.receipt.v1", "stop": {"noun": "update", "verb": "service"},
        "observed": {"words": ["update", "service", action], "path": "update/service"},
        "could_change_to": if matches!(action, "on" | "off") { json!({"state": action}) } else { Value::Null },
        "attempt": {"attempted": attempted, "step": step},
        "final_receipt": {"ok": false, "firstMissingSignal": signal},
        "ok": false, "firstMissingSignal": signal
    });
    if action != "status" {
        answer["requestedState"] = if matches!(action, "on" | "off") { json!(action) } else { Value::Null };
        answer["mutation"] = if attempted { Value::Null } else { json!(false) };
    }
    answer
}

fn update_service_receipt(action: &str) -> (Value, bool) {
    match crate::gate::snake::crossing_path_with_timeout(
        UPDATE_SERVICE_BAND, &json!({"action": action}), std::time::Duration::from_secs(30),
    ) {
        Ok(walked) => match walked.get("receiptPayload") {
            Some(receipt) if receipt.is_object() => (receipt.clone(), true),
            _ => (service_native(action, "caduceus-snake-receipt-missing", true, "receipt"), false),
        },
        Err(signal) => {
            // The executor's error is only a string: it cannot distinguish a
            // pre-spawn refusal from a failure after the crossing started.
            let mut receipt = service_native(action, &signal, false, "crossing");
            receipt["attempt"]["attempted"] = Value::Null;
            if action != "status" {
                receipt["mutation"] = Value::Null;
            }
            (receipt, false)
        }
    }
}

fn enabled_state(receipt: &Value) -> Option<bool> {
    let enabled = receipt.get("enabled")?;
    if let Some(enabled) = enabled.as_bool() {
        return Some(enabled);
    }
    let state = enabled.as_str()?.trim().to_ascii_lowercase();
    match state.as_str() {
        "enabled" | "enabled-runtime" => Some(true),
        "disabled" | "masked" | "masked-runtime" | "linked" | "linked-runtime" | "static"
        | "alias" | "indirect" | "generated" | "transient" => Some(false),
        _ => None,
    }
}

fn known_active_state(state: &str) -> bool {
    matches!(
        state,
        "active"
            | "reloading"
            | "inactive"
            | "failed"
            | "activating"
            | "deactivating"
            | "maintenance"
            | "refreshing"
    )
}

fn active_state_from_output(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let state = line.strip_prefix("is-active stdout:")?.trim();
        let token = state.split_whitespace().next()?;
        known_active_state(token).then(|| token.to_string())
    })
}

fn timer_state(receipt: &Value) -> Option<String> {
    if let Some(state) = receipt.get("timerState").and_then(Value::as_str) {
        if known_active_state(state.trim()) {
            return Some(state.to_string());
        }
    }
    receipt
        .get("output")
        .and_then(Value::as_str)
        .and_then(active_state_from_output)
}

pub fn service_status_json() -> Result<Value, String> {
    if let Err(signal) = update_timer_name() {
        return Ok(service_native("status", &signal, false, "timer"));
    }
    let (receipt, crossed) = update_service_receipt("status");
    if !crossed { return Ok(receipt); }
    let mut response = receipt.clone();
    let enabled = enabled_state(&receipt);
    let timer_state = timer_state(&receipt);
    let first_missing_signal = if !service_bound(&receipt) {
        "caduceus-schema-desync"
    } else if enabled.is_none() {
        "caduceus-update-service-enabled-state-unobserved"
    } else if timer_state.is_none() {
        "caduceus-update-service-timer-state-unobserved"
    } else {
        "none"
    };
    if let Some(object) = response.as_object_mut() {
        object.entry("enabledBool").or_insert(json!(enabled));
        object.entry("timerState").or_insert(json!(timer_state));
        if first_missing_signal != "none" {
            object.entry("doorSignal").or_insert(json!(first_missing_signal));
        }
    }
    Ok(response)
}

pub fn service_toggle_json(state: &str, rest: &[String]) -> Result<Value, String> {
    if !matches!(state, "on" | "off") {
        return Ok(service_native("toggle", "caduceus-public-action-not-allowed", false, "policy"));
    }
    if let Err(signal) = update_timer_name() {
        return Ok(service_native(state, &signal, false, "timer"));
    }
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    if dry_run {
        return Ok(json!({
            "schema": "caduceus.staff.receipt.v1",
            "stop": {"noun": "update", "verb": "service"},
            "ok": true,
            "mutation": false,
            "requestedState": state,
            "firstMissingSignal": "none",
            "observed": {"words": ["update", "service", "toggle"], "path": "update/service"},
            "attempt": {"attempted": false, "step": "dry-run"},
            "final_receipt": {"ok": true, "firstMissingSignal": "none"},
            "could_change_to": {
                "band": UPDATE_SERVICE_BAND,
                "stdinPayload": {"action": state}
            }
        }));
    }

    let (mut response, crossed) = update_service_receipt(state);
    if !crossed { return Ok(response); }
    let enabled = enabled_state(&response);
    let timer = timer_state(&response);
    let signal = if !service_bound(&response) {
        "caduceus-schema-desync"
    } else if enabled.is_none() { "caduceus-update-service-enabled-state-unobserved" }
      else if timer.is_none() { "caduceus-update-service-timer-state-unobserved" }
      else { "none" };
    let mutation = if service_bound(&response) && response.get("ok").and_then(Value::as_bool) == Some(true) {
        Some(true)
    } else {
        None
    };
    if let Some(object) = response.as_object_mut() {
        object.entry("enabledBool").or_insert(json!(enabled));
        object.entry("timerState").or_insert(json!(timer));
        if signal != "none" {
            object.entry("doorSignal").or_insert(json!(signal));
        }
        object.entry("mutation").or_insert(json!(mutation));
        object.entry("requestedState").or_insert(json!(state));
    }
    Ok(response)
}

pub fn status() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.update.status.v1");
            println!("profile_present={}", value["profilePresent"]);
            println!("state_present={}", value["statePresent"]);
            println!("route_present={}", value["routePresent"]);
            println!("first_missing_signal={}", value["firstMissingSignal"]);
            if value["ok"].as_bool() == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("caduceus-update-status-failed: {err}");
            1
        }
    }
}

pub fn now(rest: &[String]) -> i32 {
    let value = invoke_now_json(rest);
    print_invoke_cli(&value);
    invoke_exit_code(&value)
}

pub fn check(rest: &[String]) -> i32 {
    let value = invoke_check_json(rest);
    print_invoke_cli(&value);
    invoke_exit_code(&value)
}

pub fn service_status() -> i32 {
    let value = service_status_json().unwrap_or_else(|signal| service_native("status", &signal, false, "status"));
    println!("schema={}", value.get("schema").and_then(Value::as_str).unwrap_or(""));
    println!("receipt={value}");
    if value["ok"].as_bool() == Some(true) && service_bound(&value) && value.get("doorSignal").is_none() { 0 } else { 1 }
}

pub fn service_toggle(state: &str, rest: &[String]) -> i32 {
    let value = service_toggle_json(state, rest).unwrap_or_else(|signal| service_native(state, &signal, false, "toggle"));
    let success = value["ok"].as_bool() == Some(true) && service_bound(&value) && value.get("doorSignal").is_none();
    if success {
        println!("schema={}", value["schema"].as_str().unwrap_or(""));
        println!("mutation={}", value["mutation"]);
        println!("receipt={value}");
        0
    } else {
        eprintln!("schema={}", value["schema"].as_str().unwrap_or(""));
        eprintln!("receipt={value}");
        1
    }
}

fn print_invoke_cli(value: &Value) {
    if let Some(body) = value.get("body").and_then(Value::as_str) {
        print!("{body}");
        return;
    }
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

fn invoke_exit_code(value: &Value) -> i32 {
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        0
    } else {
        1
    }
}
