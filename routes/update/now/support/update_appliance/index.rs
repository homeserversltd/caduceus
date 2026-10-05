use crate::shared::{config, harmonia, receipts, systemd};
use serde_json::{json, Value};

pub fn read_json() -> Result<Value, String> {
    let profile_ok = config::public_profile_present();
    let state = config::read_public_file("var/lib/caduceus/state.json")
        .unwrap_or_else(|_| "{}".to_string());
    let route_ok = harmonia::route("update_now").is_ok();
    let first_missing_signal = if profile_ok && route_ok {
        "none"
    } else if !profile_ok {
        "caduceus-profile-missing"
    } else {
        "caduceus-harmonia-route-missing:update_now"
    };
    Ok(json!({
        "schema": "caduceus.update.status.v1",
        "profilePresent": profile_ok,
        "statePresent": state != "{}",
        "routePresent": route_ok,
        "firstMissingSignal": first_missing_signal,
        "ok": profile_ok && route_ok
    }))
}

pub fn invoke_now_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("update_now", &flags, dry_run);
    if !dry_run {
        let _ = receipts::write_latest(&body);
    }
    harmonia::invoke_body_to_json("update_now", code, &body)
}

pub fn invoke_check_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("update_check", &flags, dry_run);
    if !dry_run {
        let _ = receipts::write_latest(&body);
    }
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

fn update_service_receipt(action: &str) -> Result<Value, String> {
    let receipt =
        crate::gate::snake::crossing_path(UPDATE_SERVICE_BAND, &json!({"action": action}))?;
    if receipt.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(receipt)
    } else {
        Err(receipt
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-update-service-refused")
            .to_string())
    }
}

fn update_service_response(receipt: Value, schema: &str, timer: &str) -> Value {
    let mut response = receipt.as_object().cloned().unwrap_or_default();
    response.insert("schema".to_string(), json!(schema));
    response.insert("timer".to_string(), json!(timer));
    response.entry("enabled".to_string()).or_insert(Value::Null);
    response.entry("active".to_string()).or_insert(Value::Null);
    response.entry("output".to_string()).or_insert(Value::Null);
    response
        .entry("firstMissingSignal".to_string())
        .or_insert(json!("none"));
    response.entry("ok".to_string()).or_insert(json!(true));
    Value::Object(response)
}

pub fn service_status_json() -> Result<Value, String> {
    let timer = update_timer_name()?;
    let receipt = update_service_receipt("status")?;
    let mut response =
        update_service_response(receipt, "caduceus.update.service.status.v1", &timer);
    response["timerState"] = json!(systemd::timer_status(&timer));
    Ok(response)
}

pub fn service_toggle_json(state: &str, rest: &[String]) -> Result<Value, String> {
    if !matches!(state, "on" | "off") {
        return Err("caduceus-public-action-not-allowed".to_string());
    }
    let timer = update_timer_name()?;
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    if dry_run {
        return Ok(json!({
            "schema": "caduceus.update.service.toggle.v1",
            "ok": true,
            "timer": timer,
            "mutation": false,
            "requestedState": state,
            "enabled": null,
            "active": null,
            "output": null,
            "firstMissingSignal": "none",
            "plan": {
                "band": UPDATE_SERVICE_BAND,
                "stdinPayload": {"action": state}
            }
        }));
    }

    let receipt = update_service_receipt(state)?;
    let mut response =
        update_service_response(receipt, "caduceus.update.service.toggle.v1", &timer);
    response["mutation"] = json!(true);
    response["requestedState"] = json!(state);
    let receipt_body = response.to_string();
    let _ = receipts::write_latest(&receipt_body);
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
    match service_status_json() {
        Ok(value) => {
            println!("schema=caduceus.update.service.status.v1");
            println!("timer={}", value["timer"]);
            println!("timer_state={}", value["timerState"]);
            println!("enabled={}", value["enabled"]);
            println!("active={}", value["active"]);
            println!("ok={}", value["ok"]);
            println!("first_missing_signal={}", value["firstMissingSignal"]);
            if value["ok"].as_bool() == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            println!("schema=caduceus.update.service.status.v1");
            println!("timer_state=unknown");
            println!("enabled=unknown");
            println!("active=unknown");
            println!("ok=false");
            println!("first_missing_signal={err}");
            1
        }
    }
}

pub fn service_toggle(state: &str, rest: &[String]) -> i32 {
    match service_toggle_json(state, rest) {
        Ok(value) => {
            println!("schema=caduceus.update.service.toggle.v1");
            println!("ok={}", value["ok"]);
            println!("mutation={}", value["mutation"]);
            println!("requested_state={}", value["requestedState"]);
            if let Some(timer) = value.get("timer").and_then(Value::as_str) {
                println!("timer={timer}");
            }
            if let Some(plan) = value.get("plan") {
                println!("band={}", plan["band"]);
                println!("stdin_payload={}", plan["stdinPayload"]);
            }
            println!("enabled={}", value["enabled"]);
            println!("active={}", value["active"]);
            println!("output={}", value["output"]);
            println!("first_missing_signal={}", value["firstMissingSignal"]);
            0
        }
        Err(signal) => {
            eprintln!("schema=caduceus.update.service.toggle.v1");
            eprintln!("ok=false");
            eprintln!("first_missing_signal={signal}");
            1
        }
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

// Bounded asynchronous press of Harmonia update invocation membrane.

use std::sync::{Mutex, OnceLock};

const RUN_LOCK: &str = "harmonia-update-in-flight";

fn run_active() -> &'static Mutex<bool> {
    static RUN_ACTIVE: OnceLock<Mutex<bool>> = OnceLock::new();
    RUN_ACTIVE.get_or_init(|| Mutex::new(false))
}

pub fn start_json() -> Result<Value, &'static str> {
    let mut active = run_active()
        .lock()
        .map_err(|_| "caduceus-harmonia-update-lock-unavailable")?;
    if *active {
        return Err(RUN_LOCK);
    }

    *active = true;
    std::thread::spawn(move || {
        let _ = invoke_now_json(&[]);
        if let Ok(mut active) = run_active().lock() {
            *active = false;
        }
    });

    Ok(json!({
        "ok": true,
        "action": "harmonia-update",
        "state": "started",
        "runLock": RUN_LOCK
    }))
}
