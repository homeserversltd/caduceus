use crate::tools::{config, harmonia, receipts, systemd};
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

pub fn service_status_json() -> Result<Value, String> {
    let timer = update_timer_name()?;
    Ok(json!({
        "schema": "caduceus.update.service.status.v1",
        "timer": timer,
        "timerState": systemd::timer_status(&timer),
        "firstMissingSignal": "none",
        "ok": true
    }))
}

pub fn service_toggle_json(state: &str, rest: &[String]) -> Result<Value, String> {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    match state {
        "on" | "off" => {
            let body = format!(
                "schema=caduceus.update.service.toggle.v1\nmutation={}\nrequested_state={}\nfirst_missing_signal=none\n",
                !dry_run, state
            );
            if !dry_run {
                let _ = receipts::write_latest(&body);
            }
            Ok(json!({
                "schema": "caduceus.update.service.toggle.v1",
                "mutation": !dry_run,
                "requestedState": state,
                "firstMissingSignal": "none",
                "ok": true
            }))
        }
        _ => Err("caduceus-public-action-not-allowed".to_string()),
    }
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
            println!("first_missing_signal=none");
            0
        }
        Err(err) => {
            println!("schema=caduceus.update.service.status.v1");
            println!("timer_state=unknown");
            println!("first_missing_signal={err}");
            1
        }
    }
}

pub fn service_toggle(state: &str, rest: &[String]) -> i32 {
    match service_toggle_json(state, rest) {
        Ok(value) => {
            println!("schema=caduceus.update.service.toggle.v1");
            println!("mutation={}", value["mutation"]);
            println!("requested_state={}", value["requestedState"]);
            println!("first_missing_signal=none");
            0
        }
        Err(_) => {
            eprintln!("caduceus-public-action-not-allowed");
            2
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
