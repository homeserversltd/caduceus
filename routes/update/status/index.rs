use serde_json::{json, Value};

fn valid_module_id(id: &str) -> bool {
    id.len() <= 64
        && id.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && id.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub fn staff_list() -> Result<Value, String> {
    staff_call(json!({"args": ["list"]}))
}

fn staff_call(payload: Value) -> Result<Value, String> {
    let receipt = crate::gate::snake::crossing_path_receipt("update/module-toggle", &payload)?;
    if let Some(signal) = receipt.get("doorSignal").and_then(Value::as_str) {
        return Err(signal.to_string());
    }
    if receipt.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(receipt.get("firstMissingSignal").and_then(Value::as_str)
            .unwrap_or("caduceus-agathodaimon-refused").to_string());
    }
    Ok(receipt)
}

pub fn toggle_staff(module_id: &str, enabled: bool) -> Result<Value, String> {
    if !valid_module_id(module_id) {
        return Err("caduceus-profile-module-id-invalid".to_string());
    }
    staff_call(json!({"args": [module_id, if enabled { "on" } else { "off" }]}))
}

pub fn toggle(module_id: &str, state: &str) -> i32 {
    let enabled = match state {
        "on" => true,
        "off" => false,
        _ => {
            eprintln!("caduceus-public-action-not-allowed");
            return 2;
        }
    };
    match toggle_staff(module_id, enabled) {
        Ok(_) => {
            println!("schema=caduceus.profile.module.toggle.v1");
            println!("ok=true");
            println!("module_id={module_id}");
            println!("enabled={enabled}");
            println!("first_missing_signal=none");
            println!("message={module_id} {} for the next Harmonia run.", if enabled { "enabled" } else { "disabled" });
            0
        }
        Err(err) => {
            eprintln!("caduceus-profile-module-toggle-failed: {err}");
            1
        }
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/update/status",
            axum::routing::get(crate::routes::update_support::update_status_route),
        )
}
