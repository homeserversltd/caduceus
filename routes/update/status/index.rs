use crate::shared::config;
use serde_json::{json, Value};
use std::fs;

fn valid_module_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub fn toggle_json(module_id: &str, enabled: bool) -> Result<Value, String> {
    if !valid_module_id(module_id) {
        return Err("caduceus-profile-module-id-invalid".to_string());
    }
    let profile_path = config::harmonia_profile_index_path()?;
    let path = config::path(&profile_path);
    let text = fs::read_to_string(&path)
        .map_err(|err| format!("caduceus-harmonia-profile-unreadable:{err}"))?;
    let mut json_value: Value =
        serde_json::from_str(&text).map_err(|_| "caduceus-harmonia-profile-invalid".to_string())?;
    let modules = json_value
        .get_mut("modules")
        .and_then(|modules| modules.as_array_mut())
        .ok_or_else(|| "caduceus-harmonia-profile-modules-missing".to_string())?;
    let existing = modules.iter_mut().find(|module| {
        module.as_str() == Some(module_id)
            || module.get("id").and_then(Value::as_str) == Some(module_id)
    });
    match existing {
        Some(Value::Object(object)) => {
            object.insert("enabled".to_string(), Value::Bool(enabled));
        }
        Some(_) if !enabled => modules.retain(|module| module.as_str() != Some(module_id)),
        None if enabled => modules.push(Value::String(module_id.to_string())),
        _ => {}
    }
    let rendered = serde_json::to_string_pretty(&json_value)
        .map_err(|_| "caduceus-harmonia-profile-render-failed".to_string())?
        + "\n";
    fs::write(&path, rendered.as_bytes())
        .map_err(|err| format!("caduceus-harmonia-profile-write-failed:{err}"))?;
    Ok(json!({
        "schema": "caduceus.profile.module.toggle.v1",
        "ok": true,
        "moduleId": module_id,
        "enabled": enabled,
        "profilePath": profile_path,
        "firstMissingSignal": "none",
        "message": if enabled {
            format!("{module_id} enabled for the next Harmonia run.")
        } else {
            format!("{module_id} disabled for the next Harmonia run.")
        }
    }))
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
    match toggle_json(module_id, enabled) {
        Ok(value) => {
            println!("schema=caduceus.profile.module.toggle.v1");
            println!("ok=true");
            println!("module_id={module_id}");
            println!("enabled={enabled}");
            println!("first_missing_signal=none");
            if let Some(message) = value.get("message").and_then(Value::as_str) {
                println!("message={message}");
            }
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
