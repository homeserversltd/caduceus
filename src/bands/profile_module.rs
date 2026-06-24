use crate::tools::harmonia;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

fn harmonia_profile_path() -> Result<String, String> {
    let profile = harmonia::load_profile_value()?;
    profile
        .get("harmonia_profile")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "caduceus-harmonia-profile-missing".to_string())
}

fn valid_module_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
        })
}

pub fn toggle_json(module_id: &str, enabled: bool) -> Result<Value, String> {
    if !valid_module_id(module_id) {
        return Err("caduceus-profile-module-id-invalid".to_string());
    }
    let profile_path = harmonia_profile_path()?;
    let path = Path::new(&profile_path);
    let text = fs::read_to_string(path)
        .map_err(|err| format!("caduceus-harmonia-profile-unreadable:{err}"))?;
    let mut json_value: Value = serde_json::from_str(&text)
        .map_err(|_| "caduceus-harmonia-profile-invalid".to_string())?;
    let modules = json_value
        .get_mut("modules")
        .and_then(|modules| modules.as_array_mut())
        .ok_or_else(|| "caduceus-harmonia-profile-modules-missing".to_string())?;
    let had_module = modules
        .iter()
        .any(|module| module.as_str() == Some(module_id));
    if enabled && !had_module {
        modules.push(Value::String(module_id.to_string()));
    } else if !enabled {
        modules.retain(|module| module.as_str() != Some(module_id));
    }
    let rendered = serde_json::to_string_pretty(&json_value)
        .map_err(|_| "caduceus-harmonia-profile-render-failed".to_string())?
        + "\n";
    let backup_path = path.with_extension("index.json.caduceus-bak");
    let _ = fs::write(&backup_path, text.as_bytes());
    fs::write(path, rendered.as_bytes())
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