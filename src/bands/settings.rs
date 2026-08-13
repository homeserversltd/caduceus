//! Profile-gated GTK settings doors over fixed staff launchers.
//!
//! Each family owns one sbin launcher. Rust validates the family and field
//! allowlist, then delegates config-file string manipulation to the staff
//! actuator. Successful mutations must return a receipt rooted in the shared
//! Caduceus ledger.

use crate::bands::staff;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::process::{Command, Output};

pub const FAMILIES: &[&str] = &[
    "display",
    "appearance",
    "sound",
    "input",
    "notifications",
    "default-apps",
    "datetime",
];
const RECEIPT_ROOT: &str = "/var/lib/caduceus/receipts/";

fn fields(family: &str) -> Option<&'static [&'static str]> {
    match family {
        "display" => Some(&[
            "resolution",
            "refresh_rate",
            "scale",
            "orientation",
            "brightness",
            "night_light",
        ]),
        "appearance" => Some(&[
            "color_scheme",
            "accent_color",
            "wallpaper",
            "icon_theme",
            "cursor_theme",
            "font",
        ]),
        "sound" => Some(&[
            "output_device",
            "input_device",
            "volume",
            "input_volume",
            "muted",
        ]),
        "input" => Some(&[
            "keyboard_layout",
            "keyboard_variant",
            "key_repeat",
            "repeat_delay_ms",
            "repeat_interval_ms",
            "natural_scroll",
            "tap_to_click",
            "pointer_speed",
        ]),
        "notifications" => Some(&[
            "enabled",
            "do_not_disturb",
            "show_banners",
            "show_on_lock_screen",
            "sound_enabled",
        ]),
        "default-apps" => Some(&[
            "browser",
            "mail",
            "calendar",
            "music",
            "video",
            "photos",
            "text_editor",
            "terminal",
            "file_manager",
        ]),
        "datetime" => Some(&[
            "timezone",
            "ntp_enabled",
            "automatic_timezone",
            "date_format",
            "time_format",
        ]),
        _ => None,
    }
}

pub fn read_command(family: &str) -> Option<String> {
    fields(family).map(|_| format!("settings {family} read"))
}
pub fn mutate_command(family: &str) -> Option<String> {
    fields(family).map(|_| format!("settings {family} mutate"))
}
fn actuator_id(family: &str) -> String {
    format!("settings-{family}")
}

fn launcher(family: &str) -> Result<String, String> {
    let id = actuator_id(family);
    let profile = staff::profile_json()?;
    profile
        .get("actuators")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("id").and_then(Value::as_str) == Some(&id))
        })
        .and_then(|item| item.get("launcher"))
        .and_then(Value::as_str)
        .filter(|value| {
            value.starts_with("/usr/local/sbin/agathodaimon/caduceus-settings-") && !value.contains('\0')
        })
        .map(str::to_string)
        .ok_or_else(|| format!("caduceus-settings-actuator-missing:{id}"))
}

fn run(family: &str, args: &[String]) -> Result<Value, String> {
    let id = actuator_id(family);
    let output = Command::new(launcher(family)?)
        .args(args)
        .env("CADUCEUS_STAFF_ACTUATOR_ID", &id)
        .env("CADUCEUS_RECEIPT_ROOT", RECEIPT_ROOT.trim_end_matches('/'))
        .output()
        .map_err(|err| format!("caduceus-settings-launcher-unavailable:{id}:{err}"))?;
    decode_output(&id, output)
}

fn decode_output(id: &str, output: Output) -> Result<Value, String> {
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| format!("caduceus-settings-invalid-receipt:{id}"))?;
    if !output.status.success() || value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(value
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-settings-staff-refused")
            .to_string());
    }
    Ok(value)
}

fn bounded_value(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => true,
        Value::String(value) => value.len() <= 4096 && !value.contains('\0'),
        Value::Array(values) => {
            values.len() <= 32
                && values.iter().all(|value| {
                    matches!(value, Value::Null | Value::Bool(_) | Value::Number(_))
                        || value
                            .as_str()
                            .is_some_and(|text| text.len() <= 1024 && !text.contains('\0'))
                })
        }
        Value::Object(_) => false,
    }
}

fn validated_fields(family: &str, body: Value) -> Result<BTreeMap<String, Value>, String> {
    let allowed = fields(family).ok_or_else(|| "caduceus-settings-family-invalid".to_string())?;
    let object = body
        .as_object()
        .ok_or_else(|| "caduceus-settings-fields-object-required".to_string())?;
    if object.is_empty() {
        return Err("caduceus-settings-fields-empty".to_string());
    }
    let mut values = BTreeMap::new();
    for (field, value) in object {
        if !allowed.contains(&field.as_str()) {
            return Err(format!("caduceus-settings-field-not-allowed:{field}"));
        }
        if !bounded_value(value) {
            return Err(format!("caduceus-settings-value-invalid:{field}"));
        }
        values.insert(field.clone(), value.clone());
    }
    Ok(values)
}

pub fn read_json(family: &str) -> Result<Value, String> {
    fields(family).ok_or_else(|| "caduceus-settings-family-invalid".to_string())?;
    let receipt = run(family, &["get".into(), "--json".into()])?;
    let values = receipt
        .get("values")
        .and_then(Value::as_object)
        .ok_or_else(|| "caduceus-settings-read-values-missing".to_string())?;
    let allowed = fields(family).unwrap();
    if values
        .keys()
        .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err("caduceus-settings-read-field-not-allowed".to_string());
    }
    Ok(
        json!({"schema":"caduceus.settings.read.v1","ok":true,"family":family,"values":values,"firstMissingSignal":"none"}),
    )
}

pub fn mutate_json(family: &str, body: Value) -> Result<Value, String> {
    let values = validated_fields(family, body)?;
    let mut args = vec!["set".to_string()];
    for (field, value) in &values {
        args.extend([
            "--field".to_string(),
            field.clone(),
            "--value-json".to_string(),
            serde_json::to_string(value)
                .map_err(|_| "caduceus-settings-value-invalid".to_string())?,
        ]);
    }
    let receipt = run(family, &args)?;
    let receipt_path = receipt
        .get("receiptPath")
        .and_then(Value::as_str)
        .filter(|path| path.starts_with(RECEIPT_ROOT) && path.ends_with("/run.json"))
        .ok_or_else(|| "caduceus-settings-receipt-path-invalid".to_string())?;
    Ok(
        json!({"schema":"caduceus.settings.mutation.v1","ok":true,"family":family,"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(true),"fields":values.keys().collect::<Vec<_>>(),"receiptPath":receipt_path,"receipt":receipt,"firstMissingSignal":"none"}),
    )
}

pub fn command(family: &str, args: &[String]) -> i32 {
    let result = match args {
        [verb] if verb == "read" => read_json(family),
        [verb, json] if verb == "mutate" => serde_json::from_str(json)
            .map_err(|_| "caduceus-settings-json-invalid".to_string())
            .and_then(|body| mutate_json(family, body)),
        _ => Err("caduceus-settings-command-invalid".to_string()),
    };
    match result {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}
