//! Profile-gated GTK settings doors over fixed staff launchers.
//!
//! Each family owns one sbin launcher. Rust validates the family and field
//! allowlist, then delegates config-file string manipulation to the staff
//! actuator. Successful mutations must return a receipt rooted in the shared
//! Caduceus ledger.

use crate::shared::agathodaimon;
use serde_json::{json, Value};
use std::collections::BTreeMap;

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

fn run(family: &str, args: &[String]) -> Result<Value, String> {
    let input = json!({"args": args, "receiptRoot": RECEIPT_ROOT});
    agathodaimon::crossing_value("settings", family, &input).map_err(|value| {
        value
            .get("firstMissingSignal")
            .or_else(|| value.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("caduceus-settings-staff-refused")
            .to_string()
    })
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
    let field_room = match body {
        Value::Object(mut object) => object.remove("payload").unwrap_or(Value::Object(object)),
        body => body,
    };
    let object = field_room
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

#[cfg(test)]
mod tests {
    use super::validated_fields;
    use serde_json::json;

    #[test]
    fn enveloped_payload_is_accepted() {
        let values = validated_fields(
            "input",
            json!({
                "schema": "caduceus.staff.v1",
                "intent_id": "caduceus-settings-input",
                "transition": "settings/input",
                "target": "dark",
                "payload": {"pointer_speed": 0.1}
            }),
        )
        .unwrap();
        assert_eq!(values.get("pointer_speed"), Some(&json!(0.1)));
    }

    #[test]
    fn bare_field_map_is_accepted() {
        let values = validated_fields("input", json!({"pointer_speed": 0.1})).unwrap();
        assert_eq!(values.get("pointer_speed"), Some(&json!(0.1)));
    }

    #[test]
    fn present_null_payload_is_rejected() {
        let error = validated_fields("appearance", json!({"payload": null})).unwrap_err();
        assert_eq!(error, "caduceus-settings-fields-object-required");
    }
}
