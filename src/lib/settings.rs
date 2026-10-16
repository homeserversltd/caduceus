//! Profile-gated GTK settings doors over fixed staff launchers.
//!
//! Each family owns one sbin launcher. Rust validates the family and field
//! allowlist, then delegates config-file string manipulation to the staff
//! actuator. Successful mutations must return a receipt rooted in the shared
//! Caduceus ledger.

use crate::shared::agathodaimon;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

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

fn discard_transient_receipt(value: &Value) {
    let Some(path) = value.get("receiptPath").and_then(Value::as_str) else {
        return;
    };
    let Some(relative) = path.strip_prefix(RECEIPT_ROOT) else {
        return;
    };
    let mut components = Path::new(relative).components();
    let Some(std::path::Component::Normal(run_id)) = components.next() else {
        return;
    };
    if !matches!(components.next(), Some(std::path::Component::Normal(name)) if name.to_str() == Some("run.json"))
        || components.next().is_some()
    {
        return;
    }
    let Some(run_id) = run_id.to_str() else {
        return;
    };
    if run_id.is_empty() || run_id == "latest" || path != format!("{RECEIPT_ROOT}{run_id}/run.json") {
        return;
    }
    let run_directory = crate::shared::config::path(&format!("{RECEIPT_ROOT}{run_id}"));
    if !std::fs::symlink_metadata(&run_directory)
        .is_ok_and(|metadata| metadata.file_type().is_dir())
    {
        return;
    }
    let receipt_file = crate::shared::config::path(path);
    let is_regular_receipt = std::fs::symlink_metadata(&receipt_file)
        .is_ok_and(|metadata| metadata.file_type().is_file());
    if !is_regular_receipt || std::fs::remove_file(&receipt_file).is_err() {
        return;
    }
    let _ = std::fs::remove_dir(run_directory);
}

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
    agathodaimon::crossing_value_with_record(
        "settings",
        family,
        &input,
        args.first().map(String::as_str) != Some("get"),
    )
    .map_err(|value| {
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

fn valid_display_resolution(value: &str) -> bool {
    if value == "auto" {
        return true;
    }
    let Some((width, height)) = value.split_once('x') else {
        return false;
    };
    (3..=5).contains(&width.len())
        && (3..=5).contains(&height.len())
        && width.bytes().all(|byte| byte.is_ascii_digit())
        && height.bytes().all(|byte| byte.is_ascii_digit())
}

fn validate_display_config_fields(
    family: &str,
    values: &BTreeMap<String, Value>,
) -> Result<(), String> {
    if family != "display" {
        return Ok(());
    }
    if let Some(value) = values.get("resolution") {
        if !value.as_str().is_some_and(valid_display_resolution) {
            return Err("caduceus-settings-value-invalid:resolution".to_string());
        }
    }
    if let Some(value) = values.get("refresh_rate") {
        if !value
            .as_f64()
            .is_some_and(|rate| rate.is_finite() && rate > 0.0 && rate <= 500.0)
        {
            return Err("caduceus-settings-value-invalid:refresh_rate".to_string());
        }
    }
    Ok(())
}

fn restore_display_config(
    rollbacks: Vec<crate::shared::config::JsonSetRollback>,
) -> Result<(), String> {
    let mut failures = Vec::new();
    for rollback in rollbacks.into_iter().rev() {
        if let Err(error) = crate::shared::config::restore_json_set(rollback) {
            failures.push(error);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join(";"))
    }
}

fn display_mutation_error(
    signal: String,
    rollbacks: Vec<crate::shared::config::JsonSetRollback>,
) -> String {
    match restore_display_config(rollbacks) {
        Ok(()) => signal,
        Err(rollback) => {
            format!("{signal};caduceus-settings-display-rollback-failed:{rollback}")
        }
    }
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
    validate_display_config_fields(family, &values)?;
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
    let writes_display_config = family == "display"
        && ["resolution", "refresh_rate"]
            .iter()
            .any(|field| values.contains_key(*field));
    let mut rollbacks = Vec::new();
    if writes_display_config {
        for field in ["resolution", "refresh_rate"] {
            let Some(value) = values.get(field) else {
                continue;
            };
            let mut rollback = None;
            let write = crate::shared::config::set_json_with_rollback(
                &format!("display.{field}"),
                value.clone(),
                &mut rollback,
            );
            if let Some(rollback) = rollback {
                rollbacks.push(rollback);
            }
            if let Err(error) = write {
                return Err(display_mutation_error(error, rollbacks));
            }
        }
    }
    let receipt = match run(family, &args) {
        Ok(receipt) => receipt,
        Err(error) if writes_display_config => {
            return Err(display_mutation_error(error, rollbacks));
        }
        Err(error) => return Err(error),
    };
    let receipt_path = receipt
        .get("receiptPath")
        .and_then(Value::as_str)
        .filter(|path| path.starts_with(RECEIPT_ROOT) && path.ends_with("/run.json"))
        .map(str::to_string);
    let Some(receipt_path) = receipt_path else {
        let signal = "caduceus-settings-receipt-path-invalid".to_string();
        return if writes_display_config {
            Err(display_mutation_error(signal, rollbacks))
        } else {
            Err(signal)
        };
    };
    let display = if writes_display_config {
        let shown = match crate::shared::config::show_json() {
            Ok(shown) => shown,
            Err(error) => return Err(display_mutation_error(error, rollbacks)),
        };
        match shown
            .get("document")
            .and_then(|document| document.get("display"))
            .filter(|display| display.is_object())
            .cloned()
        {
            Some(display) => Some(display),
            None => {
                return Err(display_mutation_error(
                    "caduceus-settings-display-config-unobserved".to_string(),
                    rollbacks,
                ));
            }
        }
    } else {
        None
    };
    let mut result = json!({"schema":"caduceus.settings.mutation.v1","ok":true,"family":family,"changed":receipt.get("changed").and_then(Value::as_bool).unwrap_or(true),"fields":values.keys().collect::<Vec<_>>(),"receiptPath":receipt_path,"receipt":receipt,"firstMissingSignal":"none"});
    if let Some(display) = display {
        result["display"] = display;
    }
    discard_transient_receipt(&result);
    Ok(result)
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
