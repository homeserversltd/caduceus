//! Profile-gated GTK settings doors over fixed staff launchers.
//!
//! Each family owns one sbin launcher. Rust validates the family and field
//! allowlist, then delegates config-file string manipulation to the staff
//! actuator. Successful mutations must return a receipt rooted in the shared
//! Caduceus ledger.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

pub const FAMILIES: &[&str] = &[
    "display",
    "appearance",
    "sound",
    "input",
    "keyboard",
    "region",
    "energy",
    "notifications",
    "default-apps",
    "datetime",
];
const RECEIPT_ROOT: &str = "/var/lib/caduceus/receipts/";

fn discard_transient_receipt(value: &Value) -> bool {
    let Some(path) = value.get("receiptPath").and_then(Value::as_str) else {
        return false;
    };
    let Some(relative) = path.strip_prefix(RECEIPT_ROOT) else {
        return false;
    };
    let mut components = Path::new(relative).components();
    let Some(std::path::Component::Normal(run_id)) = components.next() else {
        return false;
    };
    if !matches!(components.next(), Some(std::path::Component::Normal(name)) if name.to_str() == Some("run.json"))
        || components.next().is_some()
    {
        return false;
    }
    let Some(run_id) = run_id.to_str() else {
        return false;
    };
    if run_id.is_empty() || run_id == "latest" || path != format!("{RECEIPT_ROOT}{run_id}/run.json") {
        return false;
    }
    let run_directory = crate::shared::config::path(&format!("{RECEIPT_ROOT}{run_id}"));
    if !std::fs::symlink_metadata(&run_directory)
        .is_ok_and(|metadata| metadata.file_type().is_dir())
    {
        return false;
    }
    let receipt_file = crate::shared::config::path(path);
    let is_regular_receipt = std::fs::symlink_metadata(&receipt_file)
        .is_ok_and(|metadata| metadata.file_type().is_file());
    if !is_regular_receipt || std::fs::remove_file(&receipt_file).is_err() {
        return false;
    }
    let _ = std::fs::remove_dir(run_directory);
    true
}

fn fields(family: &str) -> Option<&'static [&'static str]> {
    match family {
        "display" => Some(&[
            "output",
            "resolution",
            "refresh_rate",
            "scale",
            "orientation",
            "brightness",
            "night_light",
            "hdr",
            "adaptive_sync",
            "overscan",
        ]),
        "appearance" => Some(&[
            "color_scheme",
            "accent_color",
            "wallpaper",
            "icon_theme",
            "cursor_theme",
            "font",
            "cursor_size",
            "font_size",
            "text_scale",
        ]),
        "sound" => Some(&[
            "output_device",
            "input_device",
            "volume",
            "input_volume",
            "muted",
            "card_profile",
            "test_tone",
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
            "accel_profile",
            "left_handed",
            "disable_while_typing",
        ]),
        "keyboard" => Some(&["keyboard_layout", "repeat_rate", "repeat_delay"]),
        "region" => Some(&["locale", "measurement_units"]),
        "energy" => Some(&["screen_off_seconds", "sleep_seconds", "power_button_action"]),
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

fn cross_settings(path: &str, input: &Value) -> Result<Value, String> {
    let value = crate::gate::snake::crossing_path_with_timeout(
        path,
        input,
        Duration::from_secs(180),
    )?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(value.get("receiptPayload").cloned().unwrap_or(value))
    } else {
        Err(value
            .get("receiptPayload")
            .and_then(|payload| {
                payload
                    .get("error")
                    .or_else(|| payload.get("firstMissingSignal"))
                    .and_then(Value::as_str)
            })
            .or_else(|| value.get("firstMissingSignal").and_then(Value::as_str))
            .unwrap_or("caduceus-agathodaimon-refused")
            .into())
    }
}

fn mutation_refusal(family: &str, body: &Value, step: &str, signal: String) -> Value {
    let room = body.get("payload").unwrap_or(body);
    let names: Vec<&str> = room.as_object()
        .map(|object| object.keys().map(String::as_str).collect())
        .unwrap_or_default();
    json!({
        "schema": "caduceus.staff.receipt.v1", "ok": false,
        "stop": {"noun": format!("settings/{family}"), "verb": "mutate"},
        "observed": {"family": family, "fields": names},
        "could_change_to": {"fields": fields(family).unwrap_or(&[])},
        "attempt": {"attempted": false, "steps": [{"step": step, "signal": signal}]},
        "final_receipt": {"ok": false, "firstMissingSignal": signal},
        "firstMissingSignal": signal
    })
}

fn cross_mutation(path: &str, input: &Value) -> Result<(Value, bool), String> {
    let crossing = crate::gate::snake::crossing_path_with_timeout(path, input, Duration::from_secs(180))?;
    let ok = crossing.get("ok").and_then(Value::as_bool) == Some(true);
    if let Some(receipt) = crossing.get("receiptPayload").filter(|value| value.is_object()) {
        return Ok((receipt.clone(), ok));
    }
    Err(crossing.get("firstMissingSignal").and_then(Value::as_str)
        .unwrap_or("caduceus-agathodaimon-refused").to_string())
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
    let receipt = cross_settings(&format!("settings/{family}/read"), &json!({}))?;
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
    let mut result =
        json!({"schema":"caduceus.settings.read.v1","ok":true,"family":family,"values":values,"firstMissingSignal":"none"});
    if family == "input" {
        for field in ["sources", "base", "override"] {
            if let Some(value) = receipt.get(field) {
                result[field] = value.clone();
            }
        }
    }
    let mut options = serde_json::Map::new();
    if let Some(received) = receipt.get("options").and_then(Value::as_object) {
        for (field, entries) in received {
            if !allowed.contains(&field.as_str()) {
                continue;
            }
            let Some(entries) = entries.as_array() else {
                continue;
            };
            let choices: Vec<Value> = entries
                .iter()
                .filter(|entry| {
                    let Some(object) = entry.as_object() else {
                        return false;
                    };
                    object.get("value").is_some_and(|value| value.is_string() || value.is_number())
                        && object.get("label").and_then(Value::as_str)
                            .is_some_and(|label| label.chars().count() <= 200)
                })
                .take(2000)
                .cloned()
                .collect();
            if !choices.is_empty() {
                options.insert(field.clone(), Value::Array(choices));
            }
        }
    }
    if !options.is_empty() {
        result["options"] = Value::Object(options);
    }
    Ok(result)
}

pub fn mutate_json(family: &str, body: Value) -> Result<Value, String> {
    let validate = || -> Result<BTreeMap<String, Value>, String> {
    let values = validated_fields(family, body.clone())?;
    validate_display_config_fields(family, &values)?;
    if family == "display" {
        for field in values.keys() {
            if matches!(field.as_str(), "brightness" | "night_light" | "overscan") {
                return Err(format!("unknown-field:{field}"));
            }
        }
        if values.len() > 1 {
            return Err("mixed-display-fields".to_string());
        }
    }
    if family == "energy" && values.contains_key("sleep_seconds") {
        return Err("unknown-field:sleep_seconds".to_string());
    }
    if family == "appearance" || family == "notifications" || family == "datetime" {
        for field in values.keys() {
            if matches!((family, field.as_str()),
                ("appearance", "accent_color" | "wallpaper") |
                ("notifications", "enabled" | "show_banners" | "show_on_lock_screen" | "sound_enabled") |
                ("datetime", "automatic_timezone" | "date_format" | "time_format")) {
                return Err(format!("unknown-field:{field}"));
            }
        }
    }
    if family == "sound" && values.contains_key("test_tone")
        && (values.len() != 1 || values.get("test_tone") != Some(&Value::Bool(true))) {
        return Err("caduceus-settings-value-invalid:test_tone".to_string());
    }
    Ok(values)
    };
    let values = match validate() {
        Ok(values) => values,
        Err(signal) => return Ok(mutation_refusal(family, &body, "validate", signal)),
    };
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
                return Ok(mutation_refusal(family, &body, "write-display-config", display_mutation_error(error, rollbacks)));
            }
        }
    }
    let (path, payload) = if family == "sound" && values.contains_key("test_tone") {
        ("settings/sound/test-tone/play".to_string(), json!({}))
    } else if family == "display" && values.contains_key("hdr") {
        ("settings/display/hdr/set".to_string(), json!(values))
    } else if family == "display" && values.contains_key("adaptive_sync") {
        ("settings/display/adaptive-sync/set".to_string(), json!(values))
    } else {
        (format!("settings/{family}/set"), json!(values))
    };
    let crossed = cross_mutation(&path, &payload);
    let (mut receipt, crossing_ok) = match crossed {
        Ok(receipt) => receipt,
        Err(error) if writes_display_config => {
            return Err(display_mutation_error(error, rollbacks));
        }
        Err(error) => return Err(error),
    };
    let stop_ok = receipt.get("ok").and_then(Value::as_bool) == Some(true);
    let binding_failed = receipt.get("schema").and_then(Value::as_str) == Some("caduceus.staff.receipt.v1")
        && !crate::routes::leaf_schema::bound(&receipt, &path);
    let object = receipt.as_object_mut().expect("cross_mutation returns an object");
    object.entry("family").or_insert_with(|| json!(family));
    object.entry("fields").or_insert_with(|| json!(values.keys().collect::<Vec<_>>()));
    if !crossing_ok || !stop_ok || binding_failed {
        let rollback_failed = writes_display_config && restore_display_config(rollbacks).is_err();
        let signal = if rollback_failed {
            Some("caduceus-settings-display-rollback-failed")
        } else if !crossing_ok && stop_ok {
            Some("caduceus-agathodaimon-refused")
        } else if binding_failed {
            Some("caduceus-schema-desync")
        } else {
            None
        };
        if let Some(signal) = signal {
            object.entry("doorSignal").or_insert_with(|| json!(signal));
        }
        return Ok(receipt);
    }
    let receipt_path_valid = receipt.get("receiptPath").and_then(Value::as_str)
        .and_then(|path| path.strip_prefix(RECEIPT_ROOT).map(|relative| (path, relative)))
        .is_some_and(|(path, relative)| path.ends_with("/run.json")
            && !Path::new(relative).components().any(|component| matches!(component, std::path::Component::ParentDir | std::path::Component::RootDir | std::path::Component::Prefix(_))));
    if !receipt_path_valid {
        let signal = if writes_display_config && restore_display_config(rollbacks).is_err() {
            "caduceus-settings-display-rollback-failed"
        } else {
            "caduceus-settings-receipt-path-invalid"
        };
        receipt.as_object_mut().unwrap().entry("doorSignal").or_insert_with(|| json!(signal));
        return Ok(receipt);
    }
    if writes_display_config {
        let display = crate::shared::config::show_json().and_then(|shown| {
            shown.get("document").and_then(|document| document.get("display"))
                .filter(|display| display.is_object()).cloned()
                .ok_or_else(|| "caduceus-settings-display-config-unobserved".to_string())
        });
        match display {
            Ok(display) => { receipt.as_object_mut().unwrap().entry("display").or_insert(display); }
            Err(error) => {
                let signal = if restore_display_config(rollbacks).is_err() {
                    "caduceus-settings-display-rollback-failed".to_string()
                } else { error };
                receipt.as_object_mut().unwrap().entry("doorSignal").or_insert_with(|| json!(signal));
                return Ok(receipt);
            }
        }
    }
    if discard_transient_receipt(&receipt) {
        receipt.as_object_mut().unwrap().entry("receiptDiscarded").or_insert(json!(true));
    }
    Ok(receipt)
}

pub fn command(family: &str, args: &[String]) -> i32 {
    let result = match args {
        [verb] if verb == "read" => read_json(family),
        [verb, json] if verb == "mutate" => match serde_json::from_str(json) {
            Ok(body) => mutate_json(family, body),
            Err(_) => Ok(mutation_refusal(family, &Value::Null, "parse-json", "caduceus-settings-json-invalid".to_string())),
        },
        _ => Err("caduceus-settings-command-invalid".to_string()),
    };
    match result {
        Ok(value) => {
            let ok = value.get("ok").and_then(Value::as_bool) == Some(true)
                && value.get("doorSignal").is_none();
            println!("{value}");
            if ok { 0 } else { 1 }
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
