use crate::shared::config;
use serde_json::Value;
use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/embedded_crossings.rs"));

struct Loaded {
    raw: &'static str,
    value: Value,
}

static LOADED: OnceLock<Result<Loaded, String>> = OnceLock::new();

fn invalid(reason: &str, expected: &str, observed: &str) -> String {
    format!(
        "caduceus-crossings-declaration-invalid: reason={reason}; expected={expected}; observed={observed}"
    )
}

fn load_once() -> Result<Loaded, String> {
    let identity_path = config::path("etc/appliance/profile.json");
    let identity_raw = std::fs::read_to_string(&identity_path).map_err(|error| {
        invalid(
            "identity-unreadable",
            "readable /etc/appliance/profile.json with a non-empty profile string",
            &format!("{}: {error}", identity_path.display()),
        )
    })?;
    let identity: Value = serde_json::from_str(&identity_raw).map_err(|error| {
        invalid(
            "identity-json-invalid",
            "JSON object containing a non-empty profile string",
            &error.to_string(),
        )
    })?;
    let profile_value = identity.get("profile");
    let profile = profile_value.and_then(Value::as_str).ok_or_else(|| {
        invalid(
            "identity-profile-invalid",
            "non-empty string in /etc/appliance/profile.json profile",
            &profile_value
                .map(Value::to_string)
                .unwrap_or_else(|| "<missing>".to_owned()),
        )
    })?;
    if profile.is_empty() {
        return Err(invalid(
            "identity-profile-empty",
            "non-empty string in /etc/appliance/profile.json profile",
            "\"\"",
        ));
    }

    let (embedded_profile, raw) = EMBEDDED_CROSSINGS
        .iter()
        .find(|(id, _)| *id == profile)
        .ok_or_else(|| {
            let expected = EMBEDDED_CROSSINGS
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
                .join(", ");
            invalid(
                "sold-declaration-missing",
                &format!("embedded declaration for one of [{expected}]"),
                profile,
            )
        })?;

    let value: Value = serde_json::from_str(raw).map_err(|error| {
        invalid(
            "embedded-declaration-json-invalid",
            "valid JSON declaration bytes",
            &error.to_string(),
        )
    })?;
    let observed_schema = value
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or("<missing-or-not-string>");
    if observed_schema != "appliance.crossings.v1" {
        return Err(invalid(
            "schema-mismatch",
            "appliance.crossings.v1",
            observed_schema,
        ));
    }
    let observed_profile = value
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("<missing-or-not-string>");
    if observed_profile != profile || observed_profile != *embedded_profile {
        return Err(invalid(
            "profile-mismatch",
            profile,
            observed_profile,
        ));
    }

    Ok(Loaded { raw, value })
}

fn loaded() -> Result<&'static Loaded, String> {
    match LOADED.get_or_init(load_once) {
        Ok(value) => Ok(value),
        Err(error) => Err(error.clone()),
    }
}

pub fn initialize() -> Result<(), String> {
    loaded().map(|_| ())
}

pub fn declaration() -> Result<Value, String> {
    Ok(loaded()?.value.clone())
}

pub fn raw() -> Result<&'static str, String> {
    Ok(loaded()?.raw)
}
