use crate::tools::config;
use serde_json::Value;

pub fn load_profile_value() -> Result<Value, String> {
    let raw = config::read_public_file("etc/caduceus/profile.json")?;
    serde_json::from_str(&raw).map_err(|err| format!("caduceus-profile-invalid: {err}"))
}

pub fn allows_command(command: &str) -> Result<bool, String> {
    let profile = load_profile_value()?;
    let Some(commands) = profile.get("commands").and_then(Value::as_array) else {
        return Ok(false);
    };
    Ok(commands
        .iter()
        .filter_map(Value::as_str)
        .any(|allowed| allowed == command))
}
