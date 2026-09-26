use crate::shared::config;
use serde_json::Value;

pub fn load_profile_value() -> Result<Value, String> {
    config::read_public_profile_value()
}

pub fn allows_command(command: &str) -> Result<bool, String> {
    if config::resolved_profile().as_deref() == Ok("probe")
        && crate::routes::profile_routes::PROBE_COMMANDS.contains(&command)
    {
        return Ok(true);
    }
    let profile = load_profile_value()?;
    let Some(commands) = profile.get("commands").and_then(Value::as_array) else {
        return Ok(false);
    };
    Ok(commands
        .iter()
        .filter_map(Value::as_str)
        .any(|allowed| allowed == command))
}
