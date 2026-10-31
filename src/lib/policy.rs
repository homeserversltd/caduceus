use crate::shared::config;
use serde_json::Value;

pub fn load_profile_value() -> Result<Value, String> {
    Ok(config::carapace().clone())
}

pub fn allows_command(command: &str) -> Result<bool, String> {
    Ok(crate::routes::profile_routes::COMMANDS.contains(&command))
}
