use crate::tools::config;
use serde_json::Value;

pub fn read_json() -> Result<Value, String> {
    let mut value = config::read_public_profile_value()?;
    config::overlay_birth_profile_fields(&mut value)?;
    Ok(value)
}

pub fn show() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.profile.v1");
            println!("{}", value);
            0
        }
        Err(err) => {
            eprintln!("caduceus-profile-missing: {err}");
            1
        }
    }
}
