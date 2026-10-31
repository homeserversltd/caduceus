use crate::shared::config;
use serde_json::Value;

pub fn read_json() -> Result<Value, String> {
    let mut value = config::carapace_with_build_identity();
    config::overlay_birth_profile_fields(&mut value)?;
    Ok(value)
}

pub fn show() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.carapace.v1");
            println!("{}", value);
            0
        }
        Err(err) => {
            eprintln!("caduceus-profile-show-failed: {err}");
            1
        }
    }
}
