use crate::shared::config;
use serde_json::Value;

pub fn read_json() -> Result<Value, String> {
    let text = config::read_public_file("etc/appliance/profile.json")
        .map_err(|err| format!("caduceus-identity-profile-missing: {err}"))?;
    serde_json::from_str(&text).map_err(|err| format!("caduceus-identity-profile-invalid: {err}"))
}

pub fn show() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.identity.v1");
            println!("{}", value);
            0
        }
        Err(err) => {
            eprintln!("caduceus-identity-read-failed: {err}");
            1
        }
    }
}
