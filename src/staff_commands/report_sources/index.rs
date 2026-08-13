//! Fixed-path source-map reseed public membrane.
//!
//! The staff actuator owns boundary validation and the atomic splice.  This
//! band takes no certificate, source-map, component, or payload argument.

use serde_json::{json, Value};
const COMMAND: &str = "profile sources reseed";
const TARGET: &str = "profile-sources";
pub fn reseed_json() -> Result<Value, String> {
    crate::shared::agathodaimon::crossing_value("update", "sources-reseed", &json!({})).map_err(
        |value| {
            value
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .unwrap_or("caduceus-source-map-reseed-failed")
                .to_string()
        },
    )
}

pub fn command() -> i32 {
    match reseed_json() {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

pub const fn public_command() -> &'static str {
    COMMAND
}

pub const fn target() -> &'static str {
    TARGET
}
