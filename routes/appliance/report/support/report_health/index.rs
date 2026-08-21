use crate::shared::config;
use serde_json::{json, Value};

pub fn read_json() -> Result<Value, String> {
    let profile = config::public_profile_present();
    Ok(json!({
        "schema": "caduceus.health.v1",
        "profilePresent": profile,
        "privateLandOrgansExposed": false,
        "ok": profile
    }))
}

pub fn show() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.health.v1");
            println!("profile_present={}", value["profilePresent"]);
            println!("private_land_organs_exposed=false");
            if value["ok"].as_bool() == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("caduceus-health-read-failed: {err}");
            1
        }
    }
}
