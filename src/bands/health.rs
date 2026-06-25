use crate::tools::config;
use serde_json::{json, Value};

pub fn read_json() -> Result<Value, String> {
    let identity = config::read_public_file("etc/caduceus/identity.json").is_ok();
    let profile = config::public_profile_present();
    Ok(json!({
        "schema": "caduceus.health.v1",
        "identityPresent": identity,
        "profilePresent": profile,
        "privateLandOrgansExposed": false,
        "ok": identity && profile
    }))
}

pub fn show() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.health.v1");
            println!("identity_present={}", value["identityPresent"]);
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
