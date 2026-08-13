//! Wake-device staff actuator, retaining the registered wake-on-LAN wire behavior.
use serde_json::Value;

pub fn command_json(metadata: Value) -> Result<Value, String> {
    crate::bands::staff::execute_registered_actuator("wake-on-lan", metadata)
}

pub fn command(metadata: Value) -> i32 {
    match command_json(metadata) {
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
