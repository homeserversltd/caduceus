use crate::staff_commands::control_service;
use serde_json::Value;
pub fn service(metadata: Value) -> Result<Value, String> {
    control_service::execute_service(metadata)
}
