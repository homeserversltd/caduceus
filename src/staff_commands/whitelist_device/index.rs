//! Firewall staff command, crossed only through agathodaimon network firewall.
use serde_json::Value;

pub fn invoke(intent: Value) -> Result<Value, Value> {
    crate::shared::agathodaimon::crossing_value("network", "firewall", &intent)
}
pub fn command_json(intent: Value) -> Result<Value, Value> {
    invoke(intent)
}
