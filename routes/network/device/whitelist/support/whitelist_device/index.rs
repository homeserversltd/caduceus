// Firewall staff command, crossed only through agathodaimon network firewall.
use serde_json::Value;

pub fn invoke(intent: Value) -> Result<Value, Value> {
    crate::shared::agathodaimon::crossing_value("network", "firewall", &intent)
}
pub fn command_json(intent: Value) -> Result<Value, Value> {
    match invoke(intent) {
        Ok(v) => Ok(v),
        Err(v) => {
            let signal = v
                .get("error")
                .and_then(Value::as_str)
                .or_else(|| v.get("firstMissingSignal").and_then(Value::as_str))
                .unwrap_or("firewall-staff-refused");
            Err(serde_json::json!({"ok":false,"firstMissingSignal":signal}))
        }
    }
}
