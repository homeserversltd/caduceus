use serde_json::Value;

pub fn check_declared_admittance(declaration: &Value) -> Result<&'static str, String> {
    match declaration.get("admittance").and_then(Value::as_str) {
        None | Some("open") => Ok("open"),
        Some("admitted") => Ok("admitted"),
        Some(_) => Err("gate-admittance-invalid".into()),
    }
}
