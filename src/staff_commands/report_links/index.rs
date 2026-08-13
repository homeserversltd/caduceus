//! Caduceus Linker band — bounded JSON dispatch to the retained Linker adapter.

use serde_json::{json, Value};
const OPERATIONS: &[&str] = &[
    "browse",
    "deploy",
    "delete",
    "rename",
    "mkdir",
    "hardlink-scan",
];

pub fn invoke(request: &Value) -> Result<Value, String> {
    crate::shared::agathodaimon::crossing_value("network", "linker", request).map_err(|receipt| {
        format!(
            "caduceus-linker-failed: {}",
            receipt
                .get("firstMissingSignal")
                .or_else(|| receipt.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("nonzero-exit")
        )
    })
}

pub fn intent_json(metadata: Value) -> Result<Value, String> {
    let operation = metadata
        .get("operation")
        .and_then(Value::as_str)
        .filter(|operation| OPERATIONS.contains(operation))
        .ok_or_else(|| "caduceus-linker-operation-invalid".to_string())?;
    let receipt = invoke(&metadata)?;
    Ok(json!({
        "schema": "caduceus.linker.actuator.v1",
        "ok": true,
        "accepted": true,
        "actuatorId": "linker",
        "operation": operation,
        "receiptFamily": "caduceus.linker.actuator.v1",
        "receipt": receipt,
        "mutationPerformed": !matches!(operation, "browse" | "hardlink-scan"),
        "firstMissingSignal": "none"
    }))
}
