//! Caduceus Linker band — bounded JSON dispatch to the retained Linker adapter.

use serde_json::{json, Value};
use std::io::Write;
use std::process::{Command, Stdio};

const LINKER_LAUNCHER: &str = "/usr/local/sbin/agathodaimon/cli.py linker";
const OPERATIONS: &[&str] = &[
    "browse",
    "deploy",
    "delete",
    "rename",
    "mkdir",
    "hardlink-scan",
];

pub fn invoke(request: &Value) -> Result<Value, String> {
    let input = serde_json::to_vec(request)
        .map_err(|err| format!("caduceus-linker-request-invalid: {err}"))?;
    let mut child = Command::new("sudo")
        .args(["-n", LINKER_LAUNCHER])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("caduceus-linker-unavailable: {err}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "caduceus-linker-unavailable".to_string())?
        .write_all(&input)
        .map_err(|err| format!("caduceus-linker-unavailable: {err}"))?;
    let output = child
        .wait_with_output()
        .map_err(|err| format!("caduceus-linker-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "caduceus-linker-empty: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let receipt: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("caduceus-linker-invalid-json: {err}"))?;
    if !output.status.success() || receipt.get("ok") == Some(&json!(false)) {
        return Err(format!(
            "caduceus-linker-failed: {}",
            receipt
                .get("firstMissingSignal")
                .or_else(|| receipt.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("nonzero-exit")
        ));
    }
    Ok(receipt)
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
