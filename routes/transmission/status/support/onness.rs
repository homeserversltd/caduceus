use serde_json::Value;
use std::time::Duration;

pub(crate) fn read(timeout: Duration) -> Result<Value, String> {
    let crossing = crate::gate::snake::crossing_path_with_timeout(
        "transmission/status",
        &Value::Null,
        timeout,
    )?;
    let Some(receipt) = crossing.get("receiptPayload") else {
        return Err("caduceus-transmission-status-receipt-missing".to_owned());
    };
    if crossing.get("ok").and_then(Value::as_bool) != Some(true) {
        let signal = receipt
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .filter(|signal| !signal.is_empty() && *signal != "none")
            .or_else(|| {
                crossing
                    .get("firstMissingSignal")
                    .and_then(Value::as_str)
                    .filter(|signal| !signal.is_empty() && *signal != "none")
            })
            .unwrap_or("caduceus-agathodaimon-refused");
        return Err(signal.to_owned());
    }
    if !crate::routes::leaf_schema::accepts(
        "caduceus.transmission.status.v1",
        receipt,
    ) {
        return Err("caduceus-schema-desync".to_owned());
    }
    if receipt.get("ok").and_then(Value::as_bool) == Some(false) {
        let signal = receipt
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .filter(|signal| !signal.is_empty() && *signal != "none")
            .unwrap_or("caduceus-transmission-status-not-ok");
        return Err(signal.to_owned());
    }

    Ok(receipt.clone())
}
