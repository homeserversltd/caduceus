use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};
use std::time::Duration;

const STOP: &str = "storage/shares/converge";
const COMMAND: &str = "staff intent";

fn refusal(signal: &str) -> Value {
    json!({
        "schema": "caduceus.staff.receipt.v1",
        "stop": {"noun": "storage/shares", "verb": "converge"},
        "ok": false,
        "firstMissingSignal": signal,
        "observed": null,
        "could_change_to": null,
        "attempt": {"attempted": false},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    })
}

fn cross() -> Value {
    match crate::gate::snake::crossing_path_with_timeout(STOP, &json!({}), Duration::from_secs(120)) {
        Ok(crossing) => {
            let mut receipt = crossing.get("receiptPayload").cloned().filter(Value::is_object)
                .unwrap_or_else(|| refusal("caduceus-staff-invalid-receipt"));
            if crate::routes::leaf_schema::bound(&receipt, STOP)
                && crossing.get("ok").and_then(Value::as_bool) != Some(true)
                && receipt.get("ok").and_then(Value::as_bool) != Some(false)
            {
                if let Some(object) = receipt.as_object_mut() {
                    object.entry("doorSignal").or_insert_with(|| json!("caduceus-agathodaimon-refused"));
                }
            }
            receipt
        },
        Err(signal) => refusal(&signal),
    }
}

fn desync(mut receipt: Value) -> Value {
    if let Some(object) = receipt.as_object_mut() {
        object.entry("doorSignal").or_insert_with(|| json!("caduceus-schema-desync"));
        object.entry("crossedStop").or_insert_with(|| json!(STOP));
    }
    receipt
}

pub fn rebuild_at_start() -> Value {
    let receipt = cross();
    if crate::routes::leaf_schema::bound(&receipt, STOP) {
        receipt
    } else {
        desync(receipt)
    }
}

async fn route() -> (StatusCode, Json<Value>) {
    if !matches!(crate::shared::policy::allows_command(COMMAND), Ok(true)) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(refusal("caduceus-carapace-desync")));
    }
    let receipt = match crate::gate::blocking_task(COMMAND, cross).await {
        Ok(receipt) => receipt,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(refusal("caduceus-blocking-task-failed"))),
    };
    if !crate::routes::leaf_schema::bound(&receipt, STOP) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(desync(receipt)));
    }
    (crate::gate::mutation_status(&receipt), Json(receipt))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/storage/shares/converge", axum::routing::post(route))
}
