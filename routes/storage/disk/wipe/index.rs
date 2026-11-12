use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};
use std::time::Duration;
use crate::gate::{api_error_signal, blocking_task, mutation_status};

pub const NAMESPACE: &str = "storage/disk/wipe";

fn native_refusal(signal: &str) -> (StatusCode, Json<Value>) {
    (StatusCode::FORBIDDEN, Json(json!({
        "schema": "caduceus.staff.receipt.v1",
        "stop": {"noun": "storage/disk", "verb": "wipe"},
        "ok": false,
        "firstMissingSignal": signal,
        "observed": null,
        "could_change_to": null,
        "attempt": {"attempted": false},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    })))
}

async fn route(Json(payload): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    const COMMAND: &str = "staff intent";
    if !crate::gate::roster_allows("POST", NAMESPACE).unwrap_or(false) {
        return Err(native_refusal("caduceus-route-off-roster"));
    }
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {
            let fields = crate::routes::staff::disk_wipe_payload(&payload, false)
                .map_err(|signal| native_refusal(&signal))?;
            let receipt = blocking_task(COMMAND, move || -> Result<Value, String> {
                let walked = crate::gate::snake::crossing_path_with_timeout(NAMESPACE, &fields, Duration::from_secs(30))?;
                let mut receipt = walked.get("receiptPayload").cloned().filter(Value::is_object)
                    .ok_or_else(|| "caduceus-staff-invalid-receipt".to_string())?;
                if !crate::routes::leaf_schema::bound(&receipt, NAMESPACE) {
                    return Err("caduceus-staff-invalid-receipt".into());
                }
                if walked.get("ok").and_then(Value::as_bool) != Some(true)
                    && receipt.get("ok").and_then(Value::as_bool) != Some(false)
                {
                    if let Some(object) = receipt.as_object_mut() {
                        object.entry("doorSignal").or_insert_with(|| {
                            Value::String(walked.get("firstMissingSignal").and_then(Value::as_str)
                                .filter(|signal| !signal.is_empty() && *signal != "none")
                                .unwrap_or("caduceus-agathodaimon-refused").to_string())
                        });
                    }
                }
                Ok(receipt)
            }).await.map_err(|(status, Json(body))| (status, Json(json!(body))))?
                .map_err(|signal| {
                    let (status, Json(body)) = api_error_signal(COMMAND, &signal);
                    (status, Json(json!(body)))
                })?;
            Ok((mutation_status(&receipt), Json(receipt)))
        }
        Ok(false) => Err(native_refusal("caduceus-public-action-not-allowed")),
        Err(_) => Err(native_refusal("caduceus-profile-missing")),
    }
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/storage/disk/wipe", axum::routing::post(route))
}
