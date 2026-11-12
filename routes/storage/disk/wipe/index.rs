use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;
use std::time::Duration;
use crate::gate::{api_error, api_error_signal, blocking_task, mutation_status, ApiErrorBody};

pub const NAMESPACE: &str = "storage/disk/wipe";

async fn route(Json(payload): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "staff intent";
    if !crate::gate::roster_allows("POST", NAMESPACE).unwrap_or(false) {
        return Err(api_error_signal(COMMAND, "caduceus-route-off-roster"));
    }
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {
            let fields = crate::routes::staff::disk_wipe_payload(&payload, false)
                .map_err(|signal| api_error_signal(COMMAND, &signal))?;
            let receipt = blocking_task(COMMAND, move || {
                let walked = crate::gate::snake::crossing_path_with_timeout(NAMESPACE, &fields, Duration::from_secs(30))?;
                let receipt = walked.get("receiptPayload").cloned().filter(Value::is_object)
                    .ok_or_else(|| "caduceus-staff-invalid-receipt".to_string())?;
                if !crate::routes::leaf_schema::bound(&receipt, NAMESPACE) {
                    return Err("caduceus-staff-invalid-receipt".into());
                }
                if walked.get("ok").and_then(Value::as_bool) != Some(true) || receipt.get("ok").and_then(Value::as_bool) == Some(false) {
                    return Err(receipt.get("firstMissingSignal").and_then(Value::as_str).unwrap_or("caduceus-staff-refused").to_string());
                }
                Ok(receipt)
            }).await?.map_err(|signal| api_error_signal(COMMAND, &signal))?;
            Ok((mutation_status(&receipt), Json(receipt)))
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/storage/disk/wipe", axum::routing::post(route))
}
