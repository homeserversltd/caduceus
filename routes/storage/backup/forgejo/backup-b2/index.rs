use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;
use crate::gate::{api_error, api_error_signal, blocking_task, mutation_status, ApiErrorBody};
use crate::shared::policy;

async fn route(Json(metadata): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "staff intent";
    if !crate::gate::roster_allows("POST", "storage/backup/forgejo/backup-b2").unwrap_or(false) {
        return Err(api_error_signal(COMMAND, "caduceus-route-off-roster"));
    }
    match policy::allows_command(COMMAND) {
        Ok(true) => {
            let receipt = blocking_task(COMMAND, move || {
                crate::routes::staff::named_actuator_json("backblaze-forgejo-b2-push", metadata)
            }).await?.map_err(|signal| api_error_signal(COMMAND, &signal))?;
            Ok((mutation_status(&receipt), Json(receipt)))
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/storage/backup/forgejo/backup-b2", axum::routing::post(route))
}
