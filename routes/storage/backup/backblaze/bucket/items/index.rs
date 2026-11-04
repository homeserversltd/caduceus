use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;
use crate::gate::{api_error, api_error_signal, blocking_task, mutation_status, ApiErrorBody};
use crate::shared::policy;

async fn route(Json(metadata): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "staff intent";
    if !crate::gate::roster_allows("POST", "storage/backup/backblaze/bucket/items").unwrap_or(false) {
        return Err(api_error_signal(COMMAND, "caduceus-route-off-roster"));
    }

    match policy::allows_command(COMMAND) {
        Ok(true) => {
            let band = match metadata.get("op").and_then(Value::as_str) {
                Some("add") => "storage/backup/backblaze/bucket-items/add",
                Some("remove") => "storage/backup/backblaze/bucket-items/remove",
                _ => return Err(api_error_signal(COMMAND, "operation-invalid")),
            };
            let receipt = blocking_task(COMMAND, move || {
                crate::routes::staff::bucket_items_stop_json(band, metadata)
            }).await?.map_err(|signal| api_error_signal(COMMAND, &signal))?;
            Ok((mutation_status(&receipt), Json(receipt)))
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/storage/backup/backblaze/bucket/items", axum::routing::post(route))
}
