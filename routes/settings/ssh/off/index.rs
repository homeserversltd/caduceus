use axum::{http::StatusCode, Json, Router};
use serde_json::{json, Value};
use std::time::Duration;

const COMMAND: &str = "settings ssh off";
const TIMEOUT: Duration = Duration::from_secs(600);

async fn off_route(
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(crate::gate::api_error(COMMAND)),
        Err(_) => return Err(crate::gate::api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
    let crossed = crate::gate::blocking_task(COMMAND, move || {
        crate::gate::snake::crossing_path_with_timeout("settings/ssh/off", &json!({}), TIMEOUT)
    }).await?;
    let crossing = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
    let receipt = crossing.get("receiptPayload").cloned().ok_or_else(|| {
        crate::gate::service_unavailable(COMMAND, "caduceus-settings-ssh-off-receipt-missing")
    })?;
    if !crate::routes::leaf_schema::accepts("caduceus.chord.receipt.v1", &receipt) {
        return Err(crate::gate::service_unavailable(COMMAND, "caduceus-schema-desync"));
    }
    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/settings/ssh/off", axum::routing::post(off_route))
}
