use axum::{http::StatusCode, Json, Router};
use serde_json::Value;
use std::time::Duration;

const COMMAND: &str = "transmission status";
const TIMEOUT: Duration = Duration::from_secs(180);

async fn status_route(
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    if crate::routes::profile_routes::ACTIVE_PROFILE != "homeserver" {
        return Err(crate::gate::api_error(COMMAND));
    }
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(crate::gate::api_error(COMMAND)),
        Err(_) => {
            return Err(crate::gate::api_error_signal(
                COMMAND,
                "caduceus-profile-missing",
            ));
        }
    }

    let payload = Value::Null;
    let crossed = crate::gate::blocking_task(COMMAND, move || {
        crate::gate::snake::crossing_path_with_timeout("transmission/status", &payload, TIMEOUT)
    })
    .await?;
    let crossing = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
    let receipt = crossing.get("receiptPayload").cloned().ok_or_else(|| {
        crate::gate::service_unavailable(COMMAND, "caduceus-transmission-status-receipt-missing")
    })?;
    if !crate::routes::leaf_schema::accepts("caduceus.transmission.status.v1", &receipt) {
        return Err(crate::gate::service_unavailable(
            COMMAND,
            "caduceus-schema-desync",
        ));
    }

    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/transmission/status",
        axum::routing::get(status_route),
    )
}
