use axum::{http::StatusCode, Json, Router};
use serde_json::{json, Value};
use std::time::Duration;

const COMMAND: &str = "settings samba status";
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
                "caduceus-carapace-desync",
            ));
        }
    }

    let payload = json!({"state":"status"});
    let envelope = crate::gate::snake::crossing_envelope("settings/samba/status", &payload);
    let crossed = crate::gate::snake::execute_ordered_serve_with_timeout(
        &[json!({"snake":"settings/samba/status"})],
        &envelope,
        Some(TIMEOUT),
    ).await;
    let crossing = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
    let receipt = crossing.get("receiptPayload").cloned().ok_or_else(|| {
        crate::gate::service_unavailable(
            COMMAND,
            "caduceus-settings-samba-status-receipt-missing",
        )
    })?;
    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/settings/samba/status",
        axum::routing::get(status_route),
    )
}
