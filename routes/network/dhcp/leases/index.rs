/// C2 route leaf.
pub const NAMESPACE: &str = "network/dhcp/leases";

use crate::gate::ApiErrorBody;
use axum::{response::Json, Router};
use serde_json::Value;

async fn dhcp_leases_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let command = "network dhcp leases";
    match crate::shared::policy::allows_command(command) {
        Ok(true) => {
            let value = crate::routes::native_kea_read::response(command);
            if value["ok"] == true {
                Ok(Json(value))
            } else {
                Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: command.to_string(),
                        first_missing_signal: value["firstMissingSignal"]
                            .as_str()
                            .unwrap_or("caduceus-network-dhcp-read-failed")
                            .to_string(),
                    }),
                ))
            }
        }
        Ok(false) => Err(crate::gate::api_error(command)),
        Err(_) => Err(crate::gate::api_error_signal(
            command,
            "caduceus-profile-missing",
        )),
    }
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/network/dhcp/leases",
        axum::routing::get(dhcp_leases_route),
    )
}
