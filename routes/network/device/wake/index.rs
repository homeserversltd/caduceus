// Wake-device staff actuator, retaining the registered wake-on-LAN wire behavior.
use serde_json::Value;

pub fn command_json(metadata: Value) -> Result<Value, String> {
    crate::routes::staff::execute_registered_actuator("wake-on-lan", metadata)
}

pub fn command(metadata: Value) -> i32 {
    match command_json(metadata) {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

use crate::gate::ApiErrorBody;
use axum::{
    extract::{Json, OriginalUri},
    http::{HeaderMap, StatusCode},
    Router,
};

async fn wake_named_actuator_route(
    _headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    if !crate::gate::roster_allows("POST", uri.path()).unwrap_or(false) {
        return Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-route-off-roster",
        ));
    }
    match crate::shared::policy::allows_command("staff intent") {
        Ok(true) => crate::routes::staff::named_actuator_json("wake-on-lan", metadata)
            .map(|value| (crate::gate::mutation_status(&value), Json(value)))
            .map_err(|signal| crate::gate::api_error_signal("staff intent", &signal)),
        Ok(false) => Err(crate::gate::api_error("staff intent")),
        Err(_) => Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-profile-missing",
        )),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/network/device/wake",
        axum::routing::post(wake_named_actuator_route),
    )
}
