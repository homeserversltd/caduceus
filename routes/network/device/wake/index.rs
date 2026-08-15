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

use crate::gate::{api_error_signal, ApiErrorBody};
use crate::routes::staff;
use crate::shared::attendance;
use axum::{
    extract::{Json, OriginalUri},
    http::{HeaderMap, StatusCode},
    Router,
};

async fn wake_on_lan_staff_actuator_route(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(mut metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let action = match uri.path() {
        "/api/admin/wake-on-lan/send" => "send",
        "/api/admin/wake-on-lan/probe" => "probe",
        _ => {
            return Err(api_error_signal(
                "staff intent",
                "caduceus-wake-on-lan-route-invalid",
            ))
        }
    };
    let object = metadata
        .as_object_mut()
        .ok_or_else(|| api_error_signal("staff intent", "caduceus-wake-on-lan-request-invalid"))?;
    if object.contains_key("action") {
        return Err(api_error_signal(
            "staff intent",
            "caduceus-wake-on-lan-action-client-supplied",
        ));
    }
    object.insert("action".to_string(), Value::String(action.to_string()));
    wake_named_actuator_route(headers, OriginalUri(uri), Json(metadata)).await
}

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

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
// HOIST: obliterate after counterparty realignment
pub fn register(router: Router) -> Router {
    router
        .route(
            "/api/v1/network/device/wake",
            axum::routing::post(wake_on_lan_staff_actuator_route),
        )
        .route(
            "/api/admin/wake-on-lan/send",
            axum::routing::post(wake_on_lan_staff_actuator_route),
        )
        .route(
            "/api/admin/wake-on-lan/probe",
            axum::routing::post(wake_on_lan_staff_actuator_route),
        )
}
