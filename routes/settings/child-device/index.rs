// Child-device staff command, crossed only through agathodaimon network child-device.
use serde_json::{json, Value};

pub fn command_json(metadata: Value) -> Result<Value, String> {
    crate::routes::staff::named_actuator_json("child-device", metadata)
}

pub fn invoke(args: &[String]) -> Result<Value, String> {
    if args.is_empty() {
        return Err("child-device-command-missing".into());
    }
    crate::gate::snake::crossing_path("network/child-device", &json!({"args": args}))
}
pub fn command(args: &[String]) -> i32 {
    match invoke(args) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

use crate::gate::ApiErrorBody;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    Router,
};

async fn child_device_named_actuator_route(
    _headers: HeaderMap,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    // The exact mounted leaf is checked against its profile namespace, not its wire URL.
    if !crate::gate::roster_allows("POST", "settings/child-device").unwrap_or(false) {
        return Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-route-off-roster",
        ));
    }
    match crate::shared::policy::allows_command("staff intent") {
        Ok(true) => {
            let result = crate::gate::blocking_task("staff intent", move || command_json(metadata))
                .await?;
            result
                .map(|value| (crate::gate::mutation_status(&value), Json(value)))
                .map_err(|signal| crate::gate::api_error_signal("staff intent", &signal))
        }
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
        "/api/v1/settings/child-device",
        axum::routing::post(child_device_named_actuator_route),
    )
}
