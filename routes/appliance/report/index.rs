use crate::gate::{gated_json, ApiErrorBody};
use crate::shared::config;
use axum::{extract::Query, http::StatusCode, Json};
use std::collections::HashMap;
use serde_json::{json, Value};

pub fn read_json() -> Result<Value, String> {
    let profile = config::public_profile_present();
    Ok(json!({
        "schema": "caduceus.health.v1",
        "profilePresent": profile,
        "privateLandOrgansExposed": false,
        "ok": profile
    }))
}

pub fn show() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.health.v1");
            println!("profile_present={}", value["profilePresent"]);
            println!("private_land_organs_exposed=false");
            if value["ok"].as_bool() == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("caduceus-health-read-failed: {err}");
            1
        }
    }
}

/// Canonical appliance health report.
async fn report_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("health", read_json).await
}

async fn identity_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("identity show", crate::routes::report_identity::read_json).await
}

async fn legacy_list_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("legacy-sbin list", crate::routes::discovery::legacy_sbin_list_json).await
}

async fn legacy_show_http(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let id = query.get("id").ok_or_else(|| crate::gate::api_error_signal("legacy-sbin show", "caduceus-legacy-sbin-script-id-missing"))?;
    match crate::shared::policy::allows_command("legacy-sbin show") {
        Ok(true) => crate::routes::discovery::legacy_sbin_show_json(id).map(Json).map_err(|_| crate::gate::api_error_signal("legacy-sbin show", "caduceus-legacy-sbin-script-missing")),
        Ok(false) => Err(crate::gate::api_error("legacy-sbin show")),
        Err(_) => Err(crate::gate::api_error_signal("legacy-sbin show", "caduceus-profile-missing")),
    }
}

async fn homeserver_list_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("homeserver-sbin list", crate::routes::discovery::homeserver_sbin_list_json).await
}

async fn homeserver_show_http(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let id = query.get("id").ok_or_else(|| crate::gate::api_error_signal("homeserver-sbin show", "caduceus-homeserver-sbin-script-id-missing"))?;
    match crate::shared::policy::allows_command("homeserver-sbin show") {
        Ok(true) => crate::routes::discovery::homeserver_sbin_show_json(id).map(Json).map_err(|_| crate::gate::api_error_signal("homeserver-sbin show", "caduceus-homeserver-sbin-script-missing")),
        Ok(false) => Err(crate::gate::api_error("homeserver-sbin show")),
        Err(_) => Err(crate::gate::api_error_signal("homeserver-sbin show", "caduceus-profile-missing")),
    }
}

async fn staff_actuators_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("staff actuators", crate::routes::staff::actuators_json).await
}

pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/appliance/report", axum::routing::get(report_http))
        .route("/api/v1/identity", axum::routing::get(identity_http))
        .route("/api/v1/legacy-sbin", axum::routing::get(legacy_list_http))
        .route("/api/v1/legacy-sbin/show", axum::routing::get(legacy_show_http))
        .route("/api/v1/homeserver-sbin", axum::routing::get(homeserver_list_http))
        .route("/api/v1/homeserver-sbin/show", axum::routing::get(homeserver_show_http))
        .route("/api/v1/staff/actuators", axum::routing::get(staff_actuators_http))
}
