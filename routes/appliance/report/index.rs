use crate::shared::config;
use crate::gate::{gated_json, ApiErrorBody};
use axum::{extract::Query, http::StatusCode, Json};
use std::collections::HashMap;
use serde_json::{json, Value};

pub fn read_json() -> Result<Value, String> {
    let identity = config::read_public_file("etc/caduceus/identity.json").is_ok();
    let profile = config::public_profile_present();
    Ok(json!({
        "schema": "caduceus.health.v1",
        "identityPresent": identity,
        "profilePresent": profile,
        "privateLandOrgansExposed": false,
        "ok": identity && profile
    }))
}

pub fn show() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.health.v1");
            println!("identity_present={}", value["identityPresent"]);
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
async fn report_http() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> { gated_json("health", read_json).await }

pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/appliance/report", axum::routing::get(report_http))
        // HOIST: obliterate after counterparty realignment
        .route("/api/v1/identity", axum::routing::get(legacy_identity))
        // HOIST: obliterate after counterparty realignment
        .route("/api/v1/profile", axum::routing::get(legacy_profile))
        .route("/api/v1/legacy-sbin", axum::routing::get(legacy_list))
        .route("/api/v1/legacy-sbin/show", axum::routing::get(legacy_show))
        .route("/api/v1/homeserver-sbin", axum::routing::get(home_list))
        .route("/api/v1/homeserver-sbin/show", axum::routing::get(home_show))
        .route("/api/v1/staff/actuators", axum::routing::get(staff_actuators))
}

pub async fn legacy_identity() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> { gated_json("identity show", crate::routes::report_identity::read_json).await }
pub async fn legacy_profile() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> { gated_json("profile show", crate::routes::report_profile::read_json).await }
pub async fn legacy_list() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> { gated_json("legacy-sbin list", crate::routes::legacy_sbin::list_json).await }
pub async fn legacy_show(Query(q): Query<HashMap<String,String>>) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> { match crate::shared::policy::allows_command("legacy-sbin show") { Ok(true) => { let id=q.get("id").ok_or_else(|| crate::gate::api_error_signal("legacy-sbin show", "caduceus-legacy-sbin-script-id-missing"))?; crate::routes::legacy_sbin::show_json(id).map(Json).map_err(|_| crate::gate::api_error_signal("legacy-sbin show", "caduceus-legacy-sbin-script-missing")) }, Ok(false)=>Err(crate::gate::api_error("legacy-sbin show")), Err(_)=>Err(crate::gate::api_error_signal("legacy-sbin show", "caduceus-profile-missing")) } }
pub async fn home_list() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> { gated_json("homeserver-sbin list", crate::routes::homeserver_sbin::list_json).await }
pub async fn home_show(Query(q): Query<HashMap<String,String>>) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> { match crate::shared::policy::allows_command("homeserver-sbin show") { Ok(true) => { let id=q.get("id").ok_or_else(|| crate::gate::api_error_signal("homeserver-sbin show", "caduceus-homeserver-sbin-script-id-missing"))?; crate::routes::homeserver_sbin::show_json(id).map(Json).map_err(|_| crate::gate::api_error_signal("homeserver-sbin show", "caduceus-homeserver-sbin-script-missing")) }, Ok(false)=>Err(crate::gate::api_error("homeserver-sbin show")), Err(_)=>Err(crate::gate::api_error_signal("homeserver-sbin show", "caduceus-profile-missing")) } }
pub async fn staff_actuators() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> { gated_json("staff actuators", crate::routes::staff::actuators_json).await }
