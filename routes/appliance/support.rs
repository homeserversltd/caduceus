use crate::gate::{
    api_error, api_error_signal, attendance_admits, mutation_status, roster_allows, ApiErrorBody,
};
use crate::routes::staff;
use crate::shared::policy;
use axum::{
    extract::{Json, Path},
    http::{HeaderMap, StatusCode},
};
use serde_json::Value;

const STATUS_DOCUMENT_TARGET: &str = "/api/v1/appliance/service/{service}/status";
const START_DOCUMENT_TARGET: &str = "/api/v1/appliance/service/{service}/start";
const STOP_DOCUMENT_TARGET: &str = "/api/v1/appliance/service/{service}/stop";
const RESTART_DOCUMENT_TARGET: &str = "/api/v1/appliance/service/{service}/restart";
const ENABLE_DOCUMENT_TARGET: &str = "/api/v1/appliance/service/{service}/enable";
const DISABLE_DOCUMENT_TARGET: &str = "/api/v1/appliance/service/{service}/disable";

async fn registered_service_action_route(
    action: &'static str,
    document_target: &'static str,
    headers: HeaderMap,
    service: String,
    body: Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    attendance_admits(
        document_target,
        headers
            .get("x-caduceus-document")
            .and_then(|value| value.to_str().ok()),
        headers
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| api_error_signal("staff intent", &signal))?;

    if body != serde_json::json!({}) {
        return Err(api_error_signal(
            "service action",
            "caduceus-action-request-malformed",
        ));
    }
    let roster_path = format!("/api/v1/appliance/service/:service/{action}");
    let allowed = roster_allows("POST", &roster_path).unwrap_or(false)
        && policy::allows_command("staff intent").unwrap_or(false);
    if allowed {
        staff::execute_registered_service(&service, action)
            .map(|value| (mutation_status(&value), Json(value)))
            .map_err(|reason| api_error_signal("staff intent", &reason))
    } else {
        Err(api_error("staff intent"))
    }
}

pub(crate) async fn registered_service_status_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("status", STATUS_DOCUMENT_TARGET, headers, service, body).await
}

pub(crate) async fn registered_service_start_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("start", START_DOCUMENT_TARGET, headers, service, body).await
}

pub(crate) async fn registered_service_stop_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("stop", STOP_DOCUMENT_TARGET, headers, service, body).await
}

pub(crate) async fn registered_service_restart_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("restart", RESTART_DOCUMENT_TARGET, headers, service, body)
        .await
}

pub(crate) async fn registered_service_enable_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("enable", ENABLE_DOCUMENT_TARGET, headers, service, body).await
}

pub(crate) async fn registered_service_disable_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("disable", DISABLE_DOCUMENT_TARGET, headers, service, body)
        .await
}
