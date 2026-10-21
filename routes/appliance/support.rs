use crate::gate::{
    api_error, api_error_signal, document_attendance_admits, mutation_status, roster_allows,
    ApiErrorBody,
};
use crate::routes::staff;
use crate::shared::policy;
use axum::{
    extract::{Json, Path},
    http::{HeaderMap, StatusCode},
};
use serde_json::Value;

async fn registered_service_action_route(
    action: &'static str,
    headers: HeaderMap,
    service: String,
    body: Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    document_attendance_admits(
        headers
            .get("x-caduceus-document")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
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
    registered_service_action_route("status", headers, service, body).await
}

pub(crate) async fn registered_service_start_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("start", headers, service, body).await
}

pub(crate) async fn registered_service_stop_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("stop", headers, service, body).await
}

pub(crate) async fn registered_service_restart_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("restart", headers, service, body).await
}

pub(crate) async fn registered_service_enable_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("enable", headers, service, body).await
}

pub(crate) async fn registered_service_disable_route(
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    registered_service_action_route("disable", headers, service, body).await
}
