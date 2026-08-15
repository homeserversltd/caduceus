use crate::gate::{api_error, api_error_signal, mutation_status, roster_allows, ApiErrorBody};
use crate::routes::staff;
use crate::shared::policy;
use axum::{
    extract::{ConnectInfo, Json, Path},
    http::{HeaderMap, StatusCode},
};
use serde_json::Value;
use std::net::SocketAddr;
pub(crate) async fn registered_service_restart_route(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    if body != serde_json::json!({}) {
        return Err(api_error_signal(
            "service restart",
            "caduceus-action-request-malformed",
        ));
    }
    let allowed = roster_allows("POST", "/api/v1/appliance/service/:service/restart").unwrap_or(false)
        && policy::allows_command("staff intent").unwrap_or(false);
    if allowed {
        staff::restart_registered_service(&service)
            .map(|value| (mutation_status(&value), Json(value)))
            .map_err(|reason| api_error_signal("staff intent", &reason))
    } else {
        Err(api_error("staff intent"))
    }
}
