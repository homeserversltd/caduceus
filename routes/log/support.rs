use crate::gate::{api_error, api_error_signal, gated_mutation, ApiErrorBody};
use crate::routes::logs;
use crate::shared::policy;
use axum::{
    extract::{Json, Query},
    http::{HeaderMap, StatusCode},
};
use serde_json::Value;
use std::collections::HashMap;
pub(crate) async fn appliance_logs_read_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "logs read";
    match policy::allows_command(COMMAND) {
        Ok(true) => {
            let offset = query
                .get("offset")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(0);
            let limit = query
                .get("limit")
                .and_then(|value| value.parse::<usize>().ok())
                .unwrap_or(logs::DEFAULT_LIMIT)
                .min(logs::MAX_LIMIT);
            let receipt = logs::read_json(offset, limit);
            let status = if logs::is_missing(&receipt) {
                StatusCode::NOT_FOUND
            } else if logs::is_failure(&receipt) {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            };
            Ok((status, Json(receipt)))
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

pub(crate) async fn appliance_logs_clear_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("logs clear", logs::clear_json).await
}
