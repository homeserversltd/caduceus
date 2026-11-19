use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::routes::logs;
use crate::shared::{hyalos::LogFilters, policy};
use axum::{
    extract::{Json, Query},
    http::StatusCode,
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
                .unwrap_or(logs::DEFAULT_LIMIT);
            let level = query.get("level").map(|value| value.parse::<i64>()).transpose()
                .map_err(|_| {
                    let (_, body) = api_error_signal(COMMAND, "caduceus-hyalos-read-level-invalid");
                    (StatusCode::BAD_REQUEST, body)
                })?;
            let filters = LogFilters {
                kind: query.get("kind").cloned(),
                organ: query.get("organ").cloned(),
                verb: query.get("verb").cloned(),
                level,
                since: query.get("since").cloned(),
            };
            let receipt = crate::gate::blocking_task(COMMAND, move || {
                logs::read_filtered(offset, limit, filters)
            })
            .await?;
            let status = if logs::is_failure(&receipt) {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            };
            Ok((status, Json(receipt)))
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
}
