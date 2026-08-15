use crate::gate::{
    api_error_signal, document_attendance_admits, gated_json, missing_signal, ApiErrorBody,
};
use crate::routes::{disk, drive_test};
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
};
use serde_json::Value;
pub(crate) async fn disk_census_route(
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "disk census";
    let document = headers
        .get("x-caduceus-document")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    document_attendance_admits(
        document,
        headers
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| api_error_signal(COMMAND, &signal))?;
    disk::census_json().map(Json).map_err(|err| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: COMMAND.to_string(),
                first_missing_signal: missing_signal(&err).to_string(),
            }),
        )
    })
}

pub(crate) async fn hard_drive_test_progress_route(
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("disk test progress", drive_test::progress_json).await
}
