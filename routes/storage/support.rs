use crate::gate::{
    api_error, api_error_signal, document_attendance_admits, gated_json, missing_signal,
    mutation_status, ApiErrorBody, HardDriveTestStartBody,
};
use crate::routes::{disk, drive_test};
use crate::shared::policy;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
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

pub(crate) async fn hard_drive_test_results_route(
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("disk test results", drive_test::results_json).await
}

pub(crate) async fn hard_drive_test_start_route(
    headers: HeaderMap,
    Json(body): Json<HardDriveTestStartBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "disk test start";
    match policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(COMMAND)),
        Err(_) => return Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
    drive_test::start_json(&body.device, &body.test_type, body.dry_run)
        .map(|value| (mutation_status(&value), Json(value)))
        .map_err(|signal| api_error_signal(COMMAND, &signal))
}
