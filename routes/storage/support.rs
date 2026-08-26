use crate::gate::{
    api_error, api_error_signal, document_attendance_admits, gated_json, missing_signal,
    ApiErrorBody,
};
use crate::routes::{disk, drive_test};
use crate::storage_categories;
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

pub(crate) async fn storage_categories_route(
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "storage categories";
    let document = headers
        .get("x-caduceus-document")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    document_attendance_admits(
        document,
        headers
            .get("x-caduceus-attendance")
            .and_then(|v| v.to_str().ok()),
    )
    .map_err(|signal| api_error_signal(COMMAND, &signal))?;
    storage_categories::cached_json().map(Json).map_err(|err| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: COMMAND.to_string(),
                first_missing_signal: err,
            }),
        )
    })
}

pub(crate) async fn storage_categories_scan_route(
    headers: HeaderMap,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "storage categories scan";
    let document = headers
        .get("x-caduceus-document")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    document_attendance_admits(
        document,
        headers
            .get("x-caduceus-attendance")
            .and_then(|v| v.to_str().ok()),
    )
    .map_err(|signal| api_error_signal(COMMAND, &signal))?;
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => storage_categories::scan_json().map(Json).map_err(|err| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: COMMAND.to_string(),
                    first_missing_signal: err,
                }),
            )
        }),
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}
