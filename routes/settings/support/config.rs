use crate::gate::{
    api_error, api_error_signal, document_attendance_admits, mutation_status, ApiErrorBody,
};
use crate::shared::{config, policy};
use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    Json,
};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
fn err(command: &str, e: String) -> (StatusCode, Json<ApiErrorBody>) {
    if e.contains("config-path-invalid") {
        (
            StatusCode::BAD_REQUEST,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: command.into(),
                first_missing_signal: e,
            }),
        )
    } else {
        api_error_signal(command, &e)
    }
}
fn read(
    command: &str,
    f: impl FnOnce() -> Result<Value, String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => f().map(Json).map_err(|e| err(command, e)),
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}
fn mutate(
    command: &str,
    target: &str,
    headers: &HeaderMap,
    f: impl FnOnce() -> Result<Value, String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            if target != "tabs.starred" {
                if let Some(doc) = headers
                    .get("x-caduceus-document")
                    .and_then(|v| v.to_str().ok())
                    .filter(|v| !v.trim().is_empty())
                {
                    document_attendance_admits(
                        doc,
                        headers
                            .get("x-caduceus-attendance")
                            .and_then(|v| v.to_str().ok()),
                    )
                    .map_err(|e| api_error_signal(command, &e))?;
                }
            }
            f().map(|v| (mutation_status(&v), Json(v)))
                .map_err(|e| err(command, e))
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}
#[derive(Deserialize)]
pub struct SetBody {
    pub path: String,
    pub value: Value,
}
#[derive(Deserialize)]
pub struct PatchBody {
    pub merge: Value,
}
pub async fn path() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    read("config path", config::path_json)
}
pub async fn show() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    read("config show", config::show_json)
}
pub async fn get(
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    read("config get", || {
        config::get_json(
            q.get("path")
                .ok_or_else(|| "caduceus-household-config-path-invalid".to_string())?,
        )
    })
}
pub async fn set(
    headers: HeaderMap,
    Json(b): Json<SetBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    mutate("config set", &b.path, &headers, || {
        config::set_json(&b.path, b.value)
    })
}
pub async fn patch(
    headers: HeaderMap,
    Json(b): Json<PatchBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    mutate("config patch", "household-config", &headers, || {
        config::patch_json(b.merge)
    })
}
