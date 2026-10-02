use crate::gate::{api_error, api_error_signal, administrative_admits, mutation_status, ApiErrorBody};
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
    route: &str,
    headers: &HeaderMap,
    body: &Value,
    f: impl FnOnce() -> Result<Value, String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            administrative_admits(headers, body, route)
                .map_err(|signal| api_error_signal(command, &signal))?;
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
    #[serde(default)]
    pub flags: Option<Value>,
}
#[derive(Deserialize)]
pub struct PatchBody {
    pub merge: Value,
    #[serde(default)]
    pub flags: Option<Value>,
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
    mutate(
        "config set",
        "/api/v1/config/set",
        &headers,
        &serde_json::json!({"flags": b.flags.as_ref()}),
        || config::set_json(&b.path, b.value),
    )
}
pub async fn patch(
    headers: HeaderMap,
    Json(b): Json<PatchBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    mutate(
        "config patch",
        "/api/v1/config/patch",
        &headers,
        &serde_json::json!({"flags": b.flags.as_ref()}),
        || config::patch_json(b.merge),
    )
}
