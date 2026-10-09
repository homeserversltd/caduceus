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
async fn read<F>(
    command: &str,
    f: F,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)>
where
    F: FnOnce() -> Result<Value, String> + Send + 'static,
{
    match policy::allows_command(command) {
        Ok(true) => {
            let result = crate::gate::blocking_task(command, f).await?;
            result.map(Json).map_err(|e| err(command, e))
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}
async fn mutate<F>(
    command: &str,
    route: &str,
    headers: &HeaderMap,
    body: &Value,
    f: F,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)>
where
    F: FnOnce() -> Result<Value, String> + Send + 'static,
{
    match policy::allows_command(command) {
        Ok(true) => {
            administrative_admits(headers, body, route)
                .map_err(|signal| api_error_signal(command, &signal))?;
            let result = crate::gate::blocking_task(command, f).await?;
            result
                .map(|v| (mutation_status(&v), Json(v)))
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
    read("config path", config::path_json).await
}
pub async fn show() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    read("config show", config::show_json).await
}
pub async fn get(
    Query(q): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let path = q.get("path").cloned();
    read("config get", move || {
        config::get_json(
            path.as_deref()
                .ok_or_else(|| "caduceus-household-config-path-invalid".to_string())?,
        )
    })
    .await
}
pub async fn set(
    headers: HeaderMap,
    Json(b): Json<SetBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let admission_body = serde_json::json!({"flags": b.flags.as_ref()});
    let path = b.path;
    let value = b.value;
    mutate(
        "config set",
        "/api/v1/config/set",
        &headers,
        &admission_body,
        move || config::set_json(&path, value),
    )
    .await
}
pub async fn patch(
    headers: HeaderMap,
    Json(b): Json<PatchBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let admission_body = serde_json::json!({"flags": b.flags.as_ref()});
    let merge = b.merge;
    mutate(
        "config patch",
        "/api/v1/config/patch",
        &headers,
        &admission_body,
        move || config::patch_json(merge),
    )
    .await
}
