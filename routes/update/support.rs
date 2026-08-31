use crate::gate::{
    api_error, gated_json, gated_mutation, missing_signal, ApiErrorBody, ServiceToggleBody,
};
#[cfg(any(
    leaf_settings_appearance,
    leaf_settings_child_device,
    leaf_settings_datetime,
    leaf_settings_default_apps,
    leaf_settings_display,
    leaf_settings_input,
    leaf_settings_notifications,
    leaf_settings_pin,
    leaf_settings_sound,
    leaf_settings_ssh
))]
use crate::routes::open_settings_pane as gui;
use crate::routes::{receipts, sync_sources as sync, update_appliance as update};
use crate::shared::policy;
use axum::{
    extract::{Json, Query},
    http::{HeaderMap, StatusCode},
};
use serde_json::Value;
use std::collections::HashMap;
pub(crate) async fn update_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("update status", update::read_json).await
}

pub(crate) async fn update_now_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("update now", || update::invoke_now_json(&[])).await
}

pub(crate) async fn sync_now_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("sync now", || sync::invoke_now_json(&[])).await
}

pub(crate) async fn gui_update_now_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("gui update now", || {
        let mut value = gui::invoke_update_now_json(&[]);
        value["action"] = serde_json::json!("gui_update_now");
        value
    })
    .await
}

pub(crate) async fn update_check_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("update check", || update::invoke_check_json(&[])).await
}

pub(crate) async fn receipts_latest_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)>
{
    gated_json("receipts latest", receipts::read_latest_json).await
}

pub(crate) async fn receipts_ledger_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let page = query
        .get("page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1);
    let per_page = query
        .get("per_page")
        .or_else(|| query.get("perPage"))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10);
    match policy::allows_command("receipts ledger") {
        Ok(true) => match receipts::read_ledger_json(page, per_page) {
            Ok(value) => Ok(Json(value)),
            Err(err) => Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: "receipts ledger".to_string(),
                    first_missing_signal: missing_signal(&err).to_string(),
                }),
            )),
        },
        Ok(false) => Err(api_error("receipts ledger")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "receipts ledger".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

pub(crate) async fn update_service_status_route(
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("update service status", update::service_status_json).await
}

pub(crate) async fn update_service_toggle_route(
    headers: HeaderMap,
    Json(body): Json<ServiceToggleBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let state = body.state;
    match policy::allows_command("update service toggle") {
        Ok(true) => match update::service_toggle_json(&state, &[]) {
            Ok(value) => Ok((StatusCode::OK, Json(value))),
            Err(_) => Err(api_error("update service toggle")),
        },
        Ok(false) => Err(api_error("update service toggle")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "update service toggle".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}
