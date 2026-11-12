use crate::gate::{
    api_error, api_error_signal, blocking_task, gated_json, gated_mutation, missing_signal,
    service_unavailable, ApiErrorBody,
};
use crate::routes::{receipts, sync_sources as sync, update_appliance as update};
use crate::shared::policy;
use axum::{
    extract::{rejection::JsonRejection, Json, Query},
    http::{HeaderMap, StatusCode},
};
use serde_json::Value;
use std::collections::HashMap;
pub(crate) async fn update_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("update status", update::read_json).await
}

pub(crate) async fn update_now_route(
    _headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("update now") {
        Ok(true) => {
            let value = blocking_task("update now", || update::invoke_now_json(&[])).await?;
            let status = match value.get("state").and_then(Value::as_str) {
                Some("started") => StatusCode::ACCEPTED,
                Some("busy") => StatusCode::CONFLICT,
                Some("unknown") if value.get("ok").and_then(Value::as_bool) == Some(true) => {
                    StatusCode::ACCEPTED
                }
                Some("unknown" | "failed") => StatusCode::SERVICE_UNAVAILABLE,
                _ if value.get("ok").and_then(Value::as_bool) == Some(true) => StatusCode::OK,
                _ => StatusCode::SERVICE_UNAVAILABLE,
            };
            Ok((status, Json(value)))
        }
        Ok(false) => Err(api_error("update now")),
        Err(_) => Err(api_error_signal("update now", "caduceus-carapace-desync")),
    }
}

pub(crate) async fn sync_now_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("sync now", || sync::invoke_now_json(&[])).await
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
    let module = query.get("module").cloned();
    match policy::allows_command("receipts ledger") {
        Ok(true) => {
            let result = blocking_task("receipts ledger", move || {
                receipts::read_ledger_json(page, per_page, module.as_deref())
            })
            .await?;
            match result {
                Ok(value) => Ok(Json(value)),
                Err(_) => Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "receipts ledger".to_string(),
                        first_missing_signal: "caduceus-harmonia-ledger-unreadable".to_string(),
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("receipts ledger")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "receipts ledger".to_string(),
                first_missing_signal: "caduceus-carapace-desync".to_string(),
            }),
        )),
    }
}

pub(crate) async fn update_service_status_route() -> (StatusCode, Json<Value>) {
    match policy::allows_command("update service status") {
        Ok(true) => {
            let value = match tokio::task::spawn_blocking(update::service_status_json).await {
                Ok(Ok(value)) => value,
                Ok(Err(signal)) => update::service_native("status", &signal, false, "status"),
                Err(_) => update::service_native("status", "caduceus-blocking-task-failed", false, "join"),
            };
            let status = if value["ok"].as_bool() == Some(true) && update::service_bound(&value) && value.get("doorSignal").is_none() { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
            (status, Json(value))
        }
        Ok(false) => (StatusCode::FORBIDDEN, Json(update::service_native("status", "caduceus-public-action-not-allowed", false, "policy"))),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(update::service_native("status", "caduceus-carapace-desync", false, "policy"))),
    }
}

pub(crate) async fn update_service_toggle_route(
    _headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> (StatusCode, Json<Value>) {
    let state = body.ok().and_then(|Json(body)| {
        body.get("state").or_else(|| body.pointer("/payload/state"))
            .and_then(Value::as_str).filter(|state| matches!(*state, "on" | "off"))
            .map(str::to_owned)
    });
    let Some(state) = state else {
        return (StatusCode::FORBIDDEN, Json(update::service_native("toggle", "caduceus-public-action-not-allowed", false, "input")));
    };
    match policy::allows_command("update service toggle") {
        Ok(true) => {
            let request = state.clone();
            let value = match tokio::task::spawn_blocking(move || update::service_toggle_json(&request, &[])).await {
                Ok(Ok(value)) => value,
                Ok(Err(signal)) => update::service_native(&state, &signal, false, "toggle"),
                Err(_) => update::service_native(&state, "caduceus-blocking-task-failed", false, "join"),
            };
            let status = if value["ok"].as_bool() == Some(true) && update::service_bound(&value) && value.get("doorSignal").is_none() { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
            (status, Json(value))
        }
        Ok(false) => (StatusCode::FORBIDDEN, Json(update::service_native(&state, "caduceus-public-action-not-allowed", false, "policy"))),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, Json(update::service_native(&state, "caduceus-carapace-desync", false, "policy"))),
    }
}
