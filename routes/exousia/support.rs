use crate::gate::ConnectionInfo;
use crate::gate::{
    access_attendance_admits, api_error, api_error_signal, gated_json, gated_mutation,
    mutation_status, vault_attendance_admits, ApiErrorBody, VaultAutoBody, VaultUnlockBody,
    VAULT_ATTENDANCE_COMMAND,
};
use crate::routes::{change_pin, hyalos, open_vault, staff};
use crate::shared::{attendance, policy};
use axum::{
    extract::{ConnectInfo, Json, OriginalUri, Path},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::Value;

pub(crate) async fn pin_mode_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    Ok(Json(crate::shared::attendance::pin_mode_json()))
}

pub(crate) async fn pin_mode_route(
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    access_attendance_admits(&headers)?;
    change_pin::set_pin_mode_json(&body)
        .map(Json)
        .map_err(|signal| api_error_signal("access pin mode", &signal))
}

pub(crate) async fn pin_reset_default_route(
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    if body != serde_json::json!({"action":"reset-default"}) {
        return Err(api_error_signal(
            "access pin reset-default",
            "caduceus-access-pin-reset-default-invalid",
        ));
    }
    access_attendance_admits(&headers)?;
    change_pin::reset_default_pin_json()
        .map(Json)
        .map_err(|signal| api_error_signal("access pin reset-default", &signal))
}

pub(crate) async fn vault_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json(VAULT_ATTENDANCE_COMMAND, || Ok(open_vault::status_json())).await
}

pub(crate) async fn vault_unlock_route(
    headers: HeaderMap,
    Json(body): Json<VaultUnlockBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(VAULT_ATTENDANCE_COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(VAULT_ATTENDANCE_COMMAND)),
        Err(_) => {
            return Err(api_error_signal(
                VAULT_ATTENDANCE_COMMAND,
                "caduceus-profile-missing",
            ))
        }
    }
    vault_attendance_admits(&headers)?;
    Ok((
        StatusCode::OK,
        Json(open_vault::unlock_json(body.password.as_deref())),
    ))
}

pub(crate) async fn vault_auto_route(
    headers: HeaderMap,
    Json(body): Json<VaultAutoBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(VAULT_ATTENDANCE_COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(VAULT_ATTENDANCE_COMMAND)),
        Err(_) => {
            return Err(api_error_signal(
                VAULT_ATTENDANCE_COMMAND,
                "caduceus-profile-missing",
            ))
        }
    }
    vault_attendance_admits(&headers)?;
    Ok((
        StatusCode::OK,
        Json(open_vault::auto_decrypt_json(body.enabled)),
    ))
}

pub(crate) async fn attendance_route(
    connect_info: Option<ConnectInfo<ConnectionInfo>>,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let result = match uri.path() {
        "/api/v1/exousia/open" | "/api/v1/attendance/open" => attendance::open_json(&body),
        "/api/v1/exousia/validate" | "/api/v1/attendance/validate" => {
            attendance::validate_json(&body)
        }
        "/api/v1/exousia/touch" | "/api/v1/attendance/touch" => attendance::touch_json(&body),
        "/api/v1/exousia/change-pin"
        | "/api/v1/access/pin/change"
        | "/api/v1/attendance/change-pin" => attendance::change_pin_json(&body),
        "/api/v1/exousia/invalidate" | "/api/v1/attendance/invalidate" => {
            attendance::invalidate_json(&body)
        }
        _ => Err("caduceus-attendance-route-invalid".to_string()),
    };
    let signal = match &result {
        Ok(value) => value.get("code").and_then(Value::as_str).unwrap_or("none"),
        Err(error) => error.as_str(),
    };
    let attendance_id = body.get("attendance").and_then(Value::as_str).or_else(|| {
        result
            .as_ref()
            .ok()
            .and_then(|value| value.get("attendance"))
            .and_then(Value::as_str)
    });
    eprintln!(
        "{}",
        serde_json::json!({
            "event": "caduceus-access-request",
            "route": uri.path(),
            "firstMissingSignal": signal,
            "documentId": body.get("documentId").and_then(Value::as_str),
            "attendanceId": attendance_id,
            "peer": connect_info.map(|ConnectInfo(peer)| peer.to_string()).unwrap_or_else(|| "unknown".to_string()), // UDS credentials are audit/readback only, never admission
        })
    );
    let _ = hyalos::reflect_json(serde_json::json!({
        "organ": "caduceus-attendance",
        "kind": "admin-admission",
        "ok": signal == "none",
        "message": if signal == "none" { "attendance-admitted" } else { "attendance-refused" },
        "attributes_redacted": { "route": uri.path(), "first_missing_signal": signal }
    }));
    match result {
        Ok(value) if value.get("ok").and_then(Value::as_bool) == Some(true) => Ok(Json(value)),
        Ok(value) => Err(api_error_signal(
            "attendance",
            value
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("caduceus-attendance-refused"),
        )),
        Err(signal) => Err(api_error_signal("attendance", &signal)),
    }
}
