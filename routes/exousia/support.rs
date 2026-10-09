use crate::gate::ConnectionInfo;
use crate::gate::{
    access_attendance_admits, api_error, api_error_signal, gated_json, gated_mutation,
    mutation_status, blocking_task, vault_attendance_admits, ApiErrorBody, VAULT_ATTENDANCE_COMMAND,
};
use crate::routes::{change_pin, hyalos, open_vault, staff};
use crate::shared::{attendance, policy};
use axum::{
    extract::{ConnectInfo, Json, OriginalUri, Path},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultSupportUnlockBody {
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    flags: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct VaultSupportAutoBody {
    enabled: bool,
    #[serde(default)]
    flags: Option<Value>,
}

pub(crate) async fn posture_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("exousia posture read", attendance::posture_json).await
}

pub(crate) async fn pin_mode_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    blocking_task("access pin mode", crate::shared::attendance::pin_mode_json)
        .await
        .map(Json)
}

pub(crate) async fn pin_mode_route(
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    access_attendance_admits(
        &headers,
        &body,
        "/api/v1/access/pin/mode",
    )?;
    let mut body = body;
    crate::gate::strip_administrative_flags(&mut body);
    blocking_task("access pin mode", move || change_pin::set_pin_mode_json(&body))
        .await?
        .map(Json)
        .map_err(|signal| api_error_signal("access pin mode", &signal))
}

pub(crate) async fn sudo_mode_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    blocking_task("access sudo mode", crate::shared::attendance::sudo_mode_json)
        .await
        .map(Json)
}

pub(crate) async fn sudo_mode_route(
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    access_attendance_admits(
        &headers,
        &body,
        "/api/v1/access/sudo/mode",
    )?;
    let mut body = body;
    crate::gate::strip_administrative_flags(&mut body);
    blocking_task("access sudo mode", move || change_pin::set_sudo_mode_json(&body))
        .await?
        .map(Json)
        .map_err(|signal| api_error_signal("access sudo mode", &signal))
}

pub(crate) async fn pin_reset_default_route(
    connect_info: Option<ConnectInfo<ConnectionInfo>>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    if !peer_is_loopback(connect_info.as_ref()) {
        return Err(api_error_signal(
            "access pin reset-default",
            "caduceus-local-access-required",
        ));
    }
    blocking_task("access pin reset-default", move || {
        change_pin::reset_default_pin_json(&body)
    })
    .await?
        .map(Json)
        .map_err(|signal| api_error_signal("access pin reset-default", &signal))
}

fn peer_is_loopback(connect_info: Option<&ConnectInfo<ConnectionInfo>>) -> bool {
    matches!(
        connect_info,
        Some(ConnectInfo(ConnectionInfo::Tcp(addr))) if addr.ip().is_loopback()
    )
}

#[cfg(test)]
mod tests {
    use super::peer_is_loopback;
    use crate::gate::ConnectionInfo;
    use axum::extract::ConnectInfo;
    use std::net::SocketAddr;

    #[test]
    fn peer_is_loopback_accepts_only_loopback_tcp_peers() {
        assert!(peer_is_loopback(Some(&ConnectInfo(ConnectionInfo::Tcp(
            "127.0.0.1:43210".parse::<SocketAddr>().unwrap(),
        )))));
        assert!(peer_is_loopback(Some(&ConnectInfo(ConnectionInfo::Tcp(
            "[::1]:43210".parse::<SocketAddr>().unwrap(),
        )))));
        assert!(!peer_is_loopback(Some(&ConnectInfo(ConnectionInfo::Tcp(
            "192.168.1.50:43210".parse::<SocketAddr>().unwrap(),
        )))));
        assert!(!peer_is_loopback(None));
    }
}

pub(crate) async fn vault_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json(VAULT_ATTENDANCE_COMMAND, || Ok(open_vault::status_json())).await
}

pub(crate) async fn vault_unlock_route(
    headers: HeaderMap,
    Json(body): Json<VaultSupportUnlockBody>,
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
    vault_attendance_admits(
        &headers,
        &serde_json::json!({"flags": body.flags.as_ref()}),
        "/api/v1/storage/vault/unlock",
    )?;
    Ok((
        StatusCode::OK,
        Json(open_vault::unlock_json(body.password.as_deref())),
    ))
}

pub(crate) async fn vault_auto_route(
    headers: HeaderMap,
    Json(body): Json<VaultSupportAutoBody>,
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
    vault_attendance_admits(
        &headers,
        &serde_json::json!({"flags": body.flags.as_ref()}),
        "/api/v1/storage/vault/auto-decrypt",
    )?;
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
    // Only gate-populated transport metadata can authorize browser-child derivation.
    let trusted_unix_carrier = matches!(
        connect_info.as_ref(),
        Some(ConnectInfo(ConnectionInfo::Unix { .. }))
    );
    let result = match uri.path() {
        "/api/v1/exousia/open" | "/api/v1/attendance/open" => {
            let request_body = body.clone();
            blocking_task("attendance", move || {
                attendance::open_request_json(&request_body, trusted_unix_carrier)
            })
            .await?
        }
        "/api/v1/exousia/validate" | "/api/v1/attendance/validate" => {
            attendance::validate_json(&body)
        }
        "/api/v1/exousia/touch" | "/api/v1/attendance/touch" => attendance::touch_json(&body),
        "/api/v1/exousia/change-pin"
        | "/api/v1/access/pin/change"
        | "/api/v1/attendance/change-pin" => {
            let request_body = body.clone();
            blocking_task("attendance", move || attendance::change_pin_json(&request_body))
                .await?
        }
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
            "peer": connect_info.map(|ConnectInfo(peer)| peer.to_string()).unwrap_or_else(|| "unknown".to_string()),
        })
    );
    let reflection = serde_json::json!({
        "organ": "caduceus-attendance",
        "kind": "admin-admission",
        "ok": signal == "none",
        "message": if signal == "none" { "attendance-admitted" } else { "attendance-refused" },
        "attributes_redacted": { "route": uri.path(), "first_missing_signal": signal }
    });
    let _ = blocking_task("hyalos reflect", move || hyalos::reflect_json(reflection)).await?;
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
