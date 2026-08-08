use crate::bands::{
    cert, config, dns, firewall, gui, health, homeserver_sbin, hyalos, identity,
    legacy_sbin, local_ai, network, network_identity, network_notes, network_read, pjlink, profile,
    profile_module, receipts, source_map, staff, sync, tailscale, time, update, vpn,
};
use crate::tools::{attendance, policy};
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, OriginalUri, Path, Query},
    http::{
        header::{CONTENT_DISPOSITION, CONTENT_TYPE},
        HeaderMap, HeaderValue, StatusCode,
    },
    response::Response,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    schema: &'static str,
    ok: bool,
    command: String,
    first_missing_signal: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LivenessBody {
    schema: &'static str,
    ok: bool,
    service: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceToggleBody {
    state: String,
}

#[derive(Deserialize)]
struct ProfileModuleToggleBody {
    #[serde(alias = "moduleId")]
    module_id: String,
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkNotesBody {
    mac: String,
    note: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkDeviceClaimBody {
    mac: String,
    ip: Option<String>,
    #[serde(default)]
    auto_ip: bool,
    hostname: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirewallPutBody {
    schema: String,
    mac: String,
    mode: String,
    sites: Vec<String>,
    expected_revision: String,
    enabled: bool,
    enforcement: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirewallDeleteBody {
    schema: String,
    mac: String,
    expected_revision: String,
}

// Coronatio's MutationActionTarget is a document contract, not a concrete
// resource locator. Keep this independently fixed from Axum's :mac pattern
// and from the client-supplied MAC so document attendance cannot be widened.
const FIREWALL_DOCUMENT_TARGET: &str = "/api/v1/network/firewall/policies/{mac}";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PjlinkPowerBody {
    device_id: String,
    state: String,
    #[serde(default)]
    dry_run: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PjlinkDeviceBody {
    device_id: String,
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    from_profile: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PjlinkRemoveBody {
    id: String,
}

fn api_error_signal(command: &str, signal: &str) -> (StatusCode, Json<ApiErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.to_string(),
            first_missing_signal: signal.to_string(),
        }),
    )
}

fn api_error(command: &str) -> (StatusCode, Json<ApiErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.to_string(),
            first_missing_signal: "caduceus-public-action-not-allowed".to_string(),
        }),
    )
}

fn missing_signal(err: &str) -> &'static str {
    if err.contains("identity") {
        "caduceus-identity-missing"
    } else if err.contains("profile") {
        "caduceus-profile-missing"
    } else {
        "caduceus-profile-missing"
    }
}

async fn gated_json(
    command: &str,
    read: fn() -> Result<Value, String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => match read() {
            Ok(value) => Ok(Json(value)),
            Err(err) => Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: command.to_string(),
                    first_missing_signal: missing_signal(&err).to_string(),
                }),
            )),
        },
        Ok(false) => Err(api_error(command)),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: command.to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

fn mutation_status(value: &Value) -> StatusCode {
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn health_route() -> Json<LivenessBody> {
    Json(LivenessBody {
        schema: "caduceus.liveness.v1",
        ok: true,
        service: "caduceus",
    })
}

async fn gated_mutation(
    command: &str,
    target: &str,
    token: Option<&str>,
    run: fn() -> Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            if let Err(signal) = capability_admits(command, target, token) {
                return Err(api_error_signal(command, &signal));
            }
            let value = run();
            Ok((mutation_status(&value), Json(value)))
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}

/// Administrative mutations are admitted only by a currently open document attendance.
fn attendance_admits(target: &str, token: Option<&str>) -> Result<(), String> {
    let token = token
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "caduceus-attendance-not-current".to_string())?;
    let incarnation = env::var("CADUCEUS_DOCUMENT_INCARNATION")
        .map_err(|_| "caduceus-document-incarnation-missing".to_string())?;
    if attendance::admits(token, target, &incarnation) {
        Ok(())
    } else {
        Err("caduceus-attendance-not-current".to_string())
    }
}

/// Admit attendance bound to the exact document identity forwarded by a Crown.
fn document_attendance_admits(document: &str, token: Option<&str>) -> Result<(), String> {
    let token = token
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "caduceus-attendance-not-current".to_string())?;
    if !document.trim().is_empty() && attendance::admits_target(token, document) {
        Ok(())
    } else {
        Err("caduceus-attendance-not-current".to_string())
    }
}

fn capability_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-caduceus-attendance")
        .or_else(|| headers.get("x-caduceus-capability"))
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
        })
}

fn standalone_capability_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-caduceus-capability")
        .and_then(|value| value.to_str().ok())
        .or_else(|| {
            headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.strip_prefix("Bearer "))
        })
}

fn capability_admits(command: &str, target: &str, token: Option<&str>) -> Result<(), String> {
    if token.is_some_and(|token| attendance::admits_target(token, target)) {
        return Ok(());
    }
    if env::var_os("CADUCEUS_DOCUMENT_INCARNATION").is_some() {
        attendance_admits(target, token).map_err(|_| "caduceus-attendance-not-current".to_string())
    } else {
        policy::capability_admits(command, target, token)
            .map_err(|reason| reason.signal().to_string())
    }
}

async fn attendance_route(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let result = match uri.path() {
        "/api/v1/attendance/open" => attendance::open_json(&body),
        "/api/v1/attendance/validate" => attendance::validate_json(&body),
        "/api/v1/attendance/touch" => attendance::touch_json(&body),
        "/api/v1/attendance/change-pin" => attendance::change_pin_json(&body),
        "/api/v1/attendance/invalidate" => attendance::invalidate_json(&body),
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

async fn registered_service_restart_route(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Path(service): Path<String>,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    if body != serde_json::json!({}) {
        return Err(api_error_signal(
            "service restart",
            "caduceus-action-request-malformed",
        ));
    }
    match policy::allows_command("staff intent") {
        Ok(true) => {
            let loopback = connect_info
                .as_ref()
                .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback());
            if !loopback {
                if let Err(reason) = capability_admits(
                    "staff intent",
                    &service,
                    capability_from_headers(&headers),
                ) {
                    return Err(api_error_signal("staff intent", &reason));
                }
            }
            staff::restart_registered_service(&service)
                .map(|value| (mutation_status(&value), Json(value)))
                .map_err(|reason| api_error_signal("staff intent", &reason))
        }
        Ok(false) => Err(api_error("staff intent")),
        Err(_) => Err(api_error_signal("staff intent", "caduceus-profile-missing")),
    }
}

async fn identity_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("identity show", identity::read_json).await
}

async fn profile_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("profile show", profile::read_json).await
}

async fn profile_sources_reseed_route(
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    if body != serde_json::json!({}) {
        return Err(api_error_signal(
            source_map::public_command(),
            "caduceus-source-map-reseed-arguments-forbidden",
        ));
    }
    gated_mutation(
        source_map::public_command(),
        source_map::target(),
        capability_from_headers(&headers),
        || {
            source_map::reseed_json().unwrap_or_else(|signal| {
                serde_json::json!({
                    "schema": "caduceus.profile.sources.reseed.v1",
                    "ok": false,
                    "changed": false,
                    "firstMissingSignal": signal,
                })
            })
        },
    )
    .await
}

async fn health_api_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("health", health::read_json).await
}

async fn legacy_sbin_list_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("legacy-sbin list", legacy_sbin::list_json).await
}

async fn legacy_sbin_show_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("legacy-sbin show") {
        Ok(true) => {
            let Some(script_id) = query.get("id") else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "legacy-sbin show".to_string(),
                        first_missing_signal: "caduceus-legacy-sbin-script-id-missing".to_string(),
                    }),
                ));
            };
            match legacy_sbin::show_json(script_id) {
                Ok(value) => Ok(Json(value)),
                Err(_) => Err((
                    StatusCode::NOT_FOUND,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "legacy-sbin show".to_string(),
                        first_missing_signal: "caduceus-legacy-sbin-script-missing".to_string(),
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("legacy-sbin show")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "legacy-sbin show".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn homeserver_sbin_list_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("homeserver-sbin list", homeserver_sbin::list_json).await
}

async fn homeserver_sbin_show_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("homeserver-sbin show") {
        Ok(true) => {
            let Some(script_id) = query.get("id") else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "homeserver-sbin show".to_string(),
                        first_missing_signal: "caduceus-homeserver-sbin-script-id-missing"
                            .to_string(),
                    }),
                ));
            };
            match homeserver_sbin::show_json(script_id) {
                Ok(value) => Ok(Json(value)),
                Err(_) => Err((
                    StatusCode::NOT_FOUND,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "homeserver-sbin show".to_string(),
                        first_missing_signal: "caduceus-homeserver-sbin-script-missing".to_string(),
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("homeserver-sbin show")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "homeserver-sbin show".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn staff_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("staff status", staff::status_json).await
}

async fn staff_actuators_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("staff actuators", staff::actuators_json).await
}

fn hyalos_result(
    command: &str,
    run: impl FnOnce() -> Result<Value, String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => run()
            .map(|value| (StatusCode::OK, Json(value)))
            .map_err(|err| api_error_signal(command, &err)),
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}

async fn hyalos_reflect_route(
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    hyalos_result("hyalos reflect", || hyalos::reflect_json(body))
}

async fn hyalos_append_route(
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    hyalos_result("hyalos append", || hyalos::append_json(body))
}

async fn hyalos_tail_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    use crate::tools::hyalos::TailFilters;
    let filters = TailFilters {
        count: query
            .get("count")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(20),
        kind: query.get("kind").cloned(),
        organ: query.get("organ").cloned(),
        world: query.get("world").cloned(),
        correlation_id: query
            .get("correlation_id")
            .or_else(|| query.get("correlationId"))
            .cloned(),
        level: query.get("level").cloned(),
        ok: query.get("ok").and_then(|value| match value.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        }),
    };
    hyalos_result("hyalos tail", || hyalos::tail_json(filters))
}

fn named_actuator_for_route(route: &str) -> Result<&'static str, (StatusCode, Json<ApiErrorBody>)> {
    match route {
        "/api/v1/network/dhcp" => Ok("network-dhcp"),
        "/api/v1/file/ingress" => Ok("file-ingress"),
        "/api/v1/upload/force-permissions" => Ok("upload-force-permissions"),
        "/api/v1/backblaze/recover" => Ok("backblaze-b2-recover"),
        "/api/v1/backblaze/forgejo/b2/push" => Ok("backblaze-forgejo-b2-push"),
        "/api/v1/backblaze/forgejo/migrate" => Ok("backblaze-forgejo-migrate"),
        "/api/v1/calibre/helper-daemon" => Ok("calibre-helper-daemon"),
        "/api/v1/calibre/watch" => Ok("calibre-watch"),
        "/api/v1/keyman/create-key"
        | "/api/v1/keyman/update-key"
        | "/api/v1/keyman/admin-password"
        | "/api/v1/keyman/key-status" => Ok("keyman-doors"),
        "/api/admin/ssh/status"
        | "/api/admin/ssh/toggle"
        | "/api/admin/ssh/service/status"
        | "/api/admin/ssh/service"
        | "/api/admin/samba/status"
        | "/api/admin/samba/service"
        | "/api/admin/system/restart"
        | "/api/admin/system/shutdown"
        | "/api/admin/services/hard-reset" => Ok("service-control-doors"),
        _ => Err(api_error_signal("staff intent", "caduceus-staff-actuator-unmapped")),
    }
}

async fn named_staff_actuator_route(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("staff intent") {
        Ok(true) => {
            if let Err(reason) = capability_admits("staff intent", uri.path(), capability_from_headers(&headers)) {
                return Err(api_error_signal("staff intent", &reason));
            }
            staff::named_actuator_json(named_actuator_for_route(uri.path())?, metadata)
                .map(|value| (mutation_status(&value), Json(value)))
                .map_err(|reason| api_error_signal("staff intent", &reason))
        }
        Ok(false) => Err(api_error("staff intent")),
        Err(_) => Err(api_error_signal("staff intent", "caduceus-profile-missing")),
    }
}

async fn keyman_staff_actuator_route(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(mut metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let action = match uri.path() {
        "/api/v1/keyman/create-key" => "create-key",
        "/api/v1/keyman/update-key" => "update-key",
        "/api/v1/keyman/admin-password" => "admin-password",
        "/api/v1/keyman/key-status" => "key-status",
        _ => return Err(api_error_signal("staff intent", "caduceus-keyman-route-invalid")),
    };
    let object = metadata
        .as_object_mut()
        .ok_or_else(|| api_error_signal("staff intent", "caduceus-keyman-request-invalid"))?;
    if object.contains_key("action") {
        return Err(api_error_signal("staff intent", "caduceus-keyman-action-client-supplied"));
    }
    object.insert("action".to_string(), Value::String(action.to_string()));
    named_staff_actuator_route(headers, OriginalUri(uri), Json(metadata)).await
}

async fn service_control_staff_actuator_route(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(mut metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let action = match uri.path() {
        "/api/admin/ssh/status" => "ssh-password-authentication-status",
        "/api/admin/ssh/toggle" => "ssh-password-authentication-toggle",
        "/api/admin/ssh/service/status" => "ssh-service-status",
        "/api/admin/ssh/service" => "ssh-service-toggle",
        "/api/admin/samba/status" => "samba-service-status",
        "/api/admin/samba/service" => "samba-service-toggle",
        "/api/admin/system/restart" => "system-restart",
        "/api/admin/system/shutdown" => "system-shutdown",
        "/api/admin/services/hard-reset" => "website-hard-reset",
        _ => return Err(api_error_signal("staff intent", "caduceus-service-route-invalid")),
    };
    let object = metadata
        .as_object_mut()
        .ok_or_else(|| api_error_signal("staff intent", "caduceus-service-request-invalid"))?;
    if object.contains_key("action") {
        return Err(api_error_signal("staff intent", "caduceus-service-action-client-supplied"));
    }
    object.insert("action".to_string(), Value::String(action.to_string()));
    named_staff_actuator_route(headers, OriginalUri(uri), Json(metadata)).await
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigSetBody {
    path: String,
    value: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ConfigPatchBody {
    merge: Value,
}

fn config_api_error(command: &str, err: String) -> (StatusCode, Json<ApiErrorBody>) {
    let status = match err.as_str() {
        "caduceus-household-config-path-invalid"
        | "caduceus-household-config-patch-object-required" => StatusCode::BAD_REQUEST,
        "caduceus-household-config-key-missing" => StatusCode::NOT_FOUND,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    (
        status,
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.to_string(),
            first_missing_signal: err,
        }),
    )
}

fn config_read(
    command: &str,
    read: impl FnOnce() -> Result<Value, String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => read()
            .map(Json)
            .map_err(|err| config_api_error(command, err)),
        Ok(false) => Err(api_error(command)),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: command.to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

fn config_mutation(
    command: &str,
    target: &str,
    headers: &HeaderMap,
    run: impl FnOnce() -> Result<Value, String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            // IRIS T01/T02: a visible, enabled regular tab is guest-star-eligible.
            // This narrowly permits only its stored selection; all other config
            // mutations remain subject to capability and current attendance.
            if target != "tabs.starred" {
                let token = capability_from_headers(headers);
                let admission = headers
                    .get("x-caduceus-document")
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| !value.trim().is_empty())
                    .map(|document| document_attendance_admits(document, token))
                    .unwrap_or_else(|| capability_admits(command, target, token));
                if let Err(reason) = admission {
                    return Err(api_error_signal(command, &reason));
                }
            }
            run()
                .map(|value| (mutation_status(&value), Json(value)))
                .map_err(|err| config_api_error(command, err))
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: command.to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn config_path_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    config_read("config path", config::path_json)
}

async fn config_show_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    config_read("config show", config::show_json)
}

async fn config_get_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    config_read("config get", || {
        let path = query
            .get("path")
            .ok_or_else(|| "caduceus-household-config-path-invalid".to_string())?;
        config::get_json(path)
    })
}

async fn config_set_route(
    headers: HeaderMap,
    Json(body): Json<ConfigSetBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    config_mutation("config set", &body.path, &headers, || {
        config::set_json(&body.path, body.value)
    })
}

async fn config_patch_route(
    headers: HeaderMap,
    Json(body): Json<ConfigPatchBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    config_mutation("config patch", "household-config", &headers, || {
        config::patch_json(body.merge)
    })
}

async fn update_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("update status", update::read_json).await
}

async fn network_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("network status", network::status_json).await
}

async fn tailscale_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("tailscale status", tailscale::status_json).await
}

async fn vpn_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("vpn status", vpn::status_json).await
}

async fn network_notes_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("network notes", network_notes::read_json).await
}

fn network_notes_write_error(signal: String) -> (StatusCode, Json<ApiErrorBody>) {
    let status = if signal == "caduceus-network-notes-mac-invalid"
        || signal == "caduceus-network-notes-note-invalid"
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: "network notes write".to_string(),
            first_missing_signal: signal,
        }),
    )
}

async fn network_notes_write_route(
    headers: HeaderMap,
    Json(body): Json<NetworkNotesBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let command = "network notes write";
    match policy::allows_command(command) {
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
        Ok(true) => {
            let document = headers
                .get("x-caduceus-document")
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.trim().is_empty());
            document_attendance_admits(
                document.unwrap_or(""),
                headers
                    .get("x-caduceus-attendance")
                    .and_then(|value| value.to_str().ok()),
            )
            .map_err(|signal| api_error_signal(command, &signal))?;
            network_notes::write_json(&body.mac, &body.note)
                .map(|value| (StatusCode::OK, Json(value)))
                .map_err(network_notes_write_error)
        }
    }
}

async fn network_read_route(
    command: &'static str,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let Some(read) = network_read::named(command) else {
        return Err(api_error(command));
    };
    match policy::allows_command(command) {
        Ok(true) => network_read::invoke(read).map(Json).map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: command.to_string(),
                    first_missing_signal: error,
                }),
            )
        }),
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}

async fn dhcp_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dhcp status").await
}

async fn dhcp_leases_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dhcp leases").await
}

async fn dhcp_reservations_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dhcp reservations list").await
}

async fn dhcp_boundary_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dhcp boundary show").await
}

async fn dns_status_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dns status").await
}

async fn dns_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dns read").await
}

async fn device_list_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network device list").await
}

async fn device_claim_route(
    Json(body): Json<NetworkDeviceClaimBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network device claim";
    match policy::allows_command(COMMAND) {
        Ok(true) => {
            if body.ip.is_some() == body.auto_ip || body.mac.is_empty() || body.hostname.is_empty()
            {
                return Err(api_error_signal(
                    COMMAND,
                    "caduceus-network-identity-claim-arguments-invalid",
                ));
            }
            let mut args = vec!["claim".to_string(), "--mac".to_string(), body.mac];
            if let Some(ip) = body.ip {
                if ip.is_empty() {
                    return Err(api_error_signal(
                        COMMAND,
                        "caduceus-network-identity-claim-arguments-invalid",
                    ));
                }
                args.extend(["--ip".to_string(), ip]);
            } else {
                args.push("--auto-ip".to_string());
            }
            args.extend(["--hostname".to_string(), body.hostname]);
            network_identity::invoke(&args)
                .map(|receipt| (StatusCode::OK, Json(receipt)))
                .map_err(|signal| api_error_signal(COMMAND, &signal))
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

fn firewall_status(value: &Value) -> StatusCode {
    let signal = value
        .get("firstMissingSignal")
        .or_else(|| value.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("");
    match signal {
        signal if signal.contains("policy-not-found") => StatusCode::NOT_FOUND,
        signal if signal.contains("revision-conflict") || signal.contains("binding-mismatch") => {
            StatusCode::CONFLICT
        }
        signal if signal.contains("rollback") && signal.contains("failed") => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        signal
            if signal.contains("staff-")
                || signal.contains("unavailable")
                || signal.contains("live-command") =>
        {
            StatusCode::SERVICE_UNAVAILABLE
        }
        signal
            if signal.contains("invalid")
                || signal.contains("refused")
                || signal.contains("foreign")
                || signal.contains("ambiguous")
                || signal.contains("validator")
                || signal.contains("config") =>
        {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn firewall_refusal(status: StatusCode, signal: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(serde_json::json!({"ok": false, "firstMissingSignal": signal})),
    )
}

fn firewall_mac(value: &str) -> Option<String> {
    let compact = value.to_ascii_lowercase().replace('-', ":");
    let canonical = if compact.len() == 12 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        compact
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).ok())
            .collect::<Option<Vec<_>>>()?
            .join(":")
    } else {
        compact
    };
    let valid = canonical.len() == 17
        && canonical
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && canonical != "00:00:00:00:00:00"
        && canonical != "ff:ff:ff:ff:ff:ff";
    valid.then_some(canonical)
}

fn firewall_fqdns(sites: &[String]) -> bool {
    sites.iter().all(|site| {
        if site.is_empty()
            || site.len() > 253
            || site.ends_with(".home.arpa")
            || site.ends_with(".home.arpa.")
        {
            return false;
        }
        let name = site.trim_end_matches('.');
        name.split('.').count() >= 2
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
    })
}

fn firewall_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn firewall_read(
    action: &str,
    mac: Option<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match policy::allows_command("caduceus.network.firewall.read") {
        Ok(true) => {
            let mut intent = serde_json::json!({"action": action});
            if let Some(mac) = mac {
                intent["mac"] = Value::String(mac);
            }
            firewall::invoke(intent)
                .map(Json)
                .map_err(|value| (firewall_status(&value), Json(value)))
        }
        Ok(false) => Err(firewall_refusal(
            StatusCode::FORBIDDEN,
            "caduceus-public-action-not-allowed",
        )),
        Err(_) => Err(firewall_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-profile-missing",
        )),
    }
}

async fn firewall_status_route() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_read("status", None)
}

async fn firewall_policies_route() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_read("list", None)
}

async fn firewall_policy_route(
    axum::extract::Path(mac): axum::extract::Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mac = firewall_mac(&mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    firewall_read("get", Some(mac))
}

async fn firewall_put_route(
    headers: HeaderMap,
    axum::extract::Path(path_mac): axum::extract::Path<String>,
    Json(body): Json<FirewallPutBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let command = "caduceus.network.firewall.put";
    let path = firewall_mac(&path_mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    let mac = firewall_mac(&body.mac)
        .filter(|mac| mac == &path)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-mismatch"))?;
    if body.schema != "caduceus.network.firewall.policy.v1"
        || body.mode != "allow-only"
        || body.enforcement != "dns-policy"
        || !(1..=64).contains(&body.sites.len())
        || !firewall_fqdns(&body.sites)
        || !firewall_digest(&body.expected_revision)
    {
        return Err(firewall_refusal(
            StatusCode::BAD_REQUEST,
            "firewall-input-invalid",
        ));
    }
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => {
            return Err(firewall_refusal(
                StatusCode::FORBIDDEN,
                "caduceus-public-action-not-allowed",
            ))
        }
        Err(_) => {
            return Err(firewall_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "caduceus-profile-missing",
            ))
        }
    }
    capability_admits(
        command,
        FIREWALL_DOCUMENT_TARGET,
        capability_from_headers(&headers),
    )
    .map_err(|signal| firewall_refusal(StatusCode::FORBIDDEN, &signal))?;
    let intent = if body.enabled {
        serde_json::json!({"action":"put", "mac":mac, "fqdns":body.sites, "revision":body.expected_revision})
    } else {
        serde_json::json!({"action":"delete", "mac":mac, "revision":body.expected_revision})
    };
    firewall::invoke(intent)
        .map(|value| (StatusCode::OK, Json(value)))
        .map_err(|value| (firewall_status(&value), Json(value)))
}

async fn firewall_delete_route(
    headers: HeaderMap,
    axum::extract::Path(path_mac): axum::extract::Path<String>,
    Json(body): Json<FirewallDeleteBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let command = "caduceus.network.firewall.delete";
    let path = firewall_mac(&path_mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    let mac = firewall_mac(&body.mac)
        .filter(|mac| mac == &path)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-mismatch"))?;
    if body.schema != "caduceus.network.firewall.policy.delete.v1"
        || !firewall_digest(&body.expected_revision)
    {
        return Err(firewall_refusal(
            StatusCode::BAD_REQUEST,
            "firewall-input-invalid",
        ));
    }
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => {
            return Err(firewall_refusal(
                StatusCode::FORBIDDEN,
                "caduceus-public-action-not-allowed",
            ))
        }
        Err(_) => {
            return Err(firewall_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "caduceus-profile-missing",
            ))
        }
    }
    capability_admits(
        command,
        FIREWALL_DOCUMENT_TARGET,
        capability_from_headers(&headers),
    )
    .map_err(|signal| firewall_refusal(StatusCode::FORBIDDEN, &signal))?;
    firewall::invoke(
        serde_json::json!({"action":"delete", "mac":mac, "revision":body.expected_revision}),
    )
    .map(|value| (StatusCode::OK, Json(value)))
    .map_err(|value| (firewall_status(&value), Json(value)))
}

async fn time_state_route(
    connect_info: Option<ConnectInfo<SocketAddr>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let lan_peer = connect_info.is_some_and(|ConnectInfo(peer)| match peer.ip() {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback(),
        std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
    });
    if !lan_peer {
        return Err(api_error_signal("time state", "caduceus-time-lan-only"));
    }
    gated_json("time state", time::state_json).await
}

fn dns_mutation_admits(
    command: &'static str,
    target: &'static str,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(command)),
        Err(_) => return Err(api_error_signal(command, "caduceus-profile-missing")),
    }
    let document = headers
        .get("x-caduceus-document")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty());
    if let Some(document) = document {
        document_attendance_admits(
            document,
            headers
                .get("x-caduceus-attendance")
                .and_then(|value| value.to_str().ok()),
        )
        .map_err(|signal| api_error_signal(command, &signal))
    } else {
        capability_admits(command, target, standalone_capability_from_headers(headers))
            .map_err(|signal| api_error_signal(command, &signal))
    }
}

fn dns_mutation_response(
    command: &'static str,
    result: Result<Value, String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    result
        .map(|value| (mutation_status(&value), Json(value)))
        .map_err(|err| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: command.to_string(),
                    first_missing_signal: err,
                }),
            )
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsDeviceNameBody {
    hostname: String,
    ip: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsAliasBody {
    label: String,
    hostname: String,
}

async fn network_dns_route(
    headers: HeaderMap,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns intent";
    const TARGET: &str = "/api/dns/unbound/drop-in";
    dns_mutation_admits(COMMAND, TARGET, &headers)?;
    dns_mutation_response(COMMAND, dns::intent_json("POST", TARGET, metadata))
}

async fn dns_device_name_create_route(
    headers: HeaderMap,
    Json(body): Json<DnsDeviceNameBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns device-name create";
    dns_mutation_admits(COMMAND, "/api/dns/device-name/create", &headers)?;
    dns_mutation_response(
        COMMAND,
        dns::device_name_json("create", &body.hostname, &body.ip),
    )
}

async fn dns_device_name_remove_route(
    headers: HeaderMap,
    Json(body): Json<DnsDeviceNameBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns device-name remove";
    dns_mutation_admits(COMMAND, "/api/dns/device-name/remove", &headers)?;
    dns_mutation_response(
        COMMAND,
        dns::device_name_json("remove", &body.hostname, &body.ip),
    )
}

async fn dns_alias_create_route(
    headers: HeaderMap,
    Json(body): Json<DnsAliasBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns alias create";
    dns_mutation_admits(COMMAND, "/api/dns/alias/create", &headers)?;
    dns_mutation_response(
        COMMAND,
        dns::alias_json("create", &body.label, &body.hostname),
    )
}

async fn dns_alias_remove_route(
    headers: HeaderMap,
    Json(body): Json<DnsAliasBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns alias remove";
    dns_mutation_admits(COMMAND, "/api/dns/alias/remove", &headers)?;
    dns_mutation_response(
        COMMAND,
        dns::alias_json("remove", &body.label, &body.hostname),
    )
}

#[derive(Deserialize, Default)]
struct CertQuery {
    platform: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct CertBody {
    identity: Option<String>,
    sans: Option<Vec<String>>,
    ips: Option<Vec<String>>,
    platform: Option<String>,
    bundle: Option<String>,
    portal: Option<String>,
    lan_ip: Option<String>,
    upstream: Option<String>,
    certificate: Option<String>,
    key_path: Option<String>,
    aliases: Option<Vec<String>>,
    renewal_authority: Option<String>,
    #[serde(default, alias = "dry_run")]
    dry_run: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
struct CsrSignBody {
    csr_pem: String,
}

fn cert_api_error(command: &str, signal: &str) -> (StatusCode, Json<Value>) {
    cert_value_error(StatusCode::FORBIDDEN, command, signal)
}

fn cert_value_error(status: StatusCode, command: &str, signal: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(serde_json::json!({
            "schema": "caduceus.api.error.v1",
            "ok": false,
            "command": command,
            "firstMissingSignal": signal,
        })),
    )
}

fn cert_profile_refusal(command: &str, primitive: &str) -> (StatusCode, Json<Value>) {
    let role = policy::load_profile_value()
        .ok()
        .and_then(|profile| {
            profile
                .get("profile")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "schema": "caduceus.cert.profile_refused.v1",
            "ok": false,
            "primitive": primitive,
            "role": role,
            "refused_verb": command,
            "firstMissingSignal": "profile_refused",
        })),
    )
}

fn cert_admitted_command(command: &str, aliases: &[&str]) -> Result<Option<String>, String> {
    if policy::allows_command(command)? {
        return Ok(Some(command.to_string()));
    }
    for alias in aliases {
        if policy::allows_command(alias)? {
            return Ok(Some((*alias).to_string()));
        }
    }
    Ok(None)
}

fn cert_mutation_result<F: FnOnce() -> Result<Value, String>>(
    command: &str,
    target: &str,
    primitive: &str,
    aliases: &[&str],
    headers: &HeaderMap,
    run: F,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    match cert_admitted_command(command, aliases) {
        Ok(None) => Err(cert_profile_refusal(command, primitive)),
        Err(_) => Err(cert_api_error(command, "caduceus-profile-missing")),
        Ok(Some(admitted_command)) => {
            capability_admits(&admitted_command, target, capability_from_headers(headers))
                .map_err(|signal| cert_api_error(command, &signal))?;
            match run() {
                Ok(value) => Ok((mutation_status(&value), Json(value))),
                Err(error) => Err(cert_api_error(command, &error)),
            }
        }
    }
}

async fn cert_status_route() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match cert_admitted_command("cert status", &[]) {
        Ok(None) => Err(cert_profile_refusal("cert status", "status")),
        Err(_) => Err(cert_api_error("cert status", "caduceus-profile-missing")),
        Ok(Some(_)) => cert::status_json()
            .map(Json)
            .map_err(|signal| cert_api_error("cert status", &signal)),
    }
}
async fn cert_ensure_root_route(
    headers: HeaderMap,
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    cert_mutation_result("cert ensure-root", "local", "ensure_root", &[], &headers, || {
        cert::ensure_root_json(body.dry_run, body.renewal_authority.as_deref())
    })
}
async fn cert_issue_leaf_route(
    headers: HeaderMap,
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let target = body.identity.as_deref().unwrap_or("home.arpa");
    cert_mutation_result("cert issue-leaf", target, "issue_leaf", &[], &headers, || {
        cert::issue_leaf_json(
            target,
            body.sans.as_deref().unwrap_or(&[]),
            body.ips.as_deref().unwrap_or(&[]),
            body.dry_run,
        )
    })
}
async fn cert_csr_sign_route(
    headers: HeaderMap,
    Json(body): Json<CsrSignBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let command = "cert csr sign";
    match cert_admitted_command(command, &[]) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(cert_profile_refusal(command, "sign_csr")),
        Err(_) => return Err(cert_api_error(command, "caduceus-profile-missing")),
    };
    let document = headers
        .get("x-caduceus-document")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    document_attendance_admits(
        document,
        headers
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| cert_api_error(command, &signal))?;
    cert::sign_csr_json(&body.csr_pem)
        .map(|value| (StatusCode::OK, Json(value)))
        .map_err(|error| cert_value_error(StatusCode::BAD_REQUEST, command, &error))
}
async fn cert_bundle_route(
    headers: HeaderMap,
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let target = body.platform.as_deref().unwrap_or("linux");
    cert_mutation_result(
        "cert bundle-export",
        target,
        "bundle_export",
        &["cert bundle create"],
        &headers,
        || cert::bundle_create_json(target, body.dry_run),
    )
}
async fn cert_constituent_lock_route(
    headers: HeaderMap,
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let portal = body.portal.as_deref().unwrap_or("");
    cert_mutation_result(
        "cert constituent-lock",
        portal,
        "constituent_lock",
        &[],
        &headers,
        || cert::constituent_lock_json(portal, body.lan_ip.as_deref().unwrap_or(""), body.dry_run),
    )
}
async fn cert_bundle_download_route(
    Query(query): Query<CertQuery>,
) -> Result<Response<Body>, (StatusCode, Json<Value>)> {
    let command = "cert bundle download";
    match cert_admitted_command(command, &[]) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(cert_profile_refusal(command, "bundle_read")),
        Err(_) => return Err(cert_api_error(command, "caduceus-profile-missing")),
    }
    let platform = query.platform.as_deref().unwrap_or("linux");
    let bundle = cert::bundle_download_json(platform).map_err(|signal| {
        let status = match signal.as_str() {
            "caduceus-cert-platform-invalid" => StatusCode::BAD_REQUEST,
            "caduceus-cert-bundle-missing" => StatusCode::NOT_FOUND,
            _ => StatusCode::SERVICE_UNAVAILABLE,
        };
        cert_value_error(status, command, &signal)
    })?;
    let disposition =
        HeaderValue::from_str(&format!(r#"attachment; filename="{}""#, bundle.filename))
            .map_err(|_| cert_api_error(command, "caduceus-cert-bundle-filename-invalid"))?;
    let content_type = HeaderValue::from_str(&bundle.mime_type)
        .map_err(|_| cert_api_error(command, "caduceus-cert-bundle-mime-invalid"))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_DISPOSITION, disposition)
        .body(Body::from(bundle.bytes))
        .map_err(|_| cert_api_error(command, "caduceus-cert-bundle-response-invalid"))
}
async fn legacy_cert_bundle_download_route(
    Query(query): Query<CertQuery>,
) -> Result<Response<Body>, (StatusCode, Json<Value>)> {
    let command = "cert bundle create";
    match cert_admitted_command(command, &["cert bundle-export"]) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(cert_profile_refusal(command, "bundle_export")),
        Err(_) => return Err(cert_api_error(command, "caduceus-profile-missing")),
    }
    let platform = query.platform.as_deref().unwrap_or("linux");
    let bundle = cert::legacy_bundle_download(platform).map_err(|signal| {
        let status = match signal.as_str() {
            "caduceus-cert-platform-invalid" => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        cert_value_error(status, command, &signal)
    })?;
    let disposition = HeaderValue::from_str(&format!(r#"attachment; filename="{}""#, bundle.filename))
        .map_err(|_| cert_api_error(command, "caduceus-cert-bundle-filename-invalid"))?;
    let content_type = HeaderValue::from_str(&bundle.mime_type)
        .map_err(|_| cert_api_error(command, "caduceus-cert-bundle-mime-invalid"))?;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(CONTENT_DISPOSITION, disposition)
        .body(Body::from(bundle.bytes))
        .map_err(|_| cert_api_error(command, "caduceus-cert-bundle-response-invalid"))
}

async fn legacy_cert_refresh_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    cert_mutation_result(
        "cert refresh-root",
        "root-ca",
        "refresh_root",
        &[],
        &headers,
        cert::legacy_refresh_root_json,
    )
}

async fn cert_apply_route(
    headers: HeaderMap,
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let target = body.portal.as_deref().unwrap_or("");
    cert_mutation_result(
        "cert apply-nginx",
        target,
        "apply_nginx",
        &["cert apply"],
        &headers,
        || {
            cert::apply_json(
                target,
                body.upstream.as_deref().unwrap_or(""),
                body.certificate.as_deref().unwrap_or(""),
                body.key_path.as_deref().unwrap_or(""),
                body.dry_run,
            )
        },
    )
}
async fn cert_trust_route(
    headers: HeaderMap,
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let target = body.bundle.as_deref().unwrap_or("");
    cert_mutation_result("cert trust-install", target, "trust_install", &[], &headers, || {
        cert::trust_install_json(
            target,
            body.platform.as_deref().unwrap_or("linux"),
            body.dry_run,
        )
    })
}
async fn cert_portal_route(
    headers: HeaderMap,
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let target = body.portal.as_deref().unwrap_or("");
    cert_mutation_result("cert portal-admit", target, "portal_admit", &[], &headers, || {
        cert::portal_admit_json(
            target,
            body.lan_ip.as_deref().unwrap_or(""),
            body.upstream.as_deref().unwrap_or(""),
            body.aliases.as_deref().unwrap_or(&[]),
            body.dry_run,
        )
    })
}

async fn pjlink_devices_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("pjlink devices", pjlink::devices_json).await
}

async fn pjlink_known_products_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("pjlink known-products", pjlink::known_products_json).await
}

async fn pjlink_scan_route(
    headers: HeaderMap,
    Json(body): Json<PjlinkDeviceBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("pjlink scan") {
        Ok(true) => {
            if let Err(reason) = capability_admits(
                "pjlink scan",
                &body.device_id,
                capability_from_headers(&headers),
            ) {
                return Err(api_error_signal("pjlink scan", &reason));
            }
            match pjlink::scan_product_json(&body.device_id, body.dry_run) {
                Ok(value) => Ok((mutation_status(&value), Json(value))),
                Err(err) => Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "pjlink scan".to_string(),
                        first_missing_signal: err,
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("pjlink scan")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "pjlink scan".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn pjlink_known_add_route(
    headers: HeaderMap,
    Json(body): Json<PjlinkDeviceBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("pjlink known add") {
        Ok(true) => {
            if let Err(reason) = capability_admits(
                "pjlink known add",
                &body.device_id,
                capability_from_headers(&headers),
            ) {
                return Err(api_error_signal("pjlink known add", &reason));
            }
            match pjlink::add_known_product_json(&body.device_id, body.dry_run, body.from_profile) {
                Ok(value) => Ok((StatusCode::OK, Json(value))),
                Err(err) => Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "pjlink known add".to_string(),
                        first_missing_signal: err,
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("pjlink known add")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "pjlink known add".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn pjlink_known_remove_route(
    headers: HeaderMap,
    Json(body): Json<PjlinkRemoveBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("pjlink known remove") {
        Ok(true) => {
            if let Err(reason) = capability_admits(
                "pjlink known remove",
                &body.id,
                capability_from_headers(&headers),
            ) {
                return Err(api_error_signal("pjlink known remove", &reason));
            }
            match pjlink::remove_known_product_json(&body.id) {
                Ok(value) => Ok((StatusCode::OK, Json(value))),
                Err(err) => Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "pjlink known remove".to_string(),
                        first_missing_signal: err,
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("pjlink known remove")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "pjlink known remove".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn pjlink_power_status_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("pjlink power status") {
        Ok(true) => {
            let Some(device_id) = query.get("deviceId").or_else(|| query.get("device_id")) else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "pjlink power status".to_string(),
                        first_missing_signal: "caduceus-pjlink-device-id-missing".to_string(),
                    }),
                ));
            };
            pjlink::power_status_json(device_id)
                .map(Json)
                .map_err(|err| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        Json(ApiErrorBody {
                            schema: "caduceus.api.error.v1",
                            ok: false,
                            command: "pjlink power status".to_string(),
                            first_missing_signal: err,
                        }),
                    )
                })
        }
        Ok(false) => Err(api_error("pjlink power status")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "pjlink power status".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn pjlink_power_route(
    headers: HeaderMap,
    Json(body): Json<PjlinkPowerBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("pjlink power set") {
        Ok(true) => {
            if let Err(reason) = capability_admits(
                "pjlink power set",
                &body.device_id,
                capability_from_headers(&headers),
            ) {
                return Err(api_error_signal("pjlink power set", &reason));
            }
            match pjlink::power_json(&body.device_id, &body.state, body.dry_run) {
                Ok(value) => Ok((mutation_status(&value), Json(value))),
                Err(err) => Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "pjlink power set".to_string(),
                        first_missing_signal: err,
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("pjlink power set")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "pjlink power set".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn update_now_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation(
        "update now",
        "local",
        capability_from_headers(&headers),
        || update::invoke_now_json(&[]),
    )
    .await
}

async fn update_check_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation(
        "update check",
        "local",
        capability_from_headers(&headers),
        || update::invoke_check_json(&[]),
    )
    .await
}

async fn sync_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("sync status", sync::read_json).await
}

async fn sync_now_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation(
        "sync now",
        "local",
        capability_from_headers(&headers),
        || sync::invoke_now_json(&[]),
    )
    .await
}

async fn receipts_latest_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("receipts latest", receipts::read_latest_json).await
}

async fn receipts_ledger_route(
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

async fn update_service_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("update service status", update::service_status_json).await
}

async fn gui_update_now_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation(
        "gui update now",
        "local",
        capability_from_headers(&headers),
        || gui::invoke_update_now_json(&[]),
    )
    .await
}

async fn local_ai_runtime_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("local-ai runtime status", local_ai::runtime_status_json).await
}

async fn local_ai_runtime_check_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("local-ai runtime check", local_ai::runtime_status_json).await
}

async fn local_ai_runtime_update_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation(
        "local-ai runtime update",
        "local",
        capability_from_headers(&headers),
        || local_ai::invoke_runtime_update_json(&[]),
    )
    .await
}

async fn profile_module_toggle_route(
    headers: HeaderMap,
    Json(body): Json<ProfileModuleToggleBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let module_id = body.module_id;
    match policy::allows_command("profile module toggle") {
        Ok(true) => {
            if let Err(reason) = capability_admits(
                "profile module toggle",
                &module_id,
                capability_from_headers(&headers),
            ) {
                return Err(api_error_signal("profile module toggle", &reason));
            }
            match profile_module::toggle_json(&module_id, body.enabled) {
                Ok(value) => Ok((StatusCode::OK, Json(value))),
                Err(_) => Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "profile module toggle".to_string(),
                        first_missing_signal: "caduceus-profile-module-toggle-failed".to_string(),
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("profile module toggle")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "profile module toggle".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

async fn update_service_toggle_route(
    headers: HeaderMap,
    Json(body): Json<ServiceToggleBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let state = body.state;
    match policy::allows_command("update service toggle") {
        Ok(true) => {
            if let Err(reason) = capability_admits(
                "update service toggle",
                &state,
                capability_from_headers(&headers),
            ) {
                return Err(api_error_signal("update service toggle", &reason));
            }
            match update::service_toggle_json(&state, &[]) {
                Ok(value) => Ok((StatusCode::OK, Json(value))),
                Err(_) => Err(api_error("update service toggle")),
            }
        }
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

pub fn router() -> Router {
    let attendance_routes = Router::new()
        .route("/api/v1/attendance/open", post(attendance_route))
        .route("/api/v1/attendance/validate", post(attendance_route))
        .route("/api/v1/attendance/touch", post(attendance_route))
        .route("/api/v1/attendance/change-pin", post(attendance_route))
        .route("/api/v1/attendance/invalidate", post(attendance_route))
        .route(
            "/api/v1/service/:service/restart",
            post(registered_service_restart_route),
        );
    Router::new()
        .merge(attendance_routes)
        .route("/health", get(health_route))
        .route("/api/v1/identity", get(identity_route))
        .route("/api/v1/profile", get(profile_route))
        .route(
            "/api/v1/profile/sources/reseed",
            post(profile_sources_reseed_route),
        )
        .route("/api/v1/health", get(health_api_route))
        .route("/api/v1/legacy-sbin", get(legacy_sbin_list_route))
        .route("/api/v1/legacy-sbin/show", get(legacy_sbin_show_route))
        .route("/api/v1/homeserver-sbin", get(homeserver_sbin_list_route))
        .route(
            "/api/v1/homeserver-sbin/show",
            get(homeserver_sbin_show_route),
        )
        .route("/api/v1/config/path", get(config_path_route))
        .route("/api/v1/config/show", get(config_show_route))
        .route("/api/v1/config/get", get(config_get_route))
        .route("/api/v1/config/set", post(config_set_route))
        .route("/api/v1/config/patch", post(config_patch_route))
        .route("/api/v1/update/status", get(update_status_route))
        .route("/api/v1/network/status", get(network_status_route))
        .route("/api/v1/tailscale/status", get(tailscale_status_route))
        .route("/api/v1/vpn/status", get(vpn_status_route))
        .route(
            "/api/v1/network/notes",
            get(network_notes_read_route).put(network_notes_write_route),
        )
        .route("/api/v1/network/dhcp/status", get(dhcp_status_route))
        .route("/api/v1/network/dhcp/leases", get(dhcp_leases_route))
        .route(
            "/api/v1/network/dhcp/reservations",
            get(dhcp_reservations_route),
        )
        .route("/api/v1/network/dhcp/boundary", get(dhcp_boundary_route))
        .route("/api/v1/network/dns/status", get(dns_status_read_route))
        .route("/api/v1/network/dns/read", get(dns_read_route))
        .route("/api/v1/network/device", get(device_list_route))
        .route("/api/v1/network/device/claim", post(device_claim_route))
        .route(
            "/api/v1/network/firewall/status",
            get(firewall_status_route),
        )
        .route(
            "/api/v1/network/firewall/policies",
            get(firewall_policies_route),
        )
        .route(
            "/api/v1/network/firewall/policies/:mac",
            get(firewall_policy_route)
                .put(firewall_put_route)
                .delete(firewall_delete_route),
        )
        .route("/api/v1/time/state", get(time_state_route))
        .route("/api/v1/network/dns", post(network_dns_route))
        .route(
            "/api/v1/network/dns/device-name/create",
            post(dns_device_name_create_route),
        )
        .route(
            "/api/v1/network/dns/device-name/remove",
            post(dns_device_name_remove_route),
        )
        .route(
            "/api/v1/network/dns/alias/create",
            post(dns_alias_create_route),
        )
        .route(
            "/api/v1/network/dns/alias/remove",
            post(dns_alias_remove_route),
        )
        .route("/api/v1/cert/status", get(cert_status_route))
        .route("/api/v1/cert/ensure-root", post(cert_ensure_root_route))
        .route("/api/v1/cert/issue-leaf", post(cert_issue_leaf_route))
        .route(
            "/api/v1/cert/csr/sign",
            post(cert_csr_sign_route).layer(DefaultBodyLimit::max(65536)),
        )
        .route("/api/v1/cert/bundle", post(cert_bundle_route))
        .route("/api/v1/cert/bundle/create", post(cert_bundle_route))
        .route("/api/v1/cert/bundle-export", post(cert_bundle_route))
        .route(
            "/api/v1/cert/bundle/download",
            get(cert_bundle_download_route),
        )
        .route(
            "/api/admin/download-root-crt",
            get(legacy_cert_bundle_download_route),
        )
        .route("/api/admin/refresh-root-crt", post(legacy_cert_refresh_route))
        .route("/api/v1/cert/apply", post(cert_apply_route))
        .route("/api/v1/cert/apply-nginx", post(cert_apply_route))
        .route(
            "/api/v1/cert/constituent-lock",
            post(cert_constituent_lock_route),
        )
        .route("/api/v1/cert/trust-install", post(cert_trust_route))
        .route("/api/v1/cert/portal-admit", post(cert_portal_route))
        .route("/api/v1/pjlink/devices", get(pjlink_devices_route))
        .route(
            "/api/v1/pjlink/known-products",
            get(pjlink_known_products_route).post(pjlink_known_add_route),
        )
        .route(
            "/api/v1/pjlink/known-products/remove",
            post(pjlink_known_remove_route),
        )
        .route("/api/v1/pjlink/product/scan", post(pjlink_scan_route))
        .route(
            "/api/v1/pjlink/power/status",
            get(pjlink_power_status_route),
        )
        .route("/api/v1/pjlink/power", post(pjlink_power_route))
        .route("/api/v1/staff/status", get(staff_status_route))
        .route("/api/v1/staff/actuators", get(staff_actuators_route))
        .route("/api/v1/network/dhcp", post(named_staff_actuator_route))
        .route("/api/v1/file/ingress", post(named_staff_actuator_route))
        .route("/api/v1/upload/force-permissions", post(named_staff_actuator_route))
        .route("/api/v1/backblaze/recover", post(named_staff_actuator_route))
        .route("/api/v1/backblaze/forgejo/b2/push", post(named_staff_actuator_route))
        .route("/api/v1/backblaze/forgejo/migrate", post(named_staff_actuator_route))
        .route("/api/v1/calibre/helper-daemon", post(named_staff_actuator_route))
        .route("/api/v1/calibre/watch", post(named_staff_actuator_route))
        .route("/api/v1/keyman/create-key", post(keyman_staff_actuator_route))
        .route("/api/v1/keyman/update-key", post(keyman_staff_actuator_route))
        .route("/api/v1/keyman/admin-password", post(keyman_staff_actuator_route))
        .route("/api/v1/keyman/key-status", post(keyman_staff_actuator_route))
        .route("/api/admin/ssh/status", post(service_control_staff_actuator_route))
        .route("/api/admin/ssh/toggle", post(service_control_staff_actuator_route))
        .route("/api/admin/ssh/service/status", post(service_control_staff_actuator_route))
        .route("/api/admin/ssh/service", post(service_control_staff_actuator_route))
        .route("/api/admin/samba/status", post(service_control_staff_actuator_route))
        .route("/api/admin/samba/service", post(service_control_staff_actuator_route))
        .route("/api/admin/system/restart", post(service_control_staff_actuator_route))
        .route("/api/admin/system/shutdown", post(service_control_staff_actuator_route))
        .route("/api/admin/services/hard-reset", post(service_control_staff_actuator_route))
        .route("/api/v1/hyalos/reflect", post(hyalos_reflect_route))
        .route("/api/v1/hyalos/append", post(hyalos_append_route))
        .route("/api/v1/hyalos/tail", get(hyalos_tail_route))
        .route("/api/v1/update/now", post(update_now_route))
        .route("/api/v1/update/check", post(update_check_route))
        .route("/api/v1/sync/status", get(sync_status_route))
        .route("/api/v1/sync/now", post(sync_now_route))
        .route("/api/v1/receipts/latest", get(receipts_latest_route))
        .route("/api/v1/receipts/ledger", get(receipts_ledger_route))
        .route(
            "/api/v1/update/service/status",
            get(update_service_status_route),
        )
        .route(
            "/api/v1/update/service/toggle",
            post(update_service_toggle_route),
        )
        .route("/api/v1/gui/update/now", post(gui_update_now_route))
        .route(
            "/api/v1/local-ai/runtime/status",
            get(local_ai_runtime_status_route),
        )
        .route(
            "/api/v1/local-ai/runtime/check",
            post(local_ai_runtime_check_route),
        )
        .route(
            "/api/v1/local-ai/runtime/update",
            post(local_ai_runtime_update_route),
        )
        .route(
            "/api/v1/profile/module/toggle",
            post(profile_module_toggle_route),
        )
        .layer(DefaultBodyLimit::max(8192))
}

pub async fn run_async() -> i32 {
    let bind = env::var("CADUCEUS_BIND").unwrap_or_else(|_| "0.0.0.0:8787".to_string());
    let addr: SocketAddr = match bind.parse() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("caduceus-bind-invalid: {err}");
            return 1;
        }
    };

    attendance::bind();
    let app = router();

    let listener = match TcpListener::bind(addr).await {
        Ok(value) => value,
        Err(err) => {
            eprintln!("caduceus-bind-failed: {err}");
            return 1;
        }
    };

    eprintln!("caduceus serve listening on {addr}");
    match axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("caduceus-serve-failed: {err}");
            1
        }
    }
}

pub fn run() -> i32 {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("caduceus-serve-runtime-failed: {err}");
            return 1;
        }
    };
    runtime.block_on(run_async())
}
