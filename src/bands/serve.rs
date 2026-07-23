use crate::bands::{
    cert, config, dhcp, dns, gui, health, homeserver_sbin, hyalos, identity, legacy_sbin, local_ai,
    network, pjlink, profile, profile_module, receipts, staff, sync, update,
};
use crate::tools::{attendance, policy};
use axum::{
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, OriginalUri, Query},
    http::{HeaderMap, StatusCode},
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct StaffIntentBody {
    method: String,
    route: String,
    classification: Option<String>,
    metadata: Option<Value>,
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
    let token = token.filter(|value| !value.trim().is_empty()).ok_or_else(|| "caduceus-attendance-not-current".to_string())?;
    let incarnation = env::var("CADUCEUS_DOCUMENT_INCARNATION").map_err(|_| "caduceus-document-incarnation-missing".to_string())?;
    if attendance::admits(token, target, &incarnation) { Ok(()) } else { Err("caduceus-attendance-not-current".to_string()) }
}

fn capability_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-caduceus-attendance")
        .or_else(|| headers.get("x-caduceus-capability"))
        .and_then(|value| value.to_str().ok())
        .or_else(|| headers.get("authorization").and_then(|value| value.to_str().ok()).and_then(|value| value.strip_prefix("Bearer ")))
}

fn capability_admits(command: &str, target: &str, token: Option<&str>) -> Result<(), String> {
    if env::var_os("CADUCEUS_DOCUMENT_INCARNATION").is_some() {
        attendance_admits(target, token).map_err(|_| "caduceus-attendance-not-current".to_string())
    } else {
        policy::capability_admits(command, target, token).map_err(|reason| reason.signal().to_string())
    }
}

async fn attendance_route(
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let result = match uri.path() {
        "/api/v1/attendance/open" => attendance::open_json(&body),
        "/api/v1/attendance/validate" => attendance::validate_json(&body),
        "/api/v1/attendance/invalidate" => attendance::invalidate_json(&body),
        _ => Err("caduceus-attendance-route-invalid".to_string()),
    };
    let signal = match &result {
        Ok(value) => value.get("code").and_then(Value::as_str).unwrap_or("none"),
        Err(error) => error.as_str(),
    };
    let _ = hyalos::reflect_json(serde_json::json!({
        "organ": "caduceus-attendance",
        "kind": "admin-admission",
        "ok": signal == "none",
        "message": if signal == "none" { "attendance-admitted" } else { "attendance-refused" },
        "attributes_redacted": { "route": uri.path(), "first_missing_signal": signal }
    }));
    match result {
        Ok(value) if value.get("ok").and_then(Value::as_bool) == Some(true) => Ok(Json(value)),
        Ok(value) => Err(api_error_signal("attendance", value.get("code").and_then(Value::as_str).unwrap_or("caduceus-attendance-refused"))),
        Err(signal) => Err(api_error_signal("attendance", &signal)),
    }
}

async fn admin_action_admission_route(
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let action = body
        .get("action")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| api_error_signal("admin action", "caduceus-admin-action-malformed"))?;
    let target = body
        .get("target")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 1024)
        .ok_or_else(|| api_error_signal("admin action", "caduceus-admin-action-malformed"))?;
    attendance_admits(target, capability_from_headers(&headers))
        .map_err(|signal| api_error_signal("admin action", &signal))?;
    Ok(Json(serde_json::json!({
        "schema": "caduceus.admin.action-admission.v1",
        "ok": true,
        "code": "none",
        "action": action,
        "target": target,
    })))
}

async fn identity_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("identity show", identity::read_json).await
}

async fn profile_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("profile show", profile::read_json).await
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

async fn staff_intent_route(
    connect_info: Option<ConnectInfo<SocketAddr>>,
    headers: HeaderMap,
    Json(body): Json<StaffIntentBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("staff intent") {
        Ok(true) => {
            let loopback_portal_service = connect_info
                .as_ref()
                .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback())
                && body.classification.as_deref() == Some("portal-service")
                && body.method == "POST"
                && body.route == "/api/service/control";
            if !loopback_portal_service {
                if let Err(reason) = capability_admits(
                    "staff intent",
                    &body.route,
                    capability_from_headers(&headers),
                ) {
                    return Err(api_error_signal("staff intent", &reason));
                }
            }
            match staff::intent_json(
                &body.method,
                &body.route,
                body.classification.as_deref(),
                body.metadata,
            ) {
                Ok(value) => Ok((StatusCode::ACCEPTED, Json(value))),
                Err(err) => Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "staff intent".to_string(),
                        first_missing_signal: missing_signal(&err).to_string(),
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("staff intent")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "staff intent".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
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
            if let Err(reason) =
                capability_admits(command, target, capability_from_headers(headers))
            {
                return Err(api_error_signal(command, &reason));
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

async fn dhcp_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("network dhcp status", dhcp::status_json).await
}

async fn network_dns_route(
    headers: HeaderMap,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let command = "network dns";
    let target = "/api/dns/unbound/drop-in";
    match policy::allows_command(command) {
        Ok(true) => {
            if let Err(reason) =
                capability_admits(command, target, capability_from_headers(&headers))
            {
                return Err(api_error_signal(command, &reason));
            }
            match dns::intent_json("POST", target, metadata) {
                Ok(value) => Ok((mutation_status(&value), Json(value))),
                Err(err) => Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: command.to_string(),
                        first_missing_signal: err,
                    }),
                )),
            }
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
    #[serde(default, alias = "dry_run")]
    dry_run: bool,
}

fn cert_result<F: FnOnce() -> Result<Value, String>>(
    command: &str,
    run: F,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
        Ok(true) => match run() {
            Ok(value) => Ok((mutation_status(&value), Json(value))),
            Err(error) => Err(api_error_signal(command, &error)),
        },
    }
}

async fn cert_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("cert status", cert::status_json).await
}
async fn cert_issue_leaf_route(
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    cert_result("cert issue-leaf", || {
        cert::issue_leaf_json(
            body.identity.as_deref().unwrap_or("home.arpa"),
            body.sans.as_deref().unwrap_or(&[]),
            body.ips.as_deref().unwrap_or(&[]),
            body.dry_run,
        )
    })
}
async fn cert_bundle_route(
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    cert_result("cert bundle create", || {
        cert::bundle_create_json(body.platform.as_deref().unwrap_or("linux"), body.dry_run)
    })
}
async fn cert_apply_route(
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    cert_result("cert apply", || {
        cert::apply_json(
            body.portal.as_deref().unwrap_or(""),
            body.upstream.as_deref().unwrap_or(""),
            body.certificate.as_deref().unwrap_or(""),
            body.key_path.as_deref().unwrap_or(""),
            body.dry_run,
        )
    })
}
async fn cert_trust_route(
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    cert_result("cert trust-install", || {
        cert::trust_install_json(
            body.bundle.as_deref().unwrap_or(""),
            body.platform.as_deref().unwrap_or("linux"),
            body.dry_run,
        )
    })
}
async fn cert_portal_route(
    Json(body): Json<CertBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    cert_result("cert portal-admit", || {
        cert::portal_admit_json(
            body.portal.as_deref().unwrap_or(""),
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
        .route("/api/v1/attendance/invalidate", post(attendance_route))
        .route("/api/v1/admin/action", post(admin_action_admission_route))
        .layer(DefaultBodyLimit::max(8192));
    Router::new()
        .merge(attendance_routes)
        .route("/health", get(health_route))
        .route("/api/v1/identity", get(identity_route))
        .route("/api/v1/profile", get(profile_route))
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
        .route("/api/v1/network/dhcp/status", get(dhcp_status_route))
        .route("/api/v1/network/dns", post(network_dns_route))
        .route("/api/v1/cert/status", get(cert_status_route))
        .route("/api/v1/cert/issue-leaf", post(cert_issue_leaf_route))
        .route("/api/v1/cert/bundle", post(cert_bundle_route))
        .route("/api/v1/cert/bundle/create", post(cert_bundle_route))
        .route("/api/v1/cert/apply", post(cert_apply_route))
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
        .route("/api/v1/staff/intent", post(staff_intent_route))
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
