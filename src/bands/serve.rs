use crate::bands::{
    cert, config, dhcp, gui, health, homeserver_sbin, hyalos, identity, legacy_sbin, local_ai,
    network, pjlink, profile, profile_module, receipts, staff, sync, update,
};
use crate::tools::{access, policy};
use axum::{
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, OriginalUri, Query},
    http::{HeaderMap, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
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

fn capability_from_headers(headers: &HeaderMap) -> Option<&str> {
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

/// The actual actuator boundary. Once staff has projected its current public
/// key/epoch, static legacy verification is not a fallback: verification,
/// profile/scope/expiry/epoch checks, and atomic one-use consumption occur
/// before `run` is reached.
fn capability_admits(command: &str, target: &str, token: Option<&str>) -> Result<(), String> {
    let state = access_state();
    let profile_value =
        policy::load_profile_value().map_err(|_| "caduceus-profile-missing".to_string())?;
    let successor_required = profile_value
        .pointer("/capability/mode")
        .and_then(Value::as_str)
        == Some("successor-required");
    if state
        .has_projection()
        .map_err(|reason| reason.signal().to_string())?
    {
        let profile = profile_value
            .get("profile")
            .and_then(Value::as_str)
            .ok_or_else(|| "caduceus-profile-missing".to_string())?;
        let token = token
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| access::AccessReason::Unsigned.signal().to_string())?;
        return state
            .verify_and_consume(token, command, target, profile)
            .map_err(|reason| reason.signal().to_string());
    }
    if successor_required {
        return Err(access::AccessReason::Unsigned.signal().to_string());
    }
    policy::capability_admits(command, target, token).map_err(|reason| reason.signal().to_string())
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

async fn health_route() -> Json<LivenessBody> {
    Json(LivenessBody {
        schema: "caduceus.liveness.v1",
        ok: true,
        service: "caduceus",
    })
}

/// This handler is deliberately reached only after `reject_nonloopback_access`.
/// The JSON extractor therefore cannot buffer or parse a non-loopback body.
fn access_operation(path: &str) -> Option<&'static str> {
    match path {
        "/api/v1/access/challenges/mint" => Some("challenge.mint"),
        "/api/v1/access/sessions/mint" => Some("session.mint"),
        "/api/v1/access/sessions/prove" => Some("session.prove"),
        "/api/v1/access/sessions/clear" => Some("session.clear"),
        "/api/v1/access/capabilities/mint" => Some("capability.mint"),
        "/api/v1/access/pin/change" => Some("pin.change"),
        _ => None,
    }
}

fn bounded_text<'a>(body: &'a Value, field: &str, maximum: usize) -> Option<&'a str> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= maximum)
}

/// Challenge context is purpose-shaped at the public boundary. The staff owns
/// cryptographic verification and exact equality; Rust only bounds structure.
fn bounded_challenge_context(purpose: &str, body: &Value) -> bool {
    let Some(context) = body.get("context").filter(|value| value.is_object()) else {
        return false;
    };
    if !serde_json::to_vec(context)
        .ok()
        .is_some_and(|encoded| encoded.len() <= 4096)
    {
        return false;
    }

    match purpose {
        "session.mint" => {
            let Some(public_key) = context
                .get("document_public_key")
                .filter(|value| value.is_object())
            else {
                return false;
            };
            bounded_text(public_key, "kty", 16) == Some("EC")
                && bounded_text(public_key, "crv", 16) == Some("P-256")
                && bounded_text(public_key, "x", 1024).is_some()
                && bounded_text(public_key, "y", 1024).is_some()
        }
        "session.prove" => {
            bounded_text(context, "ticket", 4096).is_some()
                && bounded_text(context, "method", 16).is_some()
                && bounded_text(context, "target", 1024).is_some()
        }
        "session.clear" => {
            bounded_text(context, "ticket", 4096).is_some()
                && match context.get("target") {
                    None => true,
                    Some(_) => bounded_text(context, "target", 1024).is_some(),
                }
        }
        "capability.mint" => {
            bounded_text(context, "ticket", 4096).is_some()
                && bounded_text(context, "action", 512).is_some()
                && bounded_text(context, "target", 1024).is_some()
        }
        "pin.change" => {
            bounded_text(context, "ticket", 4096).is_some()
                && bounded_text(context, "action", 512) == Some("global.admin.pin.rotate")
                && bounded_text(context, "target", 1024) == Some("global.admin.pin")
        }
        _ => false,
    }
}

fn has_document_proof(body: &Value) -> bool {
    bounded_text(body, "challenge_id", 512).is_some()
        && bounded_text(body, "signature", 4096).is_some()
}

fn has_attendance_ticket(body: &Value) -> bool {
    bounded_text(body, "ticket", 4096).is_some()
}

/// The staff remains the attendance authority. Rust only rejects malformed public
/// envelopes before the private socket and never interprets tickets as authority.
fn validate_access_request(operation: &str, body: &Value) -> Result<(), &'static str> {
    match operation {
        "challenge.mint" => {
            let Some(purpose) = bounded_text(body, "purpose", 64) else {
                return Err("caduceus-attendance-challenge-malformed");
            };
            if !bounded_challenge_context(purpose, body) {
                return Err("caduceus-attendance-challenge-malformed");
            }
        }
        "session.mint" => {
            if bounded_text(body, "pin", 1024).is_none() {
                return Err("caduceus-attendance-refused");
            }
            if !has_document_proof(body) {
                return Err("caduceus-attendance-proof-malformed");
            }
        }
        "session.prove" | "session.clear" => {
            if !has_document_proof(body) {
                return Err("caduceus-attendance-proof-malformed");
            }
            if !has_attendance_ticket(body) {
                return Err("caduceus-attendance-refused");
            }
        }
        "capability.mint" => {
            if !has_document_proof(body) {
                return Err("caduceus-attendance-proof-malformed");
            }
            if !has_attendance_ticket(body)
                || bounded_text(body, "action", 512).is_none()
                || bounded_text(body, "target", 1024).is_none()
            {
                return Err("caduceus-attendance-refused");
            }
        }
        "pin.change" => {
            if !has_document_proof(body) {
                return Err("caduceus-attendance-proof-malformed");
            }
            if !has_attendance_ticket(body)
                || bounded_text(body, "capability", 8192).is_none()
                || bounded_text(body, "new_pin", 1024).is_none()
            {
                return Err("caduceus-attendance-refused");
            }
        }
        _ => return Err("caduceus-access-request-invalid"),
    }
    Ok(())
}

fn safe_access_code(value: &Value) -> &'static str {
    match value.get("code").and_then(Value::as_str) {
        Some("challenge_malformed") | Some("challenge-malformed") => {
            "caduceus-attendance-challenge-malformed"
        }
        Some("proof_malformed") | Some("proof-malformed") => "caduceus-attendance-proof-malformed",
        Some("challenge_expired") | Some("challenge-expired") => {
            "caduceus-attendance-challenge-expired"
        }
        Some("challenge_replayed") | Some("challenge-replayed") => {
            "caduceus-attendance-challenge-replayed"
        }
        Some("staff_unavailable") | Some("staff-unavailable") => "caduceus-staff-unavailable",
        _ => "caduceus-attendance-refused",
    }
}

/// Successful material is an operation-specific, direct-loopback transport only.
/// It is never copied into diagnostics, Hyalos, errors, or refusal envelopes.
fn public_access_response(operation: &str, value: Value) -> Value {
    let ok = value.get("ok").and_then(Value::as_bool) == Some(true);
    let mut response = serde_json::json!({
        "schema": "caduceus.access.attendance.v1",
        "ok": ok,
        "code": if ok { "none" } else { safe_access_code(&value) },
    });
    if !ok {
        return response;
    }

    let copy_text = |response: &mut Value, output: &str, input: &str, maximum: usize| {
        if let Some(value) = value
            .get(input)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= maximum)
        {
            response[output] = Value::String(value.to_string());
        }
    };
    let copy_expiry = |response: &mut Value| {
        if let Some(expires_at) = value.get("expires_at").or_else(|| value.get("expiresAt")) {
            if expires_at.is_u64() {
                response["expires_at"] = expires_at.clone();
            }
        }
    };
    match operation {
        "challenge.mint" => {
            copy_text(&mut response, "challenge_id", "challenge_id", 512);
            if response.get("challenge_id").is_none() {
                copy_text(&mut response, "challenge_id", "challengeId", 512);
            }
            copy_text(&mut response, "challenge", "challenge", 4096);
            if response.get("challenge").is_none() {
                copy_text(&mut response, "challenge", "challenge_bytes", 4096);
            }
            copy_expiry(&mut response);
        }
        "session.mint" => copy_text(&mut response, "ticket", "ticket", 4096),
        "capability.mint" => copy_text(&mut response, "capability", "capability", 8192),
        "session.prove" | "session.clear" | "pin.change" => {}
        _ => {}
    }
    response
}

async fn access_route(
    OriginalUri(uri): OriginalUri,
    Json(mut body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let expected = access_operation(uri.path())
        .ok_or_else(|| api_error_signal("access", "caduceus-access-request-invalid"))?;
    validate_access_request(expected, &body)
        .map_err(|signal| api_error_signal("access", signal))?;
    body["op"] = Value::String(expected.to_string());
    let operation = body.get("op").and_then(Value::as_str).unwrap_or("");
    if operation.is_empty() {
        return Err(api_error_signal(
            "access",
            "caduceus-access-request-invalid",
        ));
    }
    let socket = env::var("CADUCEUS_ACCESS_SOCKET")
        .unwrap_or_else(|_| "/run/caduceus/access.sock".to_string());
    let started = std::time::Instant::now();
    let request_body = body.clone();
    let result = tokio::task::spawn_blocking(move || {
        access::staff_request(std::path::Path::new(&socket), &request_body)
    })
    .await
    .map_err(|_| api_error_signal("access", access::AccessReason::Unavailable.signal()))?
    .map_err(|reason| api_error_signal("access", reason.signal()))?;
    if let (Some(key), Some(epoch)) = (
        result.get("public_key").and_then(Value::as_str),
        result.get("epoch").and_then(Value::as_u64),
    ) {
        if let Err(reason) = access_state().install_public_projection(key, epoch) {
            return Err(api_error_signal("access", reason.signal()));
        }
    }
    let public_response = public_access_response(operation, result);
    let signal = public_response
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("caduceus-attendance-refused");
    let section = if operation == "challenge.mint" {
        "access.document"
    } else if operation.starts_with("session") {
        "access.attendance"
    } else if operation.starts_with("capability") {
        "access.capability"
    } else {
        "access.pin-change"
    };
    let correlation_id = body
        .get("correlation_id")
        .and_then(Value::as_str)
        .unwrap_or("generated");
    let outcome = if public_response.get("ok").and_then(Value::as_bool) == Some(true) {
        "ok"
    } else {
        "refused"
    };
    let audit = access::DiagnosticEvent::new(
        section,
        correlation_id,
        operation,
        outcome,
        started,
        signal,
        access_state().clock.now(),
    );
    // This audit path has no configuration switch. In-memory diagnostics remain
    // bounded/TTL; Hyalos is the durable redacted reflection.
    access_state().record_diagnostic(audit.clone());
    let _ =
        hyalos::reflect_json(serde_json::to_value(audit).unwrap_or_else(|_| serde_json::json!({})));
    Ok(Json(public_response))
}

fn access_state() -> &'static access::AccessState {
    static STATE: std::sync::OnceLock<access::AccessState> = std::sync::OnceLock::new();
    STATE.get_or_init(access::AccessState::default)
}

/// Library-only inspection of the already-redacted diagnostic projection. This has
/// no HTTP route and cannot expose request or private staff envelopes.
#[doc(hidden)]
pub fn recorded_access_diagnostics() -> Vec<access::DiagnosticEvent> {
    access_state().diagnostics()
}

async fn reject_nonloopback_access(request: Request<axum::body::Body>, next: Next) -> Response {
    let allowed = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback());
    if !allowed {
        let event = access::DiagnosticEvent::new(
            "access.attendance",
            "peer-refused",
            "pre-body",
            "refused",
            std::time::Instant::now(),
            "caduceus-access-non-loopback",
            access_state().clock.now(),
        );
        access_state().record_diagnostic(event.clone());
        let _ = hyalos::reflect_json(
            serde_json::to_value(event).unwrap_or_else(|_| serde_json::json!({})),
        );
        return api_error_signal("access", "caduceus-access-non-loopback").into_response();
    }
    match policy::allows_command("staff intent") {
        Ok(true) => {}
        Ok(false) => return api_error("access").into_response(),
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: "access".to_string(),
                    first_missing_signal: "caduceus-profile-missing".to_string(),
                }),
            )
                .into_response()
        }
    }
    next.run(request).await
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
    let access_routes = Router::new()
        .route("/api/v1/access/challenges/mint", post(access_route))
        .route("/api/v1/access/sessions/mint", post(access_route))
        .route("/api/v1/access/sessions/prove", post(access_route))
        .route("/api/v1/access/sessions/clear", post(access_route))
        .route("/api/v1/access/capabilities/mint", post(access_route))
        .route("/api/v1/access/pin/change", post(access_route))
        .layer(DefaultBodyLimit::max(access::MAX_LINE_BYTES))
        .route_layer(middleware::from_fn(reject_nonloopback_access));
    Router::new()
        .merge(access_routes)
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
