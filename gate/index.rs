//! Generic HTTP gate kernel and live receiver.
//! Route bodies live in selected route leaves.

use crate::shared::{attendance, policy};
use axum::{
    body::Body,
    extract::{connect_info::ConnectInfo, DefaultBodyLimit},
    http::{header::CONTENT_TYPE, HeaderMap, Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{env, net::SocketAddr};
use tokio::net::TcpListener;

#[path = "../gate/snake.rs"]
pub mod snake;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ApiErrorBody {
    pub(crate) schema: &'static str,
    pub(crate) ok: bool,
    pub(crate) command: String,
    pub(crate) first_missing_signal: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LivenessBody {
    schema: &'static str,
    ok: bool,
    service: &'static str,
    #[serde(rename = "build_sha", skip_serializing_if = "Option::is_none")]
    build_sha: Option<&'static str>,
}
const CADUCEUS_BUILD_SHA: Option<&str> = option_env!("CADUCEUS_BUILD_SHA");

#[derive(Deserialize)]
pub(crate) struct HardDriveTestStartBody {
    pub(crate) device: String,
    pub(crate) test_type: String,
    #[serde(default, alias = "dryRun")]
    pub(crate) dry_run: bool,
}
#[derive(Deserialize)]
pub(crate) struct ServiceToggleBody {
    pub(crate) state: String,
}

pub(crate) fn roster_allows(method: &str, path: &str) -> Result<bool, String> {
    let profile = crate::shared::config::read_public_profile_value()?;
    let name = profile
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("homeserver");
    let routes = crate::routes::profile_routes::routes_for(name)
        .ok_or_else(|| "caduceus-public-profile-invalid".to_string())?;
    let key = format!("{method} {path}");
    Ok(routes.iter().any(|route| {
        *route == path
            || *route == key
            || (*route == "appliance/service/:service/restart"
                && path.starts_with("/api/v1/service/")
                && path.ends_with("/restart"))
    }))
}

pub(crate) fn api_error_signal(command: &str, signal: &str) -> (StatusCode, Json<ApiErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.into(),
            first_missing_signal: signal.into(),
        }),
    )
}
pub(crate) fn api_error(command: &str) -> (StatusCode, Json<ApiErrorBody>) {
    api_error_signal(command, "caduceus-public-action-not-allowed")
}
pub(crate) fn missing_signal(err: &str) -> &'static str {
    if err.contains("identity") {
        "caduceus-identity-missing"
    } else {
        "caduceus-profile-missing"
    }
}
pub(crate) async fn gated_json(
    command: &str,
    read: fn() -> Result<Value, String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => read().map(Json).map_err(|err| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: command.into(),
                    first_missing_signal: missing_signal(&err).into(),
                }),
            )
        }),
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}
pub(crate) fn mutation_status(value: &Value) -> StatusCode {
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
pub(crate) const FIREWALL_DOCUMENT_TARGET: &str = "/api/v1/network/firewall/policies/{mac}";
pub(crate) const VAULT_ATTENDANCE_COMMAND: &str = "staff intent";
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VaultUnlockBody {
    #[serde(default)]
    pub(crate) password: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VaultAutoBody {
    pub(crate) enabled: bool,
}
pub(crate) async fn gated_mutation(
    command: &str,
    run: fn() -> Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            let value = run();
            Ok((mutation_status(&value), Json(value)))
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}
pub(crate) fn attendance_admits(target: &str, token: Option<&str>) -> Result<(), String> {
    let token = token
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "caduceus-attendance-not-current".to_string())?;
    let incarnation = env::var("CADUCEUS_DOCUMENT_INCARNATION")
        .map_err(|_| "caduceus-document-incarnation-missing".to_string())?;
    if attendance::admits(token, target, &incarnation) {
        Ok(())
    } else {
        Err("caduceus-attendance-not-current".into())
    }
}
pub(crate) fn document_attendance_admits(
    document: &str,
    token: Option<&str>,
) -> Result<(), String> {
    let token = token
        .filter(|v| !v.trim().is_empty())
        .ok_or_else(|| "caduceus-attendance-not-current".to_string())?;
    if !document.trim().is_empty() && attendance::admits_target(token, document) {
        Ok(())
    } else {
        Err("caduceus-attendance-not-current".into())
    }
}
pub(crate) fn vault_attendance_admits(
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ApiErrorBody>)> {
    document_attendance_admits(
        headers
            .get("x-caduceus-document")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default(),
        headers
            .get("x-caduceus-attendance")
            .and_then(|v| v.to_str().ok()),
    )
    .map_err(|s| api_error_signal(VAULT_ATTENDANCE_COMMAND, &s))
}
pub(crate) fn access_attendance_admits(
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ApiErrorBody>)> {
    vault_attendance_admits(headers)
}
pub(crate) async fn local_access_route(request: Request<Body>, next: middleware::Next) -> Response {
    if request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| !peer.ip().is_loopback())
    {
        return api_error_signal("local access", "caduceus-local-access-required").into_response();
    }
    next.run(request).await
}

async fn health_route() -> Json<LivenessBody> {
    Json(LivenessBody {
        schema: "caduceus.liveness.v1",
        ok: true,
        service: "caduceus",
        build_sha: CADUCEUS_BUILD_SHA,
    })
}
async fn doors_route() -> Result<Response, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("doors read") {
        Ok(true) => {
            let body = serde_json::json!({"schema":"caduceus.doors.readback.v1","ok":true,"profile":env::var("CADUCEUS_PROFILE").unwrap_or_else(|_|"unknown".into()),"routes":crate::routes::SELECTED_DISCOVERY});
            Ok((
                [(CONTENT_TYPE, "application/json")],
                Body::from(body.to_string()),
            )
                .into_response())
        }
        Ok(false) => Err(api_error("doors read")),
        Err(_) => Err(api_error_signal("doors read", "caduceus-profile-missing")),
    }
}
fn audit_doors() -> Result<(), String> {
    if crate::routes::SELECTED_DISCOVERY.is_empty() {
        Err("selected-route-discovery-empty".into())
    } else {
        Ok(())
    }
}
pub fn router() -> Router {
    crate::routes::register_selected(
        Router::new()
            .route("/health", get(health_route))
            .route("/api/v1/doors", get(doors_route))
            .layer(DefaultBodyLimit::max(8192)),
    )
}
pub async fn run_async() -> i32 {
    if let Err(e) = audit_doors() {
        eprintln!("caduceus-doors-audit-failed: {e}");
        return 1;
    }
    let bind = env::var("CADUCEUS_BIND").unwrap_or_else(|_| "0.0.0.0:8787".into());
    let addr: SocketAddr = match bind.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("caduceus-bind-invalid: {e}");
            return 1;
        }
    };
    attendance::bind();
    crate::stats::start();
    crate::maintenance::start();
    let listener = match TcpListener::bind(addr).await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("caduceus-bind-failed: {e}");
            return 1;
        }
    };
    match axum::serve(
        listener,
        router().into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("caduceus-serve-failed: {e}");
            1
        }
    }
}
pub fn run() -> i32 {
    match tokio::runtime::Runtime::new() {
        Ok(rt) => rt.block_on(run_async()),
        Err(e) => {
            eprintln!("caduceus-serve-runtime-failed: {e}");
            1
        }
    }
}
#[path = "admittance/index.rs"]
pub mod admittance;
#[path = "discovery/index.rs"]
pub mod discovery;
#[path = "receipts/index.rs"]
pub mod receipts;
pub fn receive(
    raw: Value,
    route_set: &[Value],
    declaration: &Value,
    attendance_witness: bool,
) -> Result<Value, String> {
    let envelope = crate::protocol::Envelope::parse(raw)?;
    let admittance = admittance::check_declared_admittance(declaration)?;
    let _ = discovery::walk_compiled_route_set(route_set)?;
    Ok(receipts::append_stamp(
        &envelope,
        admittance,
        attendance_witness,
        true,
        true,
        None,
    ))
}
