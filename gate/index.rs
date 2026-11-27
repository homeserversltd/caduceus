//! Generic HTTP gate kernel and live receiver.
//! Route bodies live in selected route leaves.

use crate::shared::{attendance, policy};
use axum::serve::IncomingStream;
use axum::{
    body::{to_bytes, Body},
    extract::connect_info::ConnectInfo,
    http::{header::CONTENT_TYPE, HeaderMap, Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use hyper::server::conn::http1;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    env,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{self, Read},
    net::{IpAddr, SocketAddr},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    time::Instant,
};
use tokio::{
    net::{TcpListener, UnixListener, UnixStream},
    signal::unix::{signal, SignalKind},
    sync::watch,
    task::JoinSet,
};
use tower::{ServiceBuilder, ServiceExt};

#[path = "keyman.rs"]
pub mod keyman;
#[path = "../gate/snake.rs"]
pub mod snake;
#[path = "door.rs"]
pub mod door;
pub mod one_name;

pub(crate) struct ApiErrorBody {
    pub(crate) ok: bool,
    pub(crate) command: String,
    pub(crate) first_missing_signal: String,
}

impl Serialize for ApiErrorBody {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        crate::shared::load_trace::serialize_api_error(
            crate::shared::load_trace::ApiErrorBodyFields {
                ok: self.ok,
                command: &self.command,
                first_missing_signal: &self.first_missing_signal,
            },
            serializer,
        )
    }
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
    let name = crate::shared::config::resolved_profile()?;
    let routes = crate::routes::profile_routes::routes_for(&name)
        .ok_or_else(|| "caduceus-public-profile-invalid".to_string())?;
    let key = format!("{method} {path}");
    Ok(routes.iter().any(|route| {
        *route == path
            || *route == key
            || (route
                .strip_prefix("appliance/service/:service/")
                .is_some_and(|action| {
                    matches!(
                        action,
                        "status" | "start" | "stop" | "restart" | "enable" | "disable"
                    ) && (path.starts_with("/api/v1/service/")
                        || path.starts_with("/api/v1/appliance/service/"))
                        && path.ends_with(&format!("/{action}"))
                }))
    }))
}

pub(crate) fn api_error_signal(command: &str, signal: &str) -> (StatusCode, Json<ApiErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiErrorBody {
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
    if err == "caduceus-pjlink-catalog-import-required" {
        "caduceus-pjlink-catalog-import-required"
    } else if err.contains("identity") {
        "caduceus-identity-missing"
    } else {
        "caduceus-operation-failed"
    }
}
pub(crate) fn service_unavailable(command: &str, signal: &str) -> (StatusCode, Json<ApiErrorBody>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(ApiErrorBody {
            ok: false,
            command: command.into(),
            first_missing_signal: signal.into(),
        }),
    )
}
pub(crate) async fn gated_json(
    command: &str,
    read: fn() -> Result<Value, String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            let context = crate::shared::load_trace::current();
            let invocation = context
                .as_ref()
                .map(crate::shared::load_trace::begin_invocation);
            let result = blocking_task(command, read).await;
            if let (Some(context), Some(invocation)) = (context, invocation) {
                let ok = result
                    .as_ref()
                    .is_ok_and(|value| crate::shared::load_trace::outcome_for_result(value));
                crate::shared::load_trace::record_native_completion(
                    &context, command, invocation, ok,
                );
            }
            match result {
                Ok(Ok(mut value)) => {
                    crate::shared::load_trace::enrich_json(&mut value);
                    Ok(Json(value))
                }
                Ok(Err(error)) => Err(service_unavailable(command, missing_signal(&error))),
                Err(error) => Err(error),
            }
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-carapace-desync")),
    }
}
pub(crate) async fn gated_body(
    command: &str,
    read: fn() -> Result<String, String>,
) -> Result<String, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            let context = crate::shared::load_trace::current();
            let invocation = context
                .as_ref()
                .map(crate::shared::load_trace::begin_invocation);
            let result = blocking_task(command, read).await;
            if let (Some(context), Some(invocation)) = (context, invocation) {
                let ok = result
                    .as_ref()
                    .is_ok_and(|value| crate::shared::load_trace::outcome_for_result(value));
                crate::shared::load_trace::record_native_completion(
                    &context, command, invocation, ok,
                );
            }
            match result {
                Ok(Ok(body)) => Ok(crate::shared::load_trace::enrich_json_text(body)),
                Ok(Err(error)) => Err(service_unavailable(command, missing_signal(&error))),
                Err(error) => Err(error),
            }
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-carapace-desync")),
    }
}
pub fn receipt_succeeded(value: &Value) -> bool {
    value.get("ok").and_then(Value::as_bool) == Some(true)
        && value.get("doorSignal").is_none()
}

pub(crate) fn mutation_status(value: &Value) -> StatusCode {
    if value.get("ok").and_then(Value::as_bool) == Some(true)
        && value.get("doorSignal").is_none()
    {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
pub(crate) const VAULT_ATTENDANCE_COMMAND: &str = "staff intent";
#[derive(Deserialize)]
pub(crate) struct VaultUnlockBody {
    #[serde(default)]
    pub(crate) password: Option<String>,
}
#[derive(Deserialize)]
pub(crate) struct VaultAutoBody {
    pub(crate) enabled: bool,
}
pub(crate) async fn blocking_task<T, F>(
    command: &str,
    run: F,
) -> Result<T, (StatusCode, Json<ApiErrorBody>)>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let context = crate::shared::load_trace::current();
    let task = if let Some(context) = context {
        tokio::task::spawn_blocking(move || {
            crate::shared::load_trace::with_blocking_context(Some(context), run)
        })
    } else {
        tokio::task::spawn_blocking(run)
    };
    task.await.map_err(|_error: tokio::task::JoinError| {
        service_unavailable(command, "caduceus-blocking-task-join-failed")
    })
}

pub(crate) async fn gated_mutation(
    command: &str,
    run: fn() -> Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            let value = blocking_task(command, run).await?;
            Ok((mutation_status(&value), Json(value)))
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-carapace-desync")),
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

const ADMINISTRATIVE_PROFILE_MAX_BYTES: usize = 16 * 1024;
const ADMINISTRATIVE_ROUTES_MAX_BYTES: usize = 64 * 1024;
const KEYMAN_ADMIN_PASSWORD_HTTP_PATH: &str = "/api/v1/keyman/admin-password";
const KEYMAN_CREATE_KEY_HTTP_PATH: &str = "/api/v1/keyman/create-key";
const KEYMAN_UPDATE_KEY_HTTP_PATH: &str = "/api/v1/keyman/update-key";
const NAS_SETUP_HTTP_PATH: &str = "/api/v1/storage/nas/setup";
const NAS_ATTACH_HTTP_PATH: &str = "/api/v1/storage/nas/attach";
const NAS_DETACH_HTTP_PATH: &str = "/api/v1/storage/nas/detach";
const TRANSMISSION_UP_HTTP_PATH: &str = "/api/v1/transmission/up";
const TRANSMISSION_DOWN_HTTP_PATH: &str = "/api/v1/transmission/down";
const TRANSMISSION_KEYS_REPLACE_HTTP_PATH: &str = "/api/v1/transmission/keys/replace";
const TRANSMISSION_KEYS_ROTATE_HTTP_PATH: &str = "/api/v1/transmission/keys/rotate";
const TRANSMISSION_VPN_SETTINGS_HTTP_PATH: &str = "/api/v1/transmission/vpn/settings";
const TAILSCALE_UP_HTTP_PATH: &str = "/api/v1/network/tailscale/up";
const TAILSCALE_DOWN_HTTP_PATH: &str = "/api/v1/network/tailscale/down";
const TAILSCALE_AUTHKEY_HTTP_PATH: &str = "/api/v1/network/tailscale/authkey";
const TAILSCALE_TAILNET_HTTP_PATH: &str = "/api/v1/network/tailscale/tailnet";
const STATS_ADMIN_HTTP_PATH: &str = "/api/v1/appliance/stats/admin";
const ADMINISTRATIVE_FALLBACK_ROUTES: &[&str] = &[
    "/api/v1/storage/nas/list",
    "/api/v1/storage/backup/forgejo/skip-check",
    "/api/v1/access/pin/mode",
    "/api/v1/access/sudo/mode",
    STATS_ADMIN_HTTP_PATH,
    "/api/v1/storage/vault/auto-decrypt",
    "/api/v1/network/notes",
    "/api/v1/network/bandwidth/measure",
    "/api/v1/network/dns/adblock",
    "/api/v1/network/dns/blocklist/update",
    "/api/v1/network/dns/blocklist/source/add",
    "/api/v1/network/dns/blocklist/source/remove",
    "/api/v1/network/dns/upstream",
    "/api/v1/network/dns/device-name/create",
    "/api/v1/network/dns/device-name/remove",
    "/api/v1/network/dns/alias/create",
    "/api/v1/network/dns/alias/remove",
    "/api/v1/network/dns",
    "/api/v1/config/set",
    "/api/v1/config/patch",
    "/api/v1/storage/disk/census",
    NAS_ATTACH_HTTP_PATH,
    NAS_DETACH_HTTP_PATH,
    "/api/v1/storage/nas/key/rekey",
    "/api/v1/storage/backup/forgejo/nas-restore",
    "/api/v1/storage/categories",
    "/api/v1/storage/categories/scan",
    "POST /api/v1/network/dhcp",
    "POST /api/v1/network/dhcp/reservations",
    "PUT /api/v1/network/dhcp/reservations/{reservation_id}",
    "DELETE /api/v1/network/dhcp/reservations/{reservation_id}",
    "POST /api/v1/network/dhcp/pool-boundary",
    "POST /api/v1/transmission/keys/replace",
    "POST /api/v1/transmission/keys/rotate",
    "POST /api/v1/transmission/vpn/settings",
    "POST /api/v1/network/tailscale/up",
    "POST /api/v1/network/tailscale/down",
    "POST /api/v1/network/tailscale/authkey",
    "POST /api/v1/network/tailscale/tailnet",
];

fn open_nofollow_shelf_file(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrative shelf path must be absolute",
        ));
    }
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => components.push(name),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "administrative shelf path contains a non-normal component",
                ));
            }
        }
    }
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "administrative shelf path has no file component",
        ));
    }

    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut parent: OwnedFd = root.into();
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_bytes()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "NUL in administrative shelf path",
            )
        })?;
        let last = index + 1 == components.len();
        let flags = if last {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY
        };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let opened = unsafe { OwnedFd::from_raw_fd(fd) };
        if last {
            return Ok(File::from(opened));
        }
        parent = opened;
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        "administrative shelf path has no file component",
    ))
}

fn bounded_json_nofollow(path: &Path, limit: usize) -> Result<Option<Value>, String> {
    let file = match open_nofollow_shelf_file(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("caduceus-administrative-config-unavailable".to_string()),
    };
    if !file
        .metadata()
        .map_err(|_| "caduceus-administrative-config-unavailable".to_string())?
        .is_file()
    {
        return Err("caduceus-administrative-config-invalid".to_string());
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "caduceus-administrative-config-unavailable".to_string())?;
    if bytes.len() > limit {
        return Err("caduceus-administrative-config-invalid".to_string());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "caduceus-administrative-config-invalid".to_string())
}

fn administrative_profile() -> Result<String, String> {
    let path = crate::shared::config::path("etc/appliance/profile.json");
    let Some(value) = bounded_json_nofollow(&path, ADMINISTRATIVE_PROFILE_MAX_BYTES)? else {
        return Ok("specula".to_string());
    };
    let Some(profile) = value.get("profile") else {
        return Ok("specula".to_string());
    };
    let profile = profile
        .as_str()
        .filter(|value| {
            !value.is_empty()
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        })
        .ok_or_else(|| "caduceus-administrative-profile-invalid".to_string())?;
    Ok(profile.to_string())
}

fn configured_administrative_routes() -> Result<Option<Vec<String>>, String> {
    let profile = administrative_profile()?;
    let path = crate::shared::config::path(&format!(
        "usr/local/sbin/agathodaimon/crossings/{profile}.json"
    ));
    let Some(value) = bounded_json_nofollow(&path, ADMINISTRATIVE_ROUTES_MAX_BYTES)? else {
        return Ok(None);
    };
    let Some(routes) = value.pointer("/administrative/routes") else {
        return Ok(None);
    };
    let routes = routes
        .as_array()
        .ok_or_else(|| "caduceus-administrative-routes-invalid".to_string())?;
    routes
        .iter()
        .map(|route| {
            if let Some(route) = route.as_str() {
                Ok(route.to_string())
            } else {
                let method = route
                    .get("method")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "caduceus-administrative-routes-invalid".to_string())?;
                let path = route
                    .get("path")
                    .and_then(Value::as_str)
                    .ok_or_else(|| "caduceus-administrative-routes-invalid".to_string())?;
                Ok(format!("{method} {path}"))
            }
        })
        .collect::<Result<Vec<_>, String>>()
        .map(Some)
}

fn route_matches(entry: &str, method: Option<&str>, path: &str) -> bool {
    let path_matches = |listed_path: &str| {
        let mut listed_segments = listed_path.split('/');
        let mut requested_segments = path.split('/');
        loop {
            match (listed_segments.next(), requested_segments.next()) {
                (Some(listed_segment), Some(requested_segment)) => {
                    let placeholder = listed_segment
                        .strip_prefix('{')
                        .and_then(|name| name.strip_suffix('}'))
                        .filter(|name| {
                            !name.is_empty() && !name.contains('{') && !name.contains('}')
                        });
                    if placeholder.is_some() {
                        if requested_segment.is_empty() {
                            return false;
                        }
                    } else if listed_segment != requested_segment {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    };

    if let Some((listed_method, listed_path)) = entry.split_once(' ') {
        path_matches(listed_path)
            && method.map_or(true, |method| listed_method.eq_ignore_ascii_case(method))
    } else {
        path_matches(entry)
    }
}

fn declared_http_route(method: &str, path: &str) -> Option<Value> {
    let namespace = path.strip_prefix("/api/v1/")?;
    let method_matches = |value: &Value| {
        value.get("http_method").and_then(Value::as_str).is_some_and(|declared| {
            declared == method || (method == "HEAD" && declared == "GET")
        })
    };
    // The hand-written Hyalos tail is served under a different namespace.
    let mut candidate = Some(match namespace {
        "hyalos/tail" => "log/tail",
        name => name,
    });
    while let Some(name) = candidate {
        if let Some(declaration) = crate::routes::selected_declaration(name) {
            let value: Value = serde_json::from_str(declaration).ok()?;
            if generic_http_route_matches(name, &value, method, path) {
                return Some(value);
            }
            let path_matches = if name == "log/tail" {
                value["http_path"].as_str() == Some(path)
                    || value["http_aliases"].as_array().is_some_and(|aliases| {
                        aliases.iter().any(|alias| alias.as_str() == Some(path))
                    })
            } else {
                name == namespace
            };
            if !generic_http_declaration(&value) && path_matches && method_matches(&value) {
                return Some(value);
            }
            if let Some(operations) = value.get("operations").and_then(Value::as_array) {
                for operation in operations {
                    if method_matches(operation)
                        && operation.get("http_path").and_then(Value::as_str)
                            .is_some_and(|pattern| route_matches(pattern, None, path))
                    {
                        return Some(operation.clone());
                    }
                }
            }
        }
        candidate = name.rsplit_once('/').map(|(parent, _)| parent);
    }
    // Generic leaves may choose an explicit path unrelated to their namespace.
    // A hand-written leaf can also declare administrative operations at sibling
    // paths. Look only at compile-selected leaves and only at explicit admin
    // operations here; a read on a shared path keeps its existing classification.
    for name in crate::routes::SELECTED_LEAF_MODULES {
        let Some(source) = crate::routes::selected_declaration(name) else { continue; };
        let Ok(value) = serde_json::from_str::<Value>(source) else { continue; };
        if generic_http_route_matches(name, &value, method, path) {
            return Some(value);
        }
        if let Some(operation) = value
            .get("operations")
            .and_then(Value::as_array)
            .and_then(|operations| {
                operations.iter().find(|operation| {
                    operation["administrative"].as_bool() == Some(true)
                        && operation["method"].as_str() == Some(method)
                        && operation["path"]
                            .as_str()
                            .is_some_and(|pattern| generic_path_matches(pattern, path))
                })
            })
        {
            return Some(operation.clone());
        }
    }
    None
}

fn generic_http_declaration(value: &Value) -> bool {
    value.get("namespace").and_then(Value::as_str)
        .is_some_and(crate::gate::door::is_registered_namespace)
}

fn generic_http_route_matches(name: &str, value: &Value, method: &str, path: &str) -> bool {
    if !generic_http_declaration(value) {
        return false;
    }
    let declared_method = match value.get("http_method") {
        Some(method) => match method.as_str() {
            Some(method) => method.to_ascii_uppercase(),
            None => return false,
        },
        None => "POST".to_owned(),
    };
    let declared_path = match value.get("http_path") {
        Some(path) => match path.as_str() {
            Some(path) => path.to_owned(),
            None => return false,
        },
        None => format!("/api/v1/{name}"),
    };
    (declared_method == method || (method == "HEAD" && declared_method == "GET"))
        && generic_path_matches(&declared_path, path)
}

fn generic_path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern_segments = pattern.split('/');
    let mut path_segments = path.split('/');
    loop {
        match (pattern_segments.next(), path_segments.next()) {
            (Some(expected), Some(actual)) => {
                let named = expected.strip_prefix('{').and_then(|part| part.strip_suffix('}'))
                    .is_some_and(|name| !name.is_empty())
                    || expected.strip_prefix(':').is_some_and(|name| !name.is_empty());
                if named {
                    if actual.is_empty() { return false; }
                } else if expected != actual {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

fn record_admission_refusal(method: &str, path: &str, signal: &str, started: Instant) {
    let Some(declaration) = declared_http_route(method, path) else { return; };
    if generic_http_declaration(&declaration) {
        // The generic request was refused before any act, so it leaves no deed.
        return;
    }
    let Some(deed) = declaration.get("ledger_deed") else {
        return;
    };
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(serde_json::json!({
        "organ": deed["organ"],
        "kind": "admission-refusal",
        "level": "error",
        "ok": false,
        "message": "administrative deed refused",
        "attributes_redacted": {
            "who": "owner", "verb": deed["verb"], "target": deed["target"],
            "outcome": "refused", "signal": signal,
            "duration_ms": started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        }
    }));
}

// Resolve only a leaf's own declared method and path, not a parent, alias,
// operation, parameter pattern, or another method on the same path.
fn intent_seat_administrative(method: &str, path: &str) -> Option<bool> {
    const FUSED: &[&str] = &[
        "local-ai/slot", "transmission/keys", "appliance/service",
        "portals/service-control", "appliance/sudo-passwordless",
    ];
    let mut matched = None;
    for name in crate::routes::SELECTED_LEAF_MODULES {
        let Some(source) = crate::routes::selected_declaration(name) else { continue; };
        let Ok(declaration) = serde_json::from_str::<Value>(source) else { continue; };
        let declared_path = match declaration.get("http_path") {
            Some(value) => match value.as_str() {
                Some(path) => path.to_owned(),
                None => continue,
            },
            None => format!("/api/v1/{name}"),
        };
        let declared_method = match declaration.get("http_method") {
            Some(value) => value.as_str(),
            None => crate::routes::SELECTED_UNIVERSAL_DOORS.contains(name).then_some("POST"),
        };
        if declaration["namespace"].as_str() != Some(*name)
            || declared_path != path
            || !(declared_method == Some(method)
                || (method == "HEAD" && declared_method == Some("GET")))
        {
            continue;
        }
        // Ambiguous declarations cannot name one intent.
        if matched.is_some() { return None; }
        matched = Some((*name, declaration));
    }
    let (name, declaration) = matched?;
    let snakes: Vec<&str> = declaration["serve"].as_array().into_iter().flatten()
        .filter_map(|step| step.get("snake").and_then(Value::as_str)).collect();
    if snakes.len() > 1 || FUSED.contains(&name) { return None; }
    let (seat, exousia) = if let Some(value) = crate::routes::leaf_schema::intent_exousia(name) {
        (name, value)
    } else {
        let seat = *snakes.first()?;
        (seat, crate::routes::leaf_schema::intent_exousia(seat)?)
    };
    if FUSED.contains(&seat) { return None; }
    Some(exousia || declaration["administrative"].as_bool() == Some(true))
}

fn administrative_routes_match(method: Option<&str>, path: &str) -> Result<bool, String> {
    // Exact path precedence covers both middleware (Some(method)) and direct
    // administrative admission (None); do not widen it to a vault namespace.
    // Unlock stays password-only despite stale external shelves; auto-decrypt
    // remains administrative regardless of their contents.
    if path == "/api/v1/storage/vault/unlock" {
        return Ok(false);
    }
    if path == "/api/v1/storage/vault/auto-decrypt" {
        return Ok(true);
    }
    if let Some(answer) = method.and_then(|method| intent_seat_administrative(method, path)) {
        return Ok(answer);
    }
    // The compiled leaf owns its classification. An older staff mirror cannot
    // turn a newly declared administrative deed into an unattended request.
    if method.and_then(|method| declared_http_route(method, path))
        .is_some_and(|declaration| declaration["administrative"].as_bool() == Some(true))
    {
        return Ok(true);
    }
    if path == STATS_ADMIN_HTTP_PATH {
        return Ok(true);
    }
    // These NAS mutations remain attended when an older configured administrative
    // shelf replaces the fallback list and omits either newer door.
    if method.is_some_and(|method| {
        method.eq_ignore_ascii_case("POST")
            && (path == KEYMAN_ADMIN_PASSWORD_HTTP_PATH
                || path == KEYMAN_CREATE_KEY_HTTP_PATH
                || path == KEYMAN_UPDATE_KEY_HTTP_PATH
                || path == NAS_SETUP_HTTP_PATH
                || path == NAS_ATTACH_HTTP_PATH
                || path == NAS_DETACH_HTTP_PATH
                || path == TRANSMISSION_UP_HTTP_PATH
                || path == TRANSMISSION_DOWN_HTTP_PATH
                || path == TRANSMISSION_KEYS_REPLACE_HTTP_PATH
                || path == TRANSMISSION_KEYS_ROTATE_HTTP_PATH
                || path == TRANSMISSION_VPN_SETTINGS_HTTP_PATH
                || path == TAILSCALE_UP_HTTP_PATH
                || path == TAILSCALE_DOWN_HTTP_PATH
                || path == TAILSCALE_AUTHKEY_HTTP_PATH
                || path == TAILSCALE_TAILNET_HTTP_PATH)
    }) {
        return Ok(true);
    }
    if method.is_some_and(|method| {
        method.eq_ignore_ascii_case("GET") && path == "/api/v1/access/pin/mode"
    }) {
        return Ok(false);
    }
    Ok(match configured_administrative_routes()? {
        Some(routes) => routes
            .iter()
            .any(|entry| route_matches(entry, method, path)),
        None => ADMINISTRATIVE_FALLBACK_ROUTES
            .iter()
            .any(|entry| route_matches(entry, method, path)),
    })
}

fn administrative_pin_required() -> bool {
    crate::shared::config::get_json("global.admin.pin_required")
        .ok()
        .and_then(|value| value.get("value").and_then(Value::as_bool))
        .unwrap_or(false)
}

fn administrative_attendance_admits(headers: &HeaderMap) -> bool {
    let document = headers
        .get("x-caduceus-document")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let attendance = headers
        .get("x-caduceus-attendance")
        .and_then(|value| value.to_str().ok());
    document_attendance_admits(document, attendance).is_ok()
}

fn administrative_credentials_admit(headers: &HeaderMap, body: &Value) -> Result<(), String> {
    if !administrative_pin_required() || administrative_attendance_admits(headers) {
        return Ok(());
    }
    let pin = body
        .pointer("/flags/exousia/pin")
        .and_then(Value::as_str)
        .filter(|pin| !pin.is_empty() && pin.len() <= 512 && *pin != ADMINISTRATIVE_PIN_REDACTED)
        .ok_or_else(|| "exousia-pin-required".to_string())?;
    attendance::verify_administrative_pin(pin)
}

const INTERNAL_ADMIN_GATE_HEADER: &str = "x-caduceus-internal-administrative-gate";
const ADMINISTRATIVE_REQUEST_BODY_MAX_BYTES: usize = 2 * 1024 * 1024;
// keyman::REDACTED is private to its module; this is the gate's marker.
pub(crate) const ADMINISTRATIVE_PIN_REDACTED: &str = "[REDACTED]";

pub(crate) fn administrative_admits(
    headers: &HeaderMap,
    body: &Value,
    route: &str,
) -> Result<(), String> {
    if headers.contains_key(INTERNAL_ADMIN_GATE_HEADER) {
        return Ok(());
    }
    if !administrative_routes_match(None, route)? {
        return Ok(());
    }
    administrative_credentials_admit(headers, body)
}

pub(crate) fn strip_administrative_flags(body: &mut Value) -> bool {
    let Some(object) = body.as_object_mut() else {
        return false;
    };
    let removed_pin = {
        let Some(flags) = object.get_mut("flags").and_then(Value::as_object_mut) else {
            return false;
        };
        let Some(exousia) = flags.get_mut("exousia").and_then(Value::as_object_mut) else {
            return false;
        };
        exousia.remove("pin").is_some()
    };
    if !removed_pin {
        return false;
    }

    if object
        .get("flags")
        .and_then(Value::as_object)
        .and_then(|flags| flags.get("exousia"))
        .and_then(Value::as_object)
        .is_some_and(|container| container.is_empty())
    {
        if let Some(flags) = object.get_mut("flags").and_then(Value::as_object_mut) {
            flags.remove("exousia");
        }
    }
    if object
        .get("flags")
        .and_then(Value::as_object)
        .is_some_and(|container| container.is_empty())
    {
        object.remove("flags");
    }
    true
}

fn redact_administrative_pin(body: &mut Value) -> bool {
    let Some(pin) = body
        .pointer_mut("/flags/exousia/pin")
    else {
        return false;
    };
    *pin = Value::String(ADMINISTRATIVE_PIN_REDACTED.to_owned());
    true
}

/// What one pass over a body's raw bytes sees that its parsed value hides:
/// a PIN carrier, flags.exousia.pin, in any member, including a member the
/// parsed value drops because a later member reuses its key.
#[derive(Default)]
struct RawCarrierScan {
    pin_carried: bool,
}

#[derive(Clone, Copy)]
enum CarrierDepth {
    Root,
    Flags,
    Exousia,
    Elsewhere,
}

struct CarrierSeed<'a> {
    scan: &'a mut RawCarrierScan,
    depth: CarrierDepth,
}

impl<'de> serde::de::DeserializeSeed<'de> for CarrierSeed<'_> {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> serde::de::Visitor<'de> for CarrierSeed<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(CarrierSeed {
                scan: &mut *self.scan,
                depth: CarrierDepth::Elsewhere,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            let depth = match (self.depth, key.as_str()) {
                (CarrierDepth::Root, "flags") => CarrierDepth::Flags,
                (CarrierDepth::Flags, "exousia") => CarrierDepth::Exousia,
                (CarrierDepth::Exousia, "pin") => {
                    self.scan.pin_carried = true;
                    CarrierDepth::Elsewhere
                }
                _ => CarrierDepth::Elsewhere,
            };
            map.next_value_seed(CarrierSeed {
                scan: &mut *self.scan,
                depth,
            })?;
        }
        Ok(())
    }
}

/// Scans the raw request body once; None when the bytes are not one JSON value.
fn scan_raw_carrier(bytes: &[u8]) -> Option<RawCarrierScan> {
    let mut scan = RawCarrierScan::default();
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    serde::de::DeserializeSeed::deserialize(
        CarrierSeed {
            scan: &mut scan,
            depth: CarrierDepth::Root,
        },
        &mut deserializer,
    )
    .ok()?;
    deserializer.end().ok()?;
    Some(scan)
}

/// Lays the redaction literal in the PIN carrier of the parsed body, building
/// flags and exousia when the kept member lacks them; false when a step of the
/// carrier path is not an object.
fn lay_redaction_literal(body: &mut Value) -> bool {
    let Some(object) = body.as_object_mut() else {
        return false;
    };
    let flags = object
        .entry("flags")
        .or_insert_with(|| Value::Object(Default::default()));
    let Some(flags) = flags.as_object_mut() else {
        return false;
    };
    let exousia = flags
        .entry("exousia")
        .or_insert_with(|| Value::Object(Default::default()));
    let Some(exousia) = exousia.as_object_mut() else {
        return false;
    };
    exousia.insert(
        "pin".to_owned(),
        Value::String(ADMINISTRATIVE_PIN_REDACTED.to_owned()),
    );
    true
}

async fn administrative_route_gate(mut request: Request<Body>, next: middleware::Next) -> Response {
    request.headers_mut().remove(INTERNAL_ADMIN_GATE_HEADER);
    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let administrative = match administrative_routes_match(Some(&method), &path) {
        Ok(administrative) => administrative,
        Err(signal) => {
            return api_error_signal("administrative route gate", &signal).into_response();
        }
    };
    let declaration = administrative
        .then(|| declared_http_route(&method, &path))
        .flatten();
    let hyalos_read = declaration.as_ref().is_some_and(|declaration| {
        matches!(
            declaration["namespace"].as_str(),
            Some("log/read" | "log/tail")
        ) || (declaration["namespace"].as_str() == Some("log/level")
            && matches!(method.as_str(), "GET" | "HEAD"))
    });
    if !administrative || hyalos_read {
        // The staff socket keeps its original read path. Off it the log
        // requires current Admin Mode, even where ordinary doors waive the PIN.
        if hyalos_read
            && !matches!(request_connection(&request), Some(ConnectionInfo::Unix { .. }))
            && !administrative_attendance_admits(request.headers())
        {
            return api_error_signal(
                "administrative route gate",
                "caduceus-hyalos-read-admin-required",
            )
            .into_response();
        }
        request.headers_mut().insert(
            INTERNAL_ADMIN_GATE_HEADER,
            axum::http::HeaderValue::from_static("1"),
        );
        return next.run(request).await;
    }

    let started = Instant::now();
    let (mut parts, body) = request.into_parts();
    let bytes = match to_bytes(body, ADMINISTRATIVE_REQUEST_BODY_MAX_BYTES).await {
        Ok(bytes) => bytes,
        Err(_) => {
            record_admission_refusal(&method, &path,
                "caduceus-administrative-request-too-large", started);
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(ApiErrorBody {
                    ok: false,
                    command: "administrative route gate".into(),
                    first_missing_signal: "caduceus-administrative-request-too-large".into(),
                }),
            )
                .into_response();
        }
    };
    let parsed_body = serde_json::from_slice::<Value>(&bytes).ok();
    let empty_body = Value::Null;
    let admission_body = parsed_body.as_ref().unwrap_or(&empty_body);
    if let Err(signal) = administrative_credentials_admit(&parts.headers, admission_body) {
        record_admission_refusal(&method, &path, &signal, started);
        return api_error_signal("administrative route gate", &signal).into_response();
    }

    let mut stripped_pin = false;
    // The parsed value keeps only the last of a key held twice, so the raw
    // bytes can carry a PIN the parsed value hides: a body that carried the
    // PIN in any member is forwarded re-serialized with the literal in the
    // carrier, never as the caller's bytes; one that carried it and has no
    // parsed value to re-serialize is refused.
    let pin_carried = scan_raw_carrier(&bytes).is_some_and(|scan| scan.pin_carried);
    let forwarded_bytes = if let Some(mut body) = parsed_body {
        stripped_pin = redact_administrative_pin(&mut body);
        if pin_carried && !stripped_pin {
            lay_redaction_literal(&mut body);
        }
        stripped_pin |= pin_carried;
        if stripped_pin {
            match serde_json::to_vec(&body) {
                Ok(bytes) => bytes,
                Err(_) => {
                    record_admission_refusal(&method, &path,
                        "caduceus-administrative-request-invalid", started);
                    return api_error_signal(
                        "administrative route gate",
                        "caduceus-administrative-request-invalid",
                    )
                    .into_response();
                }
            }
        } else {
            bytes.to_vec()
        }
    } else if pin_carried {
        record_admission_refusal(&method, &path,
            "caduceus-administrative-request-invalid", started);
        return api_error_signal(
            "administrative route gate",
            "caduceus-administrative-request-invalid",
        )
        .into_response();
    } else {
        bytes.to_vec()
    };
    if stripped_pin {
        parts.headers.remove("content-length");
    }
    parts.headers.insert(
        INTERNAL_ADMIN_GATE_HEADER,
        axum::http::HeaderValue::from_static("1"),
    );
    next.run(Request::from_parts(parts, Body::from(forwarded_bytes)))
        .await
}

pub(crate) fn vault_attendance_admits(
    headers: &HeaderMap,
    body: &Value,
    route: &str,
) -> Result<(), (StatusCode, Json<ApiErrorBody>)> {
    administrative_admits(headers, body, route)
        .map_err(|signal| api_error_signal(VAULT_ATTENDANCE_COMMAND, &signal))
}
pub(crate) fn access_attendance_admits(
    headers: &HeaderMap,
    body: &Value,
    route: &str,
) -> Result<(), (StatusCode, Json<ApiErrorBody>)> {
    vault_attendance_admits(headers, body, route)
}
async fn self_telemetry_route(request: Request<Body>, next: middleware::Next) -> Response {
    let path = request.uri().path().to_owned();
    let started = Instant::now();
    let response = next.run(request).await;
    crate::routes::leaf_appliance_stats::record_request(
        &path,
        response.status(),
        started.elapsed(),
    );
    response
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
            let body = serde_json::json!({"schema":"caduceus.doors.readback.v1","ok":true,"profile":crate::routes::profile_routes::ACTIVE_PROFILE,"routes":crate::routes::SELECTED_DISCOVERY});
            Ok((
                [(CONTENT_TYPE, "application/json")],
                Body::from(body.to_string()),
            )
                .into_response())
        }
        Ok(false) => Err(api_error("doors read")),
        Err(_) => Err(api_error_signal("doors read", "caduceus-carapace-desync")),
    }
}
fn audit_doors() -> Result<(), String> {
    if crate::routes::SELECTED_DISCOVERY
        .iter()
        .filter(|route| **route == "/api/v1/beam")
        .count()
        != 1
    {
        return Err("beam-door-bijection-failed".into());
    }
    if crate::routes::SELECTED_DISCOVERY
        .iter()
        .filter(|route| **route == "/api/v1/ruyi")
        .count()
        != 1
    {
        return Err("ruyi-door-bijection-failed".into());
    }
    Ok(())
}
pub(crate) mod pid2_route;

// Answer non-JSON client refusals at the gate, before the receipt stamp.
// Only the first KiB is inspected; extractor diagnostics can contain input.
async fn answer_client_refusal(request: Request<Body>, next: middleware::Next) -> Response {
    use axum::{extract::MatchedPath, http::Method};
    use futures_util::StreamExt;

    let path = request.uri().path();
    let raw = matches!(*request.method(), Method::GET | Method::HEAD)
        && (matches!(path, "/health" | "/api/v1/schema" | "/api/v1/carapace"
            | "/api/v1/log/tail" | "/api/v1/hyalos/tail")
            || path.starts_with("/api/v1/schema/")
            || (path.starts_with("/api/v1/docs/") && path != "/api/v1/docs/seal"));
    let command = request.extensions().get::<MatchedPath>()
        .map(|matched| matched.as_str())
        .unwrap_or(path)
        .trim_start_matches("/api/v1/")
        .to_owned();
    let response = next.run(request).await;
    let status = response.status();
    let json = response.headers().get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|mime| {
            let mime = mime.trim();
            mime.eq_ignore_ascii_case("application/json")
                || mime.rsplit_once('+').is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json"))
        });
    if raw || !status.is_client_error() || matches!(status, StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED) || json {
        return response;
    }

    let mut stream = response.into_body().into_data_stream();
    let mut bytes = Vec::new();
    let mut complete = false;
    while bytes.len() <= 1024 {
        match stream.next().await {
            Some(Ok(chunk)) => {
                let remaining = 1024 - bytes.len();
                bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                if chunk.len() > remaining { break; }
            }
            Some(Err(_)) => break,
            None => { complete = true; break; }
        }
    }
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(1024)]);
    let word = text.trim();
    let is_word = complete && word.len() <= 128 && word.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && word.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"._:-".contains(&c));
    let (answer_status, signal) = if is_word {
        (status, word)
    } else if status == StatusCode::UNPROCESSABLE_ENTITY && text.starts_with("Failed to deserialize the JSON body into the target type")
        || status == StatusCode::BAD_REQUEST && text.starts_with("Failed to parse the request body as JSON") {
        (StatusCode::BAD_REQUEST, "caduceus-request-body-invalid")
    } else if status == StatusCode::UNSUPPORTED_MEDIA_TYPE && text.starts_with("Expected request with `Content-Type: application/json`") {
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, "caduceus-request-content-type-invalid")
    } else if status == StatusCode::PAYLOAD_TOO_LARGE && text.starts_with("Failed to buffer the request body") {
        (StatusCode::PAYLOAD_TOO_LARGE, "caduceus-request-body-too-large")
    } else if status == StatusCode::BAD_REQUEST && text.starts_with("Failed to deserialize query string") {
        (StatusCode::BAD_REQUEST, "caduceus-request-query-invalid")
    } else if status == StatusCode::BAD_REQUEST && (text.starts_with("Invalid URL: ") || text.starts_with("Invalid UTF-8 in `")) {
        (StatusCode::BAD_REQUEST, "caduceus-request-path-invalid")
    } else {
        (status, "caduceus-request-invalid")
    };
    (answer_status, Json(ApiErrorBody { ok: false, command, first_missing_signal: signal.to_owned() })).into_response()
}

pub fn router() -> Router {
    let router = crate::routes::register_selected(
        Router::new()
            .route("/health", get(health_route))
            .route("/api/v1/doors", get(doors_route)),
    );
    one_name::keep_router(router.clone());
    router
        .layer(middleware::from_fn(administrative_route_gate))
        .layer(middleware::from_fn(answer_client_refusal))
        .layer(middleware::from_fn(self_telemetry_route))
        .layer(middleware::from_fn(crate::shared::load_trace::stamp_door_answer))
        .layer(middleware::from_fn(
            crate::shared::load_trace::http_boundary,
        ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionInfo {
    Tcp(SocketAddr),
    Unix { uid: u32, gid: u32, pid: u32 },
}
impl std::fmt::Display for ConnectionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(a) => write!(f, "{a}"),
            Self::Unix { uid, gid, pid } => write!(f, "unix(uid={uid},gid={gid},pid={pid})"),
        }
    }
}
#[derive(Clone, Copy)]
struct TcpLocalIp(Option<IpAddr>);

fn request_connection(request: &Request<Body>) -> Option<ConnectionInfo> {
    request
        .extensions()
        .get::<ConnectInfo<ConnectionInfo>>()
        .map(|info| info.0)
}

pub(crate) async fn hyalos_local_write_gate(
    request: Request<Body>,
    next: middleware::Next,
) -> Response {
    let local = match request_connection(&request) {
        Some(ConnectionInfo::Unix { .. }) => true,
        Some(ConnectionInfo::Tcp(peer)) => {
            let peer = peer.ip().to_canonical();
            peer.is_loopback()
                || request
                    .extensions()
                    .get::<TcpLocalIp>()
                    .and_then(|local| local.0)
                    .is_some_and(|local| local.to_canonical() == peer)
        }
        None => false,
    };
    if !local {
        return api_error_signal("hyalos write", "caduceus-hyalos-write-local-only").into_response();
    }
    next.run(request).await
}

#[derive(Debug)]
pub struct SocketIdentity {
    pub dev: u64,
    pub ino: u64,
    _guard: OwnedFd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PathIdentity {
    dev: u64,
    ino: u64,
}

#[repr(C)]
struct Group {
    name: *mut i8,
    passwd: *mut i8,
    gid: u32,
    members: *mut *mut i8,
}
unsafe extern "C" {
    fn getgrnam(name: *const i8) -> *mut Group;
    fn chown(path: *const i8, uid: u32, gid: u32) -> i32;
    fn chmod(path: *const i8, mode: u32) -> i32;
    fn getsockopt(fd: i32, level: i32, name: i32, value: *mut u8, len: *mut u32) -> i32;
    fn dup(fd: i32) -> i32;
}
fn group_id(name: &str) -> Result<u32, String> {
    if let Ok(gid) = name.parse::<u32>() {
        return Ok(gid);
    }
    let c = std::ffi::CString::new(name).map_err(|_| "staff-group-invalid".to_string())?;
    // Group lookup is configuration, never an admission decision.
    let p = unsafe { getgrnam(c.as_ptr()) };
    if p.is_null() {
        Err(format!("staff-group-not-found: {name}"))
    } else {
        Ok(unsafe { (*p).gid })
    }
}
fn peer_credentials(stream: &UnixStream) -> Result<ConnectionInfo, String> {
    #[repr(C)]
    struct Cred {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    let mut cred = Cred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<Cred>() as u32;
    const SOL_SOCKET: i32 = 1;
    const SO_PEERCRED: i32 = 17;
    let rc = unsafe {
        getsockopt(
            stream.as_raw_fd(),
            SOL_SOCKET,
            SO_PEERCRED,
            (&mut cred as *mut Cred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(ConnectionInfo::Unix {
        uid: cred.uid,
        gid: cred.gid,
        pid: cred.pid.max(0) as u32,
    })
}
pub fn prepare_staff_socket(path: &Path) -> Result<(UnixListener, SocketIdentity), String> {
    prepare_socket_parent(
        path.parent()
            .ok_or_else(|| "staff-socket-parent-missing".to_string())?,
    )?;
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err("staff-socket-symlink-collision".into());
            }
            if !meta.file_type().is_socket() {
                return Err("staff-socket-non-socket-collision".into());
            }
            let observed = PathIdentity {
                dev: meta.dev(),
                ino: meta.ino(),
            };
            match std::os::unix::net::UnixStream::connect(path) {
                Ok(_) => return Err("staff-socket-already-live".into()),
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    remove_stale_staff_socket(path, observed)
                        .map_err(|x| format!("staff-socket-stale-remove: {x}"))?
                }
                Err(e) => return Err(format!("staff-socket-probe: {e}")),
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("staff-socket-metadata: {e}")),
    }
    let listener = UnixListener::bind(path).map_err(|e| format!("staff-socket-bind: {e}"))?;
    let guard = match unsafe { dup(listener.as_raw_fd()) } {
        fd if fd >= 0 => unsafe { OwnedFd::from_raw_fd(fd) },
        _ => {
            let error = std::io::Error::last_os_error();
            let _ = fs::remove_file(path);
            return Err(format!("staff-socket-identity-guard: {error}"));
        }
    };
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            let _ = fs::remove_file(path);
            return Err(format!("staff-socket-metadata: {error}"));
        }
    };
    let id = SocketIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        _guard: guard,
    };
    let uid = unsafe { geteuid() };
    let group = env::var("CADUCEUS_STAFF_GROUP").unwrap_or_else(|_| "owner".into());
    let gid = group_id(&group).map_err(|e| {
        let _ = cleanup_staff_socket(path, &id);
        e
    })?;
    let cpath = match std::ffi::CString::new(path.as_os_str().as_encoded_bytes()) {
        Ok(value) => value,
        Err(_) => {
            let _ = cleanup_staff_socket(path, &id);
            return Err("staff-socket-path-invalid".to_string());
        }
    };
    if unsafe { chown(cpath.as_ptr().cast(), uid, gid) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            // The service account is not a member of the declared staff group, so the
            // kernel refuses the group change. The socket stays owned by this process's
            // own uid:gid at 0660; root staff clients connect regardless. A service
            // SHALL NOT crash-loop over a group it cannot own: witness it and serve.
            eprintln!(
                "{}",
                serde_json::json!({
                    "event": "caduceus-staff-socket-group-unowned",
                    "group": group,
                    "gid": gid,
                    "firstMissingSignal": "caduceus-staff-socket-group-unowned",
                })
            );
        } else {
            let _ = cleanup_staff_socket(path, &id);
            return Err(format!("staff-socket-owner: {e}"));
        }
    }
    let mut perms = match fs::metadata(path) {
        Ok(m) => m.permissions(),
        Err(e) => {
            let _ = cleanup_staff_socket(path, &id);
            return Err(e.to_string());
        }
    };
    perms.set_mode(0o660);
    if let Err(e) = fs::set_permissions(path, perms) {
        let _ = cleanup_staff_socket(path, &id);
        return Err(e.to_string());
    }
    Ok((listener, id))
}
unsafe extern "C" {
    fn geteuid() -> u32;
    fn getegid() -> u32;
}
fn prepare_socket_parent(parent: &Path) -> Result<(), String> {
    match fs::symlink_metadata(parent) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err("staff-socket-parent-symlink".into());
            }
            if !meta.is_dir() {
                return Err("staff-socket-parent-not-directory".into());
            }
            validate_socket_parent(&meta)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(parent).map_err(|e| format!("staff-socket-parent-create: {e}"))?;
            let cpath = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes())
                .map_err(|_| "staff-socket-parent-invalid".to_string())?;
            if unsafe { chown(cpath.as_ptr().cast(), geteuid(), getegid()) } != 0 {
                return Err(format!(
                    "staff-socket-parent-owner: {}",
                    std::io::Error::last_os_error()
                ));
            }
            if unsafe { chmod(cpath.as_ptr().cast(), 0o755) } != 0 {
                return Err(format!(
                    "staff-socket-parent-mode: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let meta = fs::symlink_metadata(parent)
                .map_err(|e| format!("staff-socket-parent-metadata: {e}"))?;
            if meta.file_type().is_symlink() {
                return Err("staff-socket-parent-symlink".into());
            }
            if !meta.is_dir() {
                return Err("staff-socket-parent-not-directory".into());
            }
            validate_socket_parent(&meta)
        }
        Err(e) => Err(format!("staff-socket-parent-metadata: {e}")),
    }
}
fn validate_socket_parent(meta: &std::fs::Metadata) -> Result<(), String> {
    if meta.uid() != unsafe { geteuid() } || meta.gid() != unsafe { getegid() } {
        return Err("staff-socket-parent-owner-mismatch".into());
    }
    if meta.permissions().mode() & 0o777 != 0o755 {
        return Err("staff-socket-parent-mode-mismatch".into());
    }
    Ok(())
}
fn remove_stale_staff_socket(path: &Path, identity: PathIdentity) -> Result<(), String> {
    let meta =
        fs::symlink_metadata(path).map_err(|e| format!("staff-socket-cleanup-metadata: {e}"))?;
    if !meta.file_type().is_socket() {
        return Err("staff-socket-cleanup-not-socket".into());
    }
    let current = PathIdentity {
        dev: meta.dev(),
        ino: meta.ino(),
    };
    if current != identity {
        return Err("staff-socket-cleanup-identity-mismatch".into());
    }
    fs::remove_file(path).map_err(|e| format!("staff-socket-cleanup-remove: {e}"))
}

pub fn cleanup_staff_socket(path: &Path, identity: &SocketIdentity) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if !meta.file_type().is_socket() => Err("staff-socket-cleanup-not-socket".into()),
        Ok(meta) => {
            if meta.dev() != identity.dev || meta.ino() != identity.ino {
                return Err("staff-socket-cleanup-identity-mismatch".into());
            }
            fs::remove_file(path).map_err(|e| format!("staff-socket-cleanup-remove: {e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("staff-socket-cleanup-metadata: {e}")),
    }
}

pub async fn serve_staff_connection(stream: UnixStream, app: Router) -> Result<(), String> {
    let info = peer_credentials(&stream)?;
    let io = TokioIo::new(stream);
    let service = hyper::service::service_fn(move |mut req| {
        let svc = app.clone();
        async move {
            req.extensions_mut().insert(ConnectInfo(info));
            svc.oneshot(req).await
        }
    });
    http1::Builder::new()
        .serve_connection(io, service)
        .await
        .map_err(|e| e.to_string())
}

async fn serve_unix(
    listener: UnixListener,
    app: Router,
    mut stop: watch::Receiver<bool>,
) -> Result<(), String> {
    let mut connections = JoinSet::new();
    let result = loop {
        tokio::select! {
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break Ok(());
                }
            }
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let connection_app = app.clone();
                        connections.spawn(async move {
                            if let Err(error) = serve_staff_connection(stream, connection_app).await {
                                eprintln!("caduceus-staff-connection-failed: {error}");
                            }
                        });
                    }
                    Err(error) => break Err(error.to_string()),
                }
            }
        }
    };
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    result
}

async fn wait_for_shutdown(mut stop: watch::Receiver<bool>) {
    while stop.changed().await.is_ok() && !*stop.borrow() {}
}

pub async fn run_async() -> i32 {
    match crate::routes::leaf_schema::initialize() {
        Ok(census) => eprintln!("caduceus-seats: {census}"),
        Err(error) => { eprintln!("{error}"); return 1; }
    }
    #[cfg(leaf_pid2)]
    let pid2_gate_ok = match crate::pid2::reset_gate() {
        Ok(_) => true,
        Err(error) => { eprintln!("pid2-reset-gate-failed: {error}"); false }
    };
    if let Err(error) = crate::crossings::initialize() {
        eprintln!("{error}");
        return 1;
    }
    let mut ctrl_c = match signal(SignalKind::interrupt()) {
        Ok(signal) => signal,
        Err(error) => {
            eprintln!("caduceus-signal-handler-failed: {error}");
            return 1;
        }
    };
    let mut terminate = match signal(SignalKind::terminate()) {
        Ok(signal) => signal,
        Err(error) => {
            eprintln!("caduceus-signal-handler-failed: {error}");
            return 1;
        }
    };
    if let Err(e) = audit_doors() {
        eprintln!("caduceus-doors-audit-failed: {e}");
        return 1;
    }
    let addr = match crate::shared::config::declared_bind() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("{error}");
            return 1;
        }
    };
    let socket_path = PathBuf::from(
        env::var("CADUCEUS_STAFF_SOCKET").unwrap_or_else(|_| "/run/caduceus/staff.sock".into()),
    );
    #[cfg(any(
        leaf_display_projector_power,
        leaf_display_projector_products,
        leaf_display_projector_scan
    ))]
    crate::routes::control_projector::import_catalog_at_serve_start();
    let tcp = match TcpListener::bind(addr).await {
        Ok(value) => value,
        Err(error) => {
            eprintln!("caduceus-bind-failed: {error}");
            return 1;
        }
    };
    let (uds, identity) = match prepare_staff_socket(&socket_path) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("caduceus-staff-socket-failed: {error}");
            return 1;
        }
    };
    #[cfg(leaf_storage_shares_converge)]
    tokio::task::spawn_blocking(|| {
        let receipt = crate::routes::leaf_storage_shares_converge::rebuild_at_start();
        let outcome = if let Some(signal) = receipt.get("doorSignal") {
            signal.as_str().unwrap_or("caduceus-agathodaimon-refused")
        } else if receipt.get("ok").and_then(serde_json::Value::as_bool) == Some(true) {
            "ok"
        } else {
            receipt.get("firstMissingSignal").and_then(serde_json::Value::as_str)
                .unwrap_or("caduceus-staff-invalid-receipt")
        };
        let outcome = outcome.split(char::is_control).next()
            .filter(|value| !value.is_empty())
            .unwrap_or("caduceus-staff-invalid-receipt");
        let outcome = if !receipt_succeeded(&receipt) && outcome == "ok" {
            "caduceus-agathodaimon-refused"
        } else {
            outcome
        };
        eprintln!("caduceus-shares-rebuild-start: {outcome}");
    });
    attendance::bind();
    crate::stats::start();
    #[cfg(leaf_pid2)]
    let pid2_task = pid2_gate_ok.then(|| tokio::spawn(crate::pid2::events::run()));
    crate::maintenance::start();
    let app = router();
    let (tx, rx) = watch::channel(false);
    let tcp_app = app.clone();
    let tcp_shutdown = wait_for_shutdown(rx.clone());
    let tcp_task = tokio::spawn(async move {
        let make_tcp_app = tower::service_fn(move |stream: IncomingStream<'_>| {
            // Use the accepted stream, not the listener's possibly wildcard bind.
            let local = TcpLocalIp(stream.local_addr().ok().map(|address| address.ip()));
            let peer = ConnectInfo(ConnectionInfo::Tcp(stream.remote_addr()));
            let service = ServiceBuilder::new()
                .layer(axum::Extension(peer))
                .layer(axum::Extension(local))
                .service(tcp_app.clone());
            std::future::ready(Ok::<_, std::convert::Infallible>(service))
        });
        axum::serve(tcp, make_tcp_app)
            .with_graceful_shutdown(tcp_shutdown)
            .await
            .map_err(|error| error.to_string())
    });
    let uds_task = tokio::spawn(serve_unix(uds, app, rx));
    let mut tcp_task = tcp_task;
    let mut uds_task = uds_task;
    let mut result = 1;
    let report =
        |label: &str, outcome: Result<Result<(), String>, tokio::task::JoinError>| match outcome {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                eprintln!("caduceus-{label}-serve-failed: {error}");
                false
            }
            Err(error) => {
                eprintln!("caduceus-{label}-serve-task-failed: {error}");
                false
            }
        };
    tokio::select! {
        tcp_result = &mut tcp_task => {
            if !report("tcp", tcp_result) { result = 1; }
            let _ = tx.send(true);
            if !report("uds", uds_task.await) { result = 1; }
        }
        uds_result = &mut uds_task => {
            if !report("uds", uds_result) { result = 1; }
            let _ = tx.send(true);
            if !report("tcp", tcp_task.await) { result = 1; }
        }
        _ = ctrl_c.recv() => {
            let _ = tx.send(true);
            result = 0;
            if !report("tcp", tcp_task.await) { result = 1; }
            if !report("uds", uds_task.await) { result = 1; }
        }
        _ = terminate.recv() => {
            let _ = tx.send(true);
            result = 0;
            if !report("tcp", tcp_task.await) { result = 1; }
            if !report("uds", uds_task.await) { result = 1; }
        }
    }
    #[cfg(leaf_pid2)]
    if let Some(task) = pid2_task { task.abort(); }
    if let Err(error) = crate::stats::stop() {
        eprintln!("caduceus-stats-stop-failed: {error}");
        result = 1;
    }
    if let Err(error) = cleanup_staff_socket(&socket_path, &identity) {
        eprintln!("caduceus-staff-socket-cleanup-failed: {error}");
        result = 1;
    }
    result
}

pub fn run() -> i32 {
    match tokio::runtime::Runtime::new() {
        Ok(rt) => rt.block_on(run_async()),
        Err(error) => {
            eprintln!("caduceus-serve-runtime-failed: {error}");
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
    let benchmark_started = if crate::protocol::benchmark_enabled(&raw) {
        Some((Instant::now(), crate::protocol::benchmark_receive_locus()?))
    } else {
        None
    };
    let envelope = crate::protocol::Envelope::parse(raw)?;
    let admittance = admittance::check_declared_admittance(declaration)?;
    let _ = discovery::walk_compiled_route_set(route_set)?;
    let mut receipt =
        receipts::append_stamp(&envelope, admittance, attendance_witness, true, true, None);
    if let Some((started, locus)) = benchmark_started {
        receipt["benchmarkStamp"] = serde_json::json!({
            "schema": crate::protocol::BENCHMARK_REPORT_SCHEMA,
            "timings": [crate::protocol::benchmark_timing_row(
                locus,
                started.elapsed(),
                true
            )]
        });
    }
    Ok(receipt)
}
