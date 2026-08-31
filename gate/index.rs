//! Generic HTTP gate kernel and live receiver.
//! Route bodies live in selected route leaves.

use crate::shared::{attendance, policy};
use axum::serve::IncomingStream;
use axum::{
    body::Body,
    extract::{
        connect_info::{ConnectInfo, Connected},
        DefaultBodyLimit,
    },
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
    env, fs,
    net::SocketAddr,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};
use tokio::{
    net::{TcpListener, UnixListener, UnixStream},
    signal::unix::{signal, SignalKind},
    sync::watch,
    task::JoinSet,
};
use tower::ServiceExt;

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
        .get::<ConnectInfo<ConnectionInfo>>()
        .is_some_and(|ConnectInfo(peer)| match peer {
            ConnectionInfo::Tcp(addr) => !addr.ip().is_loopback(),
            ConnectionInfo::Unix { .. } => false,
        })
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
impl Connected<IncomingStream<'_>> for ConnectionInfo {
    fn connect_info(stream: IncomingStream<'_>) -> Self {
        Self::Tcp(stream.remote_addr())
    }
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
        let _ = cleanup_staff_socket(path, &id);
        return Err(format!("staff-socket-owner: {e}"));
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
    let bind = env::var("CADUCEUS_BIND").unwrap_or_else(|_| "0.0.0.0:8787".into());
    let addr: SocketAddr = match bind.parse() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("caduceus-bind-invalid: {error}");
            return 1;
        }
    };
    let socket_path = PathBuf::from(
        env::var("CADUCEUS_STAFF_SOCKET").unwrap_or_else(|_| "/run/caduceus/staff.sock".into()),
    );
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
    attendance::bind();
    crate::stats::start();
    crate::maintenance::start();
    let app = router();
    let (tx, rx) = watch::channel(false);
    let tcp_app = app.clone();
    let tcp_shutdown = wait_for_shutdown(rx.clone());
    let tcp_task = tokio::spawn(async move {
        axum::serve(
            tcp,
            tcp_app.into_make_service_with_connect_info::<ConnectionInfo>(),
        )
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
