use axum::extract::rejection::PathRejection;
use axum::extract::ConnectInfo;
use axum::extract::OriginalUri;
use axum::extract::Path as RequestPath;
use axum::http::header::{CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::net::IpAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path as FsPath};

const DOCS_SCHEMA_ID: &str = "caduceus.docs.seal.v1";
const PERSPECTIVE_SCHEMA_ID: &str = "harmonia.ruyi-perspective.v1";
const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
const MAX_PERSPECTIVE_BYTES: usize = 1024 * 1024;

fn not_found(signal: &'static str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(crate::gate::ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: "docs".to_owned(),
            first_missing_signal: signal.to_owned(),
        }),
    )
        .into_response()
}

fn peer_allowed(peer: Option<&ConnectInfo<crate::gate::ConnectionInfo>>) -> bool {
    let Some(ConnectInfo(crate::gate::ConnectionInfo::Tcp(address))) = peer else {
        return false;
    };
    match address.ip() {
        IpAddr::V4(address) => {
            address.is_loopback() || address.is_private() || address.is_link_local()
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return mapped.is_loopback() || mapped.is_private() || mapped.is_link_local();
            }
            let octets = address.octets();
            address.is_loopback()
                || octets[0] & 0xfe == 0xfc
                || octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
        }
    }
}

fn valid_page_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path.as_bytes().iter().all(|byte| {
            matches!(
                *byte,
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'_' | b'/' | b'-'
            )
        })
        && path
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn content_type(path: &str) -> Option<&'static str> {
    let filename = path.rsplit('/').next()?;
    let extension = filename.rsplit_once('.')?.1;
    match extension {
        "md" => Some("text/markdown; charset=utf-8"),
        "png" => Some("image/png"),
        "jpg" => Some("image/jpeg"),
        "svg" => Some("image/svg+xml; charset=utf-8"),
        "txt" => Some("text/plain; charset=utf-8"),
        _ => None,
    }
}

fn open_document(page: &str) -> Result<File, &'static str> {
    let root_path = crate::shared::config::path("opt/docs/docs");
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(root_path)
        .map_err(|_| "caduceus-docs-root-unavailable")?;
    if !root
        .metadata()
        .map_err(|_| "caduceus-docs-root-unavailable")?
        .is_dir()
    {
        return Err("caduceus-docs-root-invalid");
    }

    let components = page.split('/').collect::<Vec<_>>();
    if components.is_empty() || components.iter().any(|part| part.is_empty()) {
        return Err("caduceus-docs-path-invalid");
    }
    let mut parent: OwnedFd = root.into();
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_bytes())
            .map_err(|_| "caduceus-docs-path-invalid")?;
        let last = index + 1 == components.len();
        let flags = if last {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK
        } else {
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY
        };
        let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            let error = io::Error::last_os_error();
            return Err(if error.kind() == io::ErrorKind::NotFound {
                "caduceus-docs-page-absent"
            } else {
                "caduceus-docs-page-unavailable"
            });
        }
        let opened = unsafe { OwnedFd::from_raw_fd(fd) };
        if last {
            return Ok(File::from(opened));
        }
        parent = opened;
    }
    Err("caduceus-docs-page-absent")
}

fn read_document(page: &str) -> Result<(Vec<u8>, &'static str), &'static str> {
    if !valid_page_path(page) {
        return Err("caduceus-docs-path-invalid");
    }
    let mime = content_type(page).ok_or("caduceus-docs-extension-unsupported")?;
    let file = open_document(page)?;
    let metadata = file
        .metadata()
        .map_err(|_| "caduceus-docs-page-unavailable")?;
    if !metadata.is_file() {
        return Err("caduceus-docs-page-not-regular");
    }
    if metadata.len() > MAX_DOCUMENT_BYTES as u64 {
        return Err("caduceus-docs-page-too-large");
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(MAX_DOCUMENT_BYTES as u64) as usize);
    file.take(MAX_DOCUMENT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "caduceus-docs-page-unavailable")?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err("caduceus-docs-page-too-large");
    }
    Ok((bytes, mime))
}

fn document_response(page: &str) -> Response {
    match read_document(page) {
        Ok((bytes, mime)) => {
            let mut response = (
                StatusCode::OK,
                [(CONTENT_TYPE, mime), (X_CONTENT_TYPE_OPTIONS, "nosniff")],
                bytes,
            )
                .into_response();
            if mime == "image/svg+xml; charset=utf-8" {
                response.headers_mut().insert(
                    CONTENT_SECURITY_POLICY,
                    HeaderValue::from_static("sandbox; default-src 'none'"),
                );
            }
            response
        }
        Err(signal) => not_found(signal),
    }
}

async fn llms(
    peer: Option<ConnectInfo<crate::gate::ConnectionInfo>>,
) -> Response {
    if !peer_allowed(peer.as_ref()) {
        return not_found("caduceus-docs-peer-not-allowed");
    }
    document_response("llms.txt")
}

async fn page(
    peer: Option<ConnectInfo<crate::gate::ConnectionInfo>>,
    OriginalUri(uri): OriginalUri,
    extracted: Result<RequestPath<String>, PathRejection>,
) -> Response {
    if !peer_allowed(peer.as_ref()) {
        return not_found("caduceus-docs-peer-not-allowed");
    }
    let raw_page = uri
        .path()
        .strip_prefix("/api/v1/docs/")
        .unwrap_or_default();
    let page = match extracted {
        Ok(path) => path.0,
        Err(_) => return not_found("caduceus-docs-path-invalid"),
    };
    if raw_page != page || !valid_page_path(raw_page) || !valid_page_path(&page) {
        return not_found("caduceus-docs-path-invalid");
    }
    document_response(&page)
}

fn open_nofollow_absolute_file(path: &FsPath) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "perspective path must be absolute",
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
                    "perspective path contains a non-normal component",
                ));
            }
        }
    }
    if components.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "perspective path has no file component",
        ));
    }
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/")?;
    let mut parent: OwnedFd = root.into();
    for (index, component) in components.iter().enumerate() {
        let name = CString::new(component.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in perspective path"))?;
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
        "perspective path has no file component",
    ))
}

fn valid_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn optional_hex(value: &Value, field: &str, length: usize) -> Option<Option<String>> {
    match value.get(field) {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(value)) if valid_lower_hex(value, length) => {
            Some(Some(value.clone()))
        }
        _ => None,
    }
}

fn optional_fire_seal(value: &Value) -> Option<Option<Value>> {
    match value.get("fire_seal") {
        None | Some(Value::Null) => Some(None),
        Some(seal @ Value::Object(_)) => {
            let band = seal.get("band")?.as_str()?;
            let _licensee = seal.get("licensee")?.as_str()?;
            let issued = seal.get("issued")?.as_str()?;
            if !valid_lower_hex(band, 64)
                || chrono::DateTime::parse_from_rfc3339(issued).is_err()
            {
                return None;
            }
            Some(Some(seal.clone()))
        }
        _ => None,
    }
}

fn optional_documentation_sha(self_row: &Value) -> Option<Option<String>> {
    match self_row.pointer("/member_flags/documentation/release_flag/source_sha") {
        None | Some(Value::Null) => Some(None),
        Some(Value::String(source_sha)) if valid_lower_hex(source_sha, 40) => {
            Some(Some(source_sha.clone()))
        }
        _ => None,
    }
}

fn perspective_observations() -> Option<(Option<String>, Option<Value>, Option<String>)> {
    let path = crate::shared::config::path("etc/appliance/ruyi.json");
    let file = open_nofollow_absolute_file(&path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file() || metadata.len() > MAX_PERSPECTIVE_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len().min(MAX_PERSPECTIVE_BYTES as u64) as usize);
    file.take(MAX_PERSPECTIVE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_PERSPECTIVE_BYTES {
        return None;
    }
    let perspective: Value = serde_json::from_slice(&bytes).ok()?;
    if !crate::routes::leaf_schema::accepts(PERSPECTIVE_SCHEMA_ID, &perspective) {
        return None;
    }
    let self_row = perspective.get("self")?;
    if !crate::routes::leaf_schema::accepts_form("caduceus.ruyi.v1", "row", self_row) {
        return None;
    }
    let stamp_sha = optional_hex(self_row, "stamp_sha", 64)?;
    let fire_seal = optional_fire_seal(self_row)?;
    let documentation_sha = optional_documentation_sha(self_row)?;
    Some((stamp_sha, fire_seal, documentation_sha))
}

async fn seal(
    peer: Option<ConnectInfo<crate::gate::ConnectionInfo>>,
) -> Response {
    if !peer_allowed(peer.as_ref()) {
        return not_found("caduceus-docs-peer-not-allowed");
    }
    let (stamp_sha, fire_seal, documentation_sha, signal) =
        match perspective_observations() {
            Some((stamp_sha, fire_seal, documentation_sha)) => {
                (stamp_sha, fire_seal, documentation_sha, Value::Null)
            }
            None => (
                None,
                None,
                None,
                json!("ruyi-perspective-absent"),
            ),
        };
    let value = json!({
        "schema": DOCS_SCHEMA_ID,
        "profile": crate::routes::profile_routes::ACTIVE_PROFILE,
        "stamp_sha": stamp_sha,
        "fire_seal": fire_seal,
        "documentation_sha": documentation_sha,
        "observed_at": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        "signal": signal,
    });
    if !crate::routes::leaf_schema::accepts(DOCS_SCHEMA_ID, &value) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(crate::gate::ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "docs".to_owned(),
                first_missing_signal: "caduceus-docs-seal-schema-desync".to_owned(),
            }),
        )
            .into_response();
    }
    Json(value).into_response()
}

pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/docs/llms.txt", axum::routing::get(llms))
        .route("/api/v1/docs/seal", axum::routing::get(seal))
        .route("/api/v1/docs/*page", axum::routing::get(page))
}
