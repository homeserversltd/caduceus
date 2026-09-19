/// Canonical C2 leaf; real handler is owned by the legacy-compatible support band.
pub const NAMESPACE: &str = "portals/deploy";
pub use crate::routes::report_links::*;

use axum::{
    body::Body,
    extract::{Json, Path},
    http::{header::CONTENT_TYPE, Request, StatusCode},
    response::IntoResponse,
};
use http_body_util::BodyExt;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Path as FsPath, PathBuf},
    sync::OnceLock,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tower_http::limit::RequestBodyLimitLayer;

pub const DEFAULT_CHUNK_SIZE: u64 = 4 * 1024 * 1024;
pub const MAX_CHUNK_SIZE: u64 = 8 * 1024 * 1024;
pub const CHUNK_BODY_MARGIN: usize = 64 * 1024;
pub const CHUNK_BODY_LIMIT: usize = MAX_CHUNK_SIZE as usize + CHUNK_BODY_MARGIN;

#[derive(Deserialize)]
struct UploadStart {
    filename: String,
    total_size: u64,
    target_dir: String,
    chunk_size: Option<u64>,
}

struct UploadSession {
    spool_path: PathBuf,
    target_path: PathBuf,
    total_size: u64,
    chunk_size: u64,
    bytes_received: u64,
    file: tokio::fs::File,
    metadata: Value,
}

fn upload_sessions() -> &'static tokio::sync::Mutex<HashMap<String, UploadSession>> {
    static SESSIONS: OnceLock<tokio::sync::Mutex<HashMap<String, UploadSession>>> = OnceLock::new();
    SESSIONS.get_or_init(|| tokio::sync::Mutex::new(HashMap::new()))
}

fn upload_error(status: StatusCode, signal: &str) -> axum::response::Response {
    (
        status,
        Json(json!({
            "ok": false,
            "firstMissingSignal": signal,
        })),
    )
        .into_response()
}

fn staff_admitted() -> Result<(), axum::response::Response> {
    match crate::shared::policy::allows_command("staff intent") {
        Ok(true) => Ok(()),
        Ok(false) => Err(upload_error(
            StatusCode::FORBIDDEN,
            "caduceus-public-action-not-allowed",
        )),
        Err(_) => Err(upload_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-profile-missing",
        )),
    }
}

fn valid_filename(filename: &str) -> bool {
    !filename.is_empty()
        && FsPath::new(filename)
            .file_name()
            .and_then(|value| value.to_str())
            == Some(filename)
}

fn spool_root() -> PathBuf {
    std::env::var_os("CADUCEUS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
        .join("var/lib/caduceus/spool/file-ingress")
}

fn next_spool_path(root: &FsPath) -> Result<PathBuf, &'static str> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "caduceus-file-ingress-spool-clock-invalid")?
        .as_nanos();
    Ok(root.join(format!("{}-{nanos}", std::process::id())))
}

async fn staff_route(
    actuator: &str,
    body: serde_json::Value,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    match crate::shared::policy::allows_command("staff intent") {
        Ok(true) => crate::routes::staff::named_actuator_json(actuator, body)
            .map(|v| (crate::gate::mutation_status(&v), axum::Json(v)))
            .map_err(|e| crate::gate::api_error_signal("staff intent", &e)),
        Ok(false) => Err(crate::gate::api_error("staff intent")),
        Err(_) => Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-profile-missing",
        )),
    }
}

async fn file_ingress(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    staff_route("storage/upload/ingress", body).await
}

async fn file_ingress_start(Json(body): Json<UploadStart>) -> axum::response::Response {
    if let Err(response) = staff_admitted() {
        return response;
    }
    if !valid_filename(&body.filename) {
        return upload_error(
            StatusCode::BAD_REQUEST,
            "caduceus-file-ingress-filename-invalid",
        );
    }
    let chunk_size = body.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
        return upload_error(
            StatusCode::BAD_REQUEST,
            "caduceus-file-ingress-chunk-size-invalid",
        );
    }
    let logical_target = format!(
        "{}/{}",
        body.target_dir.trim_end_matches('/'),
        body.filename
    );
    let target_path = match crate::routes::staff::file_ingress_target(&logical_target) {
        Ok(path) => path,
        Err(signal) => return upload_error(StatusCode::BAD_REQUEST, &signal),
    };
    if !target_path.parent().is_some_and(FsPath::is_dir) {
        return upload_error(
            StatusCode::BAD_REQUEST,
            "caduceus-file-ingress-destination-missing",
        );
    }
    if std::fs::symlink_metadata(&target_path)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return upload_error(
            StatusCode::BAD_REQUEST,
            "caduceus-file-ingress-target-symlink",
        );
    }

    let root = spool_root();
    if tokio::fs::create_dir_all(&root).await.is_err() {
        return upload_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-file-ingress-spool-unavailable",
        );
    }
    let spool_path = match next_spool_path(&root) {
        Ok(path) => path,
        Err(signal) => return upload_error(StatusCode::INTERNAL_SERVER_ERROR, signal),
    };
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).read(true).write(true).mode(0o600);
    let file = match options.open(&spool_path).await {
        Ok(file) => file,
        Err(_) => {
            return upload_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "caduceus-file-ingress-spool-open-failed",
            )
        }
    };
    if file.set_len(body.total_size).await.is_err() {
        let _ = tokio::fs::remove_file(&spool_path).await;
        return upload_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-file-ingress-spool-preallocate-failed",
        );
    }

    let upload_id = uuid::Uuid::new_v4().to_string();
    let metadata = json!({
        "filename": body.filename,
        "bytes": body.total_size,
        "destination": body.target_dir,
        "total_size": body.total_size,
        "chunk_size": chunk_size,
    });
    let session = UploadSession {
        spool_path: spool_path.clone(),
        target_path,
        total_size: body.total_size,
        chunk_size,
        bytes_received: 0,
        file,
        metadata,
    };
    if upload_sessions()
        .lock()
        .await
        .insert(upload_id.clone(), session)
        .is_some()
    {
        let _ = tokio::fs::remove_file(spool_path).await;
        return upload_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-file-ingress-upload-id-collision",
        );
    }
    (StatusCode::OK, Json(json!({"upload_id": upload_id}))).into_response()
}

async fn file_ingress_chunk(
    Path((upload_id, index)): Path<(String, u64)>,
    request: Request<Body>,
) -> axum::response::Response {
    if let Err(response) = staff_admitted() {
        return response;
    }
    let content_type = request
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if content_type != Some("application/octet-stream") {
        return upload_error(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "caduceus-file-ingress-content-type-invalid",
        );
    }

    let mut sessions = upload_sessions().lock().await;
    let Some(session) = sessions.get_mut(&upload_id) else {
        return upload_error(
            StatusCode::NOT_FOUND,
            "caduceus-file-ingress-upload-id-unknown",
        );
    };
    let Some(offset) = index.checked_mul(session.chunk_size) else {
        return upload_error(
            StatusCode::BAD_REQUEST,
            "caduceus-file-ingress-chunk-offset-invalid",
        );
    };
    if offset != session.bytes_received {
        return upload_error(
            StatusCode::CONFLICT,
            "caduceus-file-ingress-chunk-out-of-order",
        );
    }
    let remaining = session.total_size.saturating_sub(session.bytes_received);
    let allowed = remaining.min(session.chunk_size);
    if session
        .file
        .seek(std::io::SeekFrom::Start(offset))
        .await
        .is_err()
    {
        return upload_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-file-ingress-spool-seek-failed",
        );
    }

    let mut body = request.into_body();
    let mut received = 0_u64;
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => {
                return upload_error(
                    StatusCode::BAD_REQUEST,
                    "caduceus-file-ingress-chunk-read-failed",
                )
            }
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        let frame_len = data.len() as u64;
        if received
            .checked_add(frame_len)
            .is_none_or(|next| next > allowed)
        {
            return upload_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "caduceus-file-ingress-chunk-too-large",
            );
        }
        if session.file.write_all(&data).await.is_err() {
            return upload_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "caduceus-file-ingress-spool-write-failed",
            );
        }
        received += frame_len;
    }
    if received == 0 && remaining != 0 {
        return upload_error(StatusCode::BAD_REQUEST, "caduceus-file-ingress-chunk-empty");
    }
    if received != allowed && received < remaining {
        return upload_error(
            StatusCode::BAD_REQUEST,
            "caduceus-file-ingress-chunk-size-mismatch",
        );
    }
    if session.file.flush().await.is_err() {
        return upload_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-file-ingress-spool-flush-failed",
        );
    }
    session.bytes_received += received;
    (
        StatusCode::OK,
        Json(json!({"bytes_received": session.bytes_received})),
    )
        .into_response()
}

async fn file_ingress_complete(Path(upload_id): Path<String>) -> axum::response::Response {
    if let Err(response) = staff_admitted() {
        return response;
    }
    let mut sessions = upload_sessions().lock().await;
    let Some(session) = sessions.get_mut(&upload_id) else {
        return upload_error(
            StatusCode::NOT_FOUND,
            "caduceus-file-ingress-upload-id-unknown",
        );
    };
    if session.bytes_received != session.total_size {
        return upload_error(
            StatusCode::CONFLICT,
            "caduceus-file-ingress-size-incomplete",
        );
    }
    if session.file.sync_all().await.is_err() {
        return upload_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-file-ingress-spool-fsync-failed",
        );
    }
    let session = sessions
        .remove(&upload_id)
        .expect("session was observed under the same lock");
    drop(sessions);
    let UploadSession {
        spool_path,
        target_path,
        total_size,
        file,
        metadata,
        ..
    } = session;
    drop(file);

    let result = tokio::task::spawn_blocking(move || {
        crate::routes::staff::execute_spooled_file_ingress(
            metadata,
            &spool_path,
            &target_path,
            total_size,
        )
    })
    .await;
    match result {
        Ok(Ok(receipt)) => (crate::gate::mutation_status(&receipt), Json(receipt)).into_response(),
        Ok(Err(signal)) => upload_error(StatusCode::SERVICE_UNAVAILABLE, &signal),
        Err(_) => upload_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-file-ingress-complete-task-failed",
        ),
    }
}

async fn file_ingress_abort(Path(upload_id): Path<String>) -> axum::response::Response {
    if let Err(response) = staff_admitted() {
        return response;
    }
    let session = upload_sessions().lock().await.remove(&upload_id);
    let Some(session) = session else {
        return (StatusCode::OK, Json(json!({"ok": true}))).into_response();
    };
    drop(session.file);
    match tokio::fs::remove_file(&session.spool_path).await {
        Ok(()) => (StatusCode::OK, Json(json!({"ok": true}))).into_response(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (StatusCode::OK, Json(json!({"ok": true}))).into_response()
        }
        Err(_) => upload_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-file-ingress-abort-cleanup-failed",
        ),
    }
}

async fn force_permissions(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    staff_route("storage/upload/force-permissions", body).await
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/file/ingress", axum::routing::post(file_ingress))
        .route(
            "/api/v1/file/ingress/start",
            axum::routing::post(file_ingress_start),
        )
        .route(
            "/api/v1/file/ingress/:upload_id/chunk/:index",
            axum::routing::post(file_ingress_chunk)
                .layer(RequestBodyLimitLayer::new(CHUNK_BODY_LIMIT)),
        )
        .route(
            "/api/v1/file/ingress/:upload_id/complete",
            axum::routing::post(file_ingress_complete),
        )
        .route(
            "/api/v1/file/ingress/:upload_id",
            axum::routing::delete(file_ingress_abort),
        )
        .route(
            "/api/v1/upload/force-permissions",
            axum::routing::post(force_permissions),
        )
}
