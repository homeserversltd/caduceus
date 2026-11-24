use crate::gate::blocking_task;
use crate::shared::{hyalos::LogFilters, policy};
use axum::http::StatusCode;
use axum::{
    body::to_bytes,
    extract::Request,
    http::header::CONTENT_TYPE,
    routing::post,
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::LazyLock;

const COMMAND: &str = "storage backup ledger";
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: u64 = 200;
static DECLARATION: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("index.json")).expect("backup ledger declaration")
});

type Rejection = (StatusCode, &'static str);

async fn page_request(request: Request) -> Result<(Option<u64>, usize), Rejection> {
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_REQUEST_BODY_BYTES)
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "caduceus-request-body-too-large"))?;
    if bytes.is_empty() {
        return Ok((None, DEFAULT_LIMIT));
    }
    let json_content_type = parts
        .headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| {
            value.eq_ignore_ascii_case("application/json")
                || value.to_ascii_lowercase().ends_with("+json")
        });
    if !json_content_type {
        return Err((StatusCode::UNSUPPORTED_MEDIA_TYPE, "caduceus-request-content-type-invalid"));
    }
    let body: Value = serde_json::from_slice(&bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "caduceus-request-body-invalid"))?;
    if !body.is_object() {
        return Err((StatusCode::BAD_REQUEST, "caduceus-request-body-object-required"));
    }
    // The old door accepted flat fields too (used by the Crown relay).
    let metadata = body.get("metadata").unwrap_or(&body);
    if !metadata.is_null() && !metadata.is_object() {
        return Err((StatusCode::BAD_REQUEST, "metadata-invalid"));
    }
    let before = match metadata.get("before") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value.as_u64().ok_or((StatusCode::BAD_REQUEST, "before-invalid"))?,
        ),
    };
    let limit = match metadata.get("limit") {
        None => DEFAULT_LIMIT,
        Some(value) => value
            .as_u64()
            .filter(|limit| (1..=MAX_LIMIT).contains(limit))
            .ok_or((StatusCode::BAD_REQUEST, "limit-invalid"))? as usize,
    };
    Ok((before, limit))
}

fn answer(
    status: StatusCode,
    signal: &str,
    page: Option<(Vec<Value>, Option<i64>)>,
    read_attempted: bool,
) -> (StatusCode, Json<Value>) {
    let ok = page.is_some();
    let (rows, next) = page.unwrap_or_default();
    let observed = ok.then(|| json!({"row_count": rows.len()}));
    (status, Json(json!({
        "schema": DECLARATION["receipt"],
        "stop": {"noun": "storage/backup", "verb": "ledger"},
        "ok": ok, "rows": rows, "next": next, "firstMissingSignal": signal,
        "observed": observed,
        "could_change_to": null,
        "attempt": {"attempted": read_attempted},
        "final_receipt": {"ok": ok, "firstMissingSignal": signal},
    })))
}

async fn http(request: Request) -> (StatusCode, Json<Value>) {
    // Keep the generic door's declaration and command checks. The shared
    // router still owns administrative admission, including a configured shelf.
    if let Err(signal) = crate::gate::admittance::check_declared_admittance(&DECLARATION) {
        return answer(StatusCode::SERVICE_UNAVAILABLE, &signal, None, false);
    }
    match policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => {
            return answer(StatusCode::FORBIDDEN, "caduceus-public-action-not-allowed", None, false);
        }
        Err(_) => {
            return answer(StatusCode::FORBIDDEN, "caduceus-carapace-desync", None, false);
        }
    }
    let (before, limit) = match page_request(request).await {
        Ok(page) => page,
        Err((status, signal)) => return answer(status, signal, None, false),
    };
    match blocking_task(COMMAND, move || LogFilters::read_backup_page(before, limit)).await {
        Ok(Ok(page)) => answer(StatusCode::OK, "none", Some(page), true),
        Ok(Err(_)) => answer(
            StatusCode::SERVICE_UNAVAILABLE,
            "backup-ledger-unavailable",
            None,
            true,
        ),
        Err((status, Json(error))) => answer(status, &error.first_missing_signal, None, true),
    }
}

pub fn register(router: Router) -> Router {
    router.route(LEAF_STORAGE_BACKUP_LEDGER_CANONICAL, post(http))
}
