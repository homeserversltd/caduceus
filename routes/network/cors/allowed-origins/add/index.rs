use crate::gate::ApiErrorBody;
use crate::shared::config;
use axum::{
    extract::Json,
    http::{HeaderMap, StatusCode},
    Router,
};
use serde_json::{json, Value};
use std::sync::Mutex;

const COMMAND: &str = "network cors allowed-origins add";
const TARGET: &str = "global.cors.allowed_origins";
static WRITE_LOCK: Mutex<()> = Mutex::new(());

fn origin_key(raw: &str) -> Option<(String, String, u16)> {
    let url = url::Url::parse(raw.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = url.host_str()?.to_ascii_lowercase();
    // HTTP(S) URL parsing decodes host escapes before this wildcard check.
    if host.contains('*') {
        return None;
    }
    Some((
        url.scheme().to_ascii_lowercase(),
        host,
        url.port_or_known_default()?,
    ))
}

fn add_origin(origin: &str) -> Result<Value, String> {
    let key = origin_key(origin).ok_or_else(|| "caduceus-cors-origin-invalid".to_string())?;
    let _guard = WRITE_LOCK
        .lock()
        .map_err(|_| "caduceus-cors-write-lock-failed".to_string())?;
    let shown = config::show_json()?;
    let mut current = shown
        .get("document")
        .ok_or_else(|| "caduceus-cors-config-invalid".to_string())?;
    for segment in ["global", "cors"] {
        let object = current
            .as_object()
            .ok_or_else(|| "caduceus-cors-config-ancestor-invalid".to_string())?;
        match object.get(segment) {
            Some(value) => current = value,
            None => return config::set_json(TARGET, json!([origin])),
        }
    }
    let object = current
        .as_object()
        .ok_or_else(|| "caduceus-cors-config-ancestor-invalid".to_string())?;
    let mut origins = match object.get("allowed_origins") {
        None => Vec::new(),
        Some(value) => value
            .as_array()
            .cloned()
            .ok_or_else(|| "caduceus-cors-config-origins-invalid".to_string())?,
    };
    if origins.iter().any(|entry| !entry.is_string()) {
        return Err("caduceus-cors-config-origins-invalid".to_string());
    }
    if origins
        .iter()
        .any(|entry| entry.as_str().and_then(origin_key).as_ref() == Some(&key))
    {
        return config::set_json(TARGET, Value::Array(origins));
    }
    origins.push(Value::String(origin.to_string()));
    config::set_json(TARGET, Value::Array(origins))
}

async fn add_route(
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    crate::gate::access_attendance_admits(&headers)?;
    let origin = body
        .get("origin")
        .and_then(Value::as_str)
        .ok_or_else(|| error("caduceus-cors-origin-invalid".to_string()))?;
    add_origin(origin).map(Json).map_err(error)
}

fn error(signal: String) -> (StatusCode, Json<ApiErrorBody>) {
    let status = if signal == "caduceus-cors-origin-invalid" {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: COMMAND.to_string(),
            first_missing_signal: signal,
        }),
    )
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/network/cors/allowed-origins/add",
        axum::routing::post(add_route),
    )
}
