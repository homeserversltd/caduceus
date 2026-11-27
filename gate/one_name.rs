//! Declaration-driven re-entry into the registered router, below the gate.
use axum::{body::{to_bytes, Body}, extract::connect_info::ConnectInfo,
    http::{header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE}, Method, Request, StatusCode, Uri},
    response::{IntoResponse, Response}, routing::post, Json, Router};
use serde_json::{json, Map, Value};
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;

static REGISTERED: OnceLock<Router> = OnceLock::new();
pub(super) fn keep_router(router: Router) { let _ = REGISTERED.set(router); }

#[derive(Clone)]
enum ForwardBody { None, Payload, Envelope }

struct Forward {
    method: Method,
    path: String,
    path_fields: Vec<(String, String)>,
    query_fields: Vec<String>,
    body: ForwardBody,
    body_required: bool,
    required: Vec<String>,
}

fn read_forward(namespace: &str, declaration: &Value) -> Result<Forward, String> {
    let forward = declaration.get("forward").and_then(Value::as_object).ok_or("forward missing or not an object")?;
    let method = match forward.get("method").and_then(Value::as_str) {
        Some("GET") => Method::GET, Some("POST") => Method::POST,
        Some("PUT") => Method::PUT, Some("PATCH") => Method::PATCH,
        Some("DELETE") => Method::DELETE, Some("HEAD") => Method::HEAD,
        Some("OPTIONS") => Method::OPTIONS, Some("CONNECT") => Method::CONNECT,
        Some("TRACE") => Method::TRACE,
        _ => return Err("forward.method missing or unknown HTTP method".into()),
    };
    let path = forward.get("path").and_then(Value::as_str).ok_or("forward.path missing or not a string")?;
    if !path.starts_with("/api/v1/") || path == format!("/api/v1/{namespace}") {
        return Err("forward.path must begin /api/v1/ and not name the leaf itself".into());
    }
    let uri: Uri = path.parse().map_err(|_| "forward.path is not a valid URI")?;
    if uri.path() != path || uri.query().is_some() {
        return Err("forward.path must be a path without a query".into());
    }
    let mut path_fields = Vec::new();
    if let Some(value) = forward.get("path_fields") {
        let fields = value.as_object().ok_or("forward.path_fields is not an object")?;
        for (name, field) in fields {
            let segment = format!(":{}", name.trim_start_matches(':'));
            if segment == ":" || !path.split('/').any(|part| part == segment) {
                return Err(format!("forward.path_fields key {name} is not a path segment"));
            }
            let field = field.as_str().ok_or_else(|| format!("forward.path_fields value for {name} is not a string"))?;
            path_fields.push((segment, field.to_owned()));
        }
    }
    let mut query_fields = Vec::new();
    if let Some(value) = forward.get("query_fields") {
        let fields = value.as_array().ok_or("forward.query_fields is not an array")?;
        for field in fields {
            query_fields.push(field.as_str().ok_or("forward.query_fields entry is not a string")?.to_owned());
        }
    }
    let body = match forward.get("body").and_then(Value::as_str) {
        Some("none") => ForwardBody::None,
        Some("payload") => ForwardBody::Payload,
        Some("envelope") => ForwardBody::Envelope,
        _ => return Err("forward.body must be none, payload, or envelope".into()),
    };
    Ok(Forward { method, path: path.to_owned(), path_fields, query_fields, body,
        body_required: declaration.get("body").and_then(Value::as_str) == Some("required"),
        required: crate::routes::leaf_schema::intent_required_payload(namespace).unwrap_or_default() })
}

pub fn register(router: Router, namespace: &'static str) -> Router {
    let declaration: Value = crate::routes::selected_declaration(namespace)
        .ok_or("declaration missing").and_then(|s| serde_json::from_str(s).map_err(|_| "declaration invalid"))
        .unwrap_or_else(|fault| panic!("one-name {namespace}: {fault}"));
    let forward = read_forward(namespace, &declaration)
        .unwrap_or_else(|fault| panic!("one-name {namespace}: {fault}"));
    let declaration = Arc::new(declaration);
    let forward = Arc::new(forward);
    router.route(&format!("/api/v1/{namespace}"), post(move |request| {
        let declaration = declaration.clone();
        let forward = forward.clone();
        async move { forward_request(request, namespace, &declaration, &forward).await }
    }))
}

fn refusal_detail(namespace: &str, declaration: &Value, status: StatusCode, signal: &str, field: Option<&str>) -> Response {
    let (noun, verb) = namespace.rsplit_once('/').unwrap_or((namespace, ""));
    let command = declaration["commands"].as_array().and_then(|a| a.first()).and_then(Value::as_str).unwrap_or("");
    (status, Json(json!({"schema":"caduceus.staff.receipt.v1", "ok":false,
        "observed":{"route":format!("/api/v1/{namespace}"),"method":"POST","missing_field":field},
        "could_change_to":null, "attempt":{"attempted":false,"step":"payload"},
        "final_receipt":{"ok":false,"firstMissingSignal":signal}, "firstMissingSignal":signal,
        "stop":{"noun":noun,"verb":verb},"command":command}))).into_response()
}
fn refusal(namespace: &str, declaration: &Value, status: StatusCode, signal: &str) -> Response {
    refusal_detail(namespace, declaration, status, signal, None)
}

fn scalar(value: &Value) -> Option<String> {
    match value { Value::String(s) if !s.is_empty() => Some(s.clone()), Value::Number(n) => Some(n.to_string()), _ => None }
}
fn segment(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { out.push(b as char); }
        else { out.push_str(&format!("%{b:02X}")); }
    }
    out
}
async fn forward_request(request: Request<Body>, namespace: &str, declaration: &Value, forward: &Forward) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 2 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return refusal(namespace, declaration, StatusCode::PAYLOAD_TOO_LARGE, "caduceus-request-body-too-large"),
    };
    if bytes.is_empty() && forward.body_required {
        return refusal(namespace, declaration, StatusCode::BAD_REQUEST, "caduceus-request-body-required");
    }
    let mut payload = if bytes.is_empty() { Value::Object(Map::new()) } else {
        let json_type = parts.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next()).map(str::trim)
            .is_some_and(|v| v.eq_ignore_ascii_case("application/json") || v.to_ascii_lowercase().ends_with("+json"));
        if !json_type { return refusal(namespace, declaration, StatusCode::UNSUPPORTED_MEDIA_TYPE, "caduceus-request-content-type-invalid"); }
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(v) if v.is_object() => v,
            Ok(_) => return refusal(namespace, declaration, StatusCode::BAD_REQUEST, "caduceus-request-body-object-required"),
            Err(_) => return refusal(namespace, declaration, StatusCode::BAD_REQUEST, "caduceus-request-body-invalid"),
        }
    };
    for field in &forward.required {
        if payload.get(field).is_none_or(Value::is_null) {
            return refusal_detail(namespace, declaration, StatusCode::BAD_REQUEST, "caduceus-one-name-required-field-missing", Some(field));
        }
    }
    let mut path = forward.path.clone();
    for (needle, field) in &forward.path_fields {
        let Some(value) = payload.get(field).and_then(scalar) else {
            return refusal(namespace, declaration, StatusCode::BAD_REQUEST, "caduceus-one-name-path-field-missing");
        };
        path = path.split('/').map(|part| if part == needle { segment(&value) } else { part.to_owned() }).collect::<Vec<_>>().join("/");
        if let Some(object) = payload.as_object_mut() { object.remove(field); }
    }
    let query = {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        for field in &forward.query_fields {
            if let Some(value) = payload.as_object_mut().and_then(|object| object.remove(field)) {
                if !value.is_null() { query.append_pair(field, value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string()).as_str()); }
            }
        }
        query.finish()
    };
    if !query.is_empty() { path.push('?'); path.push_str(&query); }
    let data = match forward.body {
        ForwardBody::None => Ok(Vec::new()),
        ForwardBody::Payload => serde_json::to_vec(&payload),
        ForwardBody::Envelope => {
            let mut envelope = crate::gate::snake::route_envelope(namespace, &payload);
            envelope["intent_id"] = json!(format!("caduceus-{namespace}-{}", uuid::Uuid::new_v4()));
            serde_json::to_vec(&envelope)
        }
    };
    let Ok(data) = data else { return refusal(namespace, declaration, StatusCode::INTERNAL_SERVER_ERROR, "caduceus-one-name-serialization-failed"); };
    let Ok(mut inner) = Request::builder().method(forward.method.clone()).uri(path).body(Body::from(data.clone())) else {
        return refusal(namespace, declaration, StatusCode::INTERNAL_SERVER_ERROR, "caduceus-one-name-uri-invalid");
    };
    *inner.headers_mut() = parts.headers;
    inner.headers_mut().remove(CONTENT_LENGTH);
    inner.headers_mut().remove(CONTENT_TYPE);
    if let Ok(length) = HeaderValue::from_str(&data.len().to_string()) { inner.headers_mut().insert(CONTENT_LENGTH, length); }
    if !data.is_empty() { inner.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json")); }
    if let Some(peer) = parts.extensions.get::<ConnectInfo<super::ConnectionInfo>>() { inner.extensions_mut().insert(*peer); }
    if let Some(local) = parts.extensions.get::<super::TcpLocalIp>() { inner.extensions_mut().insert(*local); }
    let Some(router) = REGISTERED.get() else {
        return refusal(namespace, declaration, StatusCode::INTERNAL_SERVER_ERROR, "caduceus-one-name-router-unavailable");
    };
    match router.clone().oneshot(inner).await { Ok(response) => response, Err(never) => match never {} }
}
