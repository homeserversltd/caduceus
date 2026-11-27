//! Declaration-driven re-entry into the registered router, below the gate.
use axum::{body::{to_bytes, Body}, extract::connect_info::ConnectInfo,
    http::{header::{CONTENT_LENGTH, CONTENT_TYPE}, Method, Request, StatusCode},
    response::{IntoResponse, Response}, routing::post, Json, Router};
use serde_json::{json, Map, Value};
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;

static REGISTERED: OnceLock<Router> = OnceLock::new();
pub(super) fn keep_router(router: Router) { let _ = REGISTERED.set(router); }

pub fn register(router: Router, namespace: &'static str) -> Router {
    let declaration: Value = serde_json::from_str(crate::routes::selected_declaration(namespace)
        .expect("one-name declaration missing")).expect("one-name declaration invalid");
    let forward = declaration.get("forward").expect("one-name forward missing");
    let path = forward.get("path").and_then(Value::as_str).expect("one-name path missing");
    assert_ne!(path, format!("/api/v1/{namespace}"), "one-name forward to self");
    let declaration = Arc::new(declaration);
    router.route(&format!("/api/v1/{namespace}"), post(move |request| {
        let declaration = declaration.clone();
        async move { forward_request(request, namespace, &declaration).await }
    }))
}

fn refusal(namespace: &str, declaration: &Value, status: StatusCode, signal: &str) -> Response {
    let (noun, verb) = namespace.rsplit_once('/').unwrap_or((namespace, ""));
    let command = declaration["commands"].as_array().and_then(|a| a.first()).and_then(Value::as_str).unwrap_or("");
    (status, Json(json!({"schema":"caduceus.staff.receipt.v1", "ok":false,
        "observed":{"route":format!("/api/v1/{namespace}"),"method":"POST"},
        "could_change_to":null, "attempt":{"attempted":false,"step":"payload"},
        "final_receipt":{"ok":false,"firstMissingSignal":signal}, "firstMissingSignal":signal,
        "stop":{"noun":noun,"verb":verb},"command":command}))).into_response()
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
async fn forward_request(request: Request<Body>, namespace: &str, declaration: &Value) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 2 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return refusal(namespace, declaration, StatusCode::PAYLOAD_TOO_LARGE, "caduceus-request-body-too-large"),
    };
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
    let forward = &declaration["forward"];
    let mut path = forward["path"].as_str().expect("one-name path missing").to_owned();
    if let Some(fields) = forward["path_fields"].as_object() {
        for (name, field) in fields {
            let field = field.as_str().expect("one-name path field invalid");
            let Some(value) = payload.get(field).and_then(scalar) else {
                return refusal(namespace, declaration, StatusCode::BAD_REQUEST, "caduceus-one-name-path-field-missing");
            };
            let needle = format!(":{}", name.trim_start_matches(':'));
            path = path.split('/').map(|part| if part == needle { segment(&value) } else { part.to_owned() }).collect::<Vec<_>>().join("/");
            payload.as_object_mut().unwrap().remove(field);
        }
    }
    let query = {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(fields) = forward["query_fields"].as_array() {
            for field in fields {
                let field = field.as_str().expect("one-name query field invalid");
                if let Some(value) = payload.as_object_mut().unwrap().remove(field) {
                    if !value.is_null() { query.append_pair(field, value.as_str().map(str::to_owned).unwrap_or_else(|| value.to_string()).as_str()); }
                }
            }
        }
        query.finish()
    };
    if !query.is_empty() { path.push('?'); path.push_str(&query); }
    let data = match forward["body"].as_str().expect("one-name body missing") {
        "none" => Vec::new(),
        "payload" => serde_json::to_vec(&payload).expect("one-name payload serialization"),
        "envelope" => {
            let mut envelope = crate::gate::snake::route_envelope(namespace, &payload);
            envelope["intent_id"] = json!(format!("caduceus-{namespace}-{}", uuid::Uuid::new_v4()));
            serde_json::to_vec(&envelope).expect("one-name envelope serialization")
        }
        _ => panic!("one-name body invalid"),
    };
    let method = Method::from_bytes(forward["method"].as_str().expect("one-name method missing").as_bytes()).expect("one-name method invalid");
    let mut inner = Request::builder().method(method).uri(path).body(Body::from(data.clone())).expect("one-name URI invalid");
    *inner.headers_mut() = parts.headers;
    inner.headers_mut().remove(CONTENT_LENGTH);
    inner.headers_mut().remove(CONTENT_TYPE);
    inner.headers_mut().insert(CONTENT_LENGTH, data.len().to_string().parse().unwrap());
    if !data.is_empty() { inner.headers_mut().insert(CONTENT_TYPE, "application/json".parse().unwrap()); }
    if let Some(peer) = parts.extensions.get::<ConnectInfo<super::ConnectionInfo>>() { inner.extensions_mut().insert(*peer); }
    REGISTERED.get().expect("one-name router not initialized").clone().oneshot(inner).await.expect("router is infallible")
}
