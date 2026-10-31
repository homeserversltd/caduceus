//! Generic HTTP registration for selected route leaves without an `index.rs`.
//! The declaration remains the route, policy, body, receipt, and response seat.

use axum::{
    body::{to_bytes, Body},
    http::{header::CONTENT_TYPE, HeaderMap, Method, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, delete, get, head, on, patch, post, put, MethodFilter},
    Json, Router,
};
use serde_json::{json, Map, Value};
use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, Instant},
};

const DEFAULT_GATE_DEADLINE: Duration = Duration::from_secs(30);
const MAX_CROSSING_DEADLINE: Duration = Duration::from_secs(600);
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;
// No queued mutations: each selected leaf's permit belongs to its detached
// invocation until its complete finalizer walk returns, even on disconnect.

#[derive(Debug)]
struct DoorFailure {
    status: StatusCode,
    signal: String,
    witness: Option<Value>,
    no_change: bool,
}

struct DoorReply {
    status: StatusCode,
    body: Value,
    receipt: Value,
    changed: Option<bool>,
    is_chord: bool,
}

struct DeedGuard {
    declaration: Arc<Value>,
    request_id: String,
    started: Instant,
    enabled: bool,
    attempted: bool,
    recorded: bool,
}

impl DeedGuard {
    fn record(&mut self, outcome: &str, signal: &str, witness: Option<&Value>) {
        if !self.enabled || self.recorded {
            return;
        }
        self.recorded = true;
        record_deed(
            &self.declaration,
            &self.request_id,
            self.started.elapsed(),
            outcome,
            signal,
            witness,
        );
    }
}

impl Drop for DeedGuard {
    fn drop(&mut self) {
        if self.attempted {
            self.record("refused", "caduceus-generic-task-aborted", None);
        }
    }
}

impl DoorFailure {
    fn new(status: StatusCode, signal: impl Into<String>) -> Self {
        Self { status, signal: signal.into(), witness: None, no_change: true }
    }

    fn after_attempt(mut self) -> Self {
        self.no_change = false;
        self
    }

    fn with_witness(mut self, witness: Value, changed: Option<bool>) -> Self {
        self.no_change = changed == Some(false);
        self.witness = Some(witness);
        self
    }
}

/// The compiled router registers only index-less leaves here. This bounded,
/// declaration-only set lets the existing gate recognize defaulted generic
/// paths without reclassifying any handwritten route that also has `serve`.
static GENERIC_HTTP_NAMESPACES: OnceLock<RwLock<HashMap<String, Arc<tokio::sync::Semaphore>>>> = OnceLock::new();

fn register_generic_namespace(namespace: &str) {
    let namespaces = GENERIC_HTTP_NAMESPACES.get_or_init(|| RwLock::new(HashMap::new()));
    namespaces.write().unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(namespace.to_owned()).or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)));
}

fn mutation_slot(namespace: &str) -> Option<Arc<tokio::sync::Semaphore>> {
    GENERIC_HTTP_NAMESPACES.get().and_then(|namespaces| {
        namespaces.read().unwrap_or_else(|poisoned| poisoned.into_inner()).get(namespace).cloned()
    })
}

pub(crate) fn is_registered_namespace(namespace: &str) -> bool {
    GENERIC_HTTP_NAMESPACES.get().is_some_and(|namespaces| {
        namespaces.read().unwrap_or_else(|poisoned| poisoned.into_inner()).contains_key(namespace)
    })
}

/// Register one index-less selected leaf using its static declaration.
/// Missing `http_method` and `http_path` mean POST and `/api/v1/<namespace>`.
pub fn register(router: Router, source: &'static str) -> Router {
    let declaration: Value = serde_json::from_str(source)
        .expect("caduceus-generic-http-declaration-invalid");
    let namespace = declaration.get("namespace").and_then(Value::as_str)
        .expect("caduceus-generic-http-namespace-missing");
    register_generic_namespace(namespace);
    let method = declaration.get("http_method").and_then(Value::as_str)
        .unwrap_or("POST").to_ascii_uppercase();
    let path = declaration.get("http_path").and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("/api/v1/{namespace}"));

    let declaration = Arc::new(declaration);
    let expected_method = method.clone();
    let handler = move |request: Request<Body>| {
        let declaration = Arc::clone(&declaration);
        let expected_method = expected_method.clone();
        async move { handle_request(request, declaration, expected_method).await }
    };

    let method_router = match method.as_str() {
        "GET" => get(handler),
        "HEAD" => head(handler),
        "POST" => post(handler),
        "PUT" => put(handler),
        "PATCH" => patch(handler),
        "DELETE" => delete(handler),
        "OPTIONS" => on(MethodFilter::OPTIONS, handler),
        "CONNECT" => on(MethodFilter::CONNECT, handler),
        "TRACE" => on(MethodFilter::TRACE, handler),
        _ => any(handler),
    };
    router.route(&path, method_router)
}

async fn handle_request(
    request: Request<Body>,
    declaration: Arc<Value>,
    expected_method: String,
) -> Response {
    let started = Instant::now();
    let namespace = declaration.get("namespace").and_then(Value::as_str).unwrap_or("generic");
    let command = first_command(&declaration).unwrap_or_default();
    let mutation_allowed = declaration.get("mutation_allowed").and_then(Value::as_bool).unwrap_or(true);
    let (parts, body) = request.into_parts();
    let request_id = request_id(&parts.headers);

    if parts.method.as_str() != expected_method.as_str()
        && !(expected_method == "GET" && parts.method == Method::HEAD)
    {
        let failure = DoorFailure::new(StatusCode::METHOD_NOT_ALLOWED, "caduceus-http-method-not-allowed");
        return finish_failure(&declaration, &request_id, started, mutation_allowed, &command, failure);
    }

    if command.is_empty() {
        let failure = DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "caduceus-generic-command-missing");
        return finish_failure(&declaration, &request_id, started, mutation_allowed, &command, failure);
    }
    if let Err(signal) = crate::gate::admittance::check_declared_admittance(&declaration) {
        let failure = DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, signal);
        return finish_failure(&declaration, &request_id, started, mutation_allowed, &command, failure);
    }
    match crate::shared::policy::allows_command(&command) {
        Ok(true) => {}
        Ok(false) => {
            let failure = DoorFailure::new(StatusCode::FORBIDDEN, "caduceus-public-action-not-allowed");
            return finish_failure(&declaration, &request_id, started, mutation_allowed, &command, failure);
        }
        Err(_) => {
            let failure = DoorFailure::new(StatusCode::FORBIDDEN, "caduceus-carapace-desync");
            return finish_failure(&declaration, &request_id, started, mutation_allowed, &command, failure);
        }
    }

    let receipt_schema = match receipt_schema(&declaration) {
        Some(schema) if crate::routes::leaf_schema::declaration(schema).is_some() => Some(schema.to_owned()),
        Some(_) => {
            let failure = DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "caduceus-schema-desync");
            return finish_failure(&declaration, &request_id, started, mutation_allowed, &command, failure);
        }
        None => None,
    };
    let payload = match read_payload(parts.headers, body, &declaration).await {
        Ok(payload) => payload,
        Err(failure) => {
            return finish_failure(&declaration, &request_id, started, mutation_allowed, &command, failure);
        }
    };

    let permit = if mutation_allowed {
        let Some(slot) = mutation_slot(namespace) else {
            return error_response(StatusCode::SERVICE_UNAVAILABLE, &command, "caduceus-generic-slot-missing");
        };
        match slot.try_acquire_owned() {
            Ok(permit) => Some(permit),
            // No mutation has started: the rejected concurrent request is a non-event.
            Err(_) => return error_response(StatusCode::SERVICE_UNAVAILABLE, &command, "caduceus-generic-mutation-busy"),
        }
    } else { None };
    // This independent task owns the complete invocation and deed. Dropping the
    // HTTP future after this spawn cannot cancel a running serve/finally chord.
    let task_declaration = Arc::clone(&declaration);
    let task_command = command.clone();
    let task_namespace = namespace.to_owned();
    let task_request_id = request_id.clone();
    let task = tokio::spawn(async move {
        let _permit = permit;
        let mut deed = DeedGuard {
            declaration: Arc::clone(&task_declaration),
            request_id: task_request_id.clone(),
            started,
            enabled: mutation_allowed,
            attempted: false,
            recorded: false,
        };
        let result = dispatch(&task_declaration, &task_namespace, &task_request_id, payload, receipt_schema.as_deref(), &mut deed).await;
        let response = match result {
            Ok(reply) => {
                let ok = reply.receipt.get("ok").and_then(Value::as_bool) == Some(true);
                let signal = receipt_signal(&reply.receipt).filter(|signal| ok || *signal != "none")
                    .unwrap_or(if ok { "none" } else { "caduceus-generic-actuator-refused" });
                if !reply.is_chord || reply.changed == Some(false) {
                    deed.recorded = true;
                } else {
                    deed.record(
                        if ok { "success" } else { "refused" },
                        signal,
                        Some(&reply.receipt),
                    );
                }
                (reply.status, Json(reply.body)).into_response()
            }
            Err(failure) => {
                if failure.no_change { deed.recorded = true; }
                else { deed.record("refused", &failure.signal, failure.witness.as_ref()); }
                error_response(failure.status, &task_command, &failure.signal)
            }
        };
        // A completed mutation may have released a resource that held a PID-2
        // line. Wake only after dispatch (including finally) and deed handling.
        #[cfg(leaf_pid2)]
        if mutation_allowed && deed.attempted { crate::pid2::events::notify(); }
        response
    });
    match task.await {
        Ok(response) => response,
        Err(_) => {
            // The spawned task is detached from the client and normally writes
            // before it returns. A join failure is surfaced without retaining a
            // receipt or creating a second deed that could duplicate its write.
            error_response(StatusCode::SERVICE_UNAVAILABLE, &command, "caduceus-generic-task-join-failed")
        }
    }
}

async fn read_payload(
    headers: HeaderMap,
    body: Body,
    declaration: &Value,
) -> Result<Value, DoorFailure> {
    let body_mode = declaration.get("body").and_then(Value::as_str).unwrap_or("optional");
    let bytes = to_bytes(body, MAX_REQUEST_BODY_BYTES).await
        .map_err(|_| DoorFailure::new(StatusCode::PAYLOAD_TOO_LARGE, "caduceus-request-body-too-large"))?;
    let empty = bytes.is_empty();
    match body_mode {
        "none" | "forbidden" => {
            if !empty {
                return Err(DoorFailure::new(StatusCode::BAD_REQUEST, "caduceus-request-body-not-allowed"));
            }
            Ok(Value::Object(Map::new()))
        }
        "optional" | "required" => {
            if empty {
                if body_mode == "required" {
                    return Err(DoorFailure::new(StatusCode::BAD_REQUEST, "caduceus-request-body-required"));
                }
                return Ok(Value::Object(Map::new()));
            }
            if !content_type_is_json(&headers) {
                return Err(DoorFailure::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "caduceus-request-content-type-invalid"));
            }
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| DoorFailure::new(StatusCode::BAD_REQUEST, "caduceus-request-body-invalid"))?;
            if !value.is_object() {
                return Err(DoorFailure::new(StatusCode::BAD_REQUEST, "caduceus-request-body-object-required"));
            }
            Ok(value)
        }
        _ => Err(DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "caduceus-generic-body-declaration-invalid")),
    }
}

fn content_type_is_json(headers: &HeaderMap) -> bool {
    headers.get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim)
        .is_some_and(|value| value.eq_ignore_ascii_case("application/json") || value.to_ascii_lowercase().ends_with("+json"))
}

async fn dispatch(
    declaration: &Value,
    namespace: &str,
    request_id: &str,
    payload: Value,
    receipt_schema: Option<&str>,
    deed: &mut DeedGuard,
) -> Result<DoorReply, DoorFailure> {
    let serve = declaration.get("serve").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let finally = declaration.get("finally").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    if serve.is_empty() && finally.is_empty() {
        return Err(DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "caduceus-generic-serve-empty"));
    }
    let deadline = match declaration.get("deadline_seconds") {
        None => DEFAULT_GATE_DEADLINE,
        Some(value) => match value.as_u64().filter(|seconds| *seconds > 0) {
            Some(seconds) => Duration::from_secs(seconds),
            None => return Err(DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "caduceus-generic-deadline-invalid")),
        },
    };

    let mut envelope = crate::gate::snake::route_envelope(namespace, &payload);
    if let Some(object) = envelope.as_object_mut() {
        object.insert("intent_id".into(), json!(format!("caduceus-{namespace}-{request_id}")));
    } else {
        return Err(DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "protocol-envelope-not-object"));
    }

    let is_chord = serve.len() != 1 || !finally.is_empty()
        || serve.iter().chain(finally.iter()).any(|step| {
            ["stage_id", "arguments", "required", "depends_on", "deadline_seconds"]
                .iter().any(|field| step.get(*field).is_some())
        });
    let chord_receipt_schema = if is_chord {
        Some(receipt_schema.unwrap_or("caduceus.chord.receipt.v1"))
    } else {
        None
    };
    let validation_schema = receipt_schema.or(chord_receipt_schema);
    if let Some(schema) = validation_schema {
        if crate::routes::leaf_schema::declaration(schema).is_none() {
            return Err(DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "caduceus-schema-desync"));
        }
    }
    deed.attempted = true;
    let receipt = if is_chord {
        crate::gate::snake::execute_native_chord(
            namespace, serve, finally, &envelope, chord_receipt_schema.expect("chord schema selected"), deadline,
        ).await.map_err(|signal| DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, signal).after_attempt())?
    } else {
        let bounded_timeout = deadline.min(MAX_CROSSING_DEADLINE);
        let crossing = crate::gate::snake::execute_ordered_serve_with_timeout(
            serve, &envelope, Some(bounded_timeout),
        ).await.map_err(|signal| DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, signal).after_attempt())?;
        crossing.get("receiptPayload").cloned().ok_or_else(|| {
            DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "caduceus-generic-receipt-missing").after_attempt()
        })?
    };

    if validation_schema.is_some_and(|schema| !crate::routes::leaf_schema::accepts(schema, &receipt)) {
        return Err(DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, "caduceus-schema-desync").with_witness(receipt, None).after_attempt());
    }
    let changed = declared_receipt_change(validation_schema, &receipt);
    let body = project_response(declaration, &receipt)
        .map_err(|signal| {
            let failure = DoorFailure::new(StatusCode::SERVICE_UNAVAILABLE, signal).with_witness(receipt.clone(), changed);
            if is_chord { failure } else { failure.after_attempt() }
        })?;
    let status = status_from_declaration(declaration, &receipt)
        .unwrap_or_else(|| crate::gate::mutation_status(&receipt));
    Ok(DoorReply { status, body, receipt, changed, is_chord })
}

// Only a boolean declared by the expected public seat can establish a no-op.
// An absent seat, undeclared extension, or malformed value remains unknown.
pub(crate) fn declared_receipt_change(schema: Option<&str>, receipt: &Value) -> Option<bool> {
    let schema = schema?;
    if !crate::routes::leaf_schema::accepts(schema, receipt) { return None; }
    let seat = crate::routes::leaf_schema::declaration(schema)?;
    let declared = ["required", "optional"].iter().any(|key| {
        seat.get(*key).and_then(Value::as_array)
            .is_some_and(|fields| fields.iter().any(|field| field.as_str() == Some("changed")))
    });
    if !declared || seat.pointer("/fields/changed/type").and_then(Value::as_str) != Some("boolean") {
        return None;
    }
    receipt.get("changed").and_then(Value::as_bool)
}

fn first_command(declaration: &Value) -> Option<String> {
    declaration.get("commands")?.as_array()?.first().and_then(|command| {
        command.as_str().map(ToOwned::to_owned)
            .or_else(|| command.get("name").and_then(Value::as_str).map(ToOwned::to_owned))
    })
}

fn receipt_schema(declaration: &Value) -> Option<&str> {
    declaration.get("receipt").and_then(Value::as_str)
        .or_else(|| declaration.pointer("/flags/receiptSchema").and_then(Value::as_str))
}

fn status_from_declaration(declaration: &Value, receipt: &Value) -> Option<StatusCode> {
    let table = declaration.get("status_table")
        .or_else(|| declaration.get("statusTable"))
        .or_else(|| declaration.get("status"))?
        .as_object()?;
    let ok = receipt.get("ok").and_then(Value::as_bool) == Some(true);
    let outcome = receipt.get("outcome").and_then(Value::as_str);
    let aliases: &[&str] = if ok { &["success", "ok", "true", "2xx"] } else { &["failure", "failed", "refused", "error", "false", "5xx"] };
    let mapped = outcome.and_then(|outcome| table.get(outcome))
        .or_else(|| aliases.iter().find_map(|key| table.get(*key)))?;
    let code = mapped.as_u64().and_then(|value| u16::try_from(value).ok())
        .or_else(|| mapped.as_str().and_then(|value| value.parse::<u16>().ok()))?;
    StatusCode::from_u16(code).ok()
}

fn project_response(declaration: &Value, source: &Value) -> Result<Value, &'static str> {
    let Some(project) = declaration.get("project").or_else(|| declaration.get("projection")) else {
        return Ok(source.clone());
    };
    if let Some(path) = project.as_str() {
        return lookup_project_path(source, path).ok_or("caduceus-http-response-project-invalid");
    }
    if let Some(path) = project.get("path").and_then(Value::as_str) {
        return lookup_project_path(source, path).ok_or("caduceus-http-response-project-invalid");
    }
    let fields = project.get("fields").and_then(Value::as_object)
        .or_else(|| project.as_object())
        .ok_or("caduceus-http-response-project-invalid")?;
    let mut output = Map::new();
    for (name, path) in fields {
        if name == "fields" || name == "path" { continue; }
        let path = path.as_str().ok_or("caduceus-http-response-project-invalid")?;
        let value = lookup_project_path(source, path)
            .ok_or("caduceus-http-response-project-invalid")?;
        output.insert(name.clone(), value);
    }
    Ok(Value::Object(output))
}

fn lookup_project_path(source: &Value, path: &str) -> Option<Value> {
    if path.is_empty() || path == "." || path == "$" {
        return Some(source.clone());
    }
    if path.starts_with('/') {
        return source.pointer(path).cloned();
    }
    let path = path.strip_prefix("$.").unwrap_or(path);
    let mut current = source;
    for segment in path.split('.') {
        current = if let Ok(index) = segment.parse::<usize>() {
            current.get(index)?
        } else {
            current.get(segment)?
        };
    }
    Some(current.clone())
}

fn receipt_signal(receipt: &Value) -> Option<&str> {
    receipt.get("firstMissingSignal").and_then(Value::as_str)
        .filter(|signal| !signal.is_empty())
        .or_else(|| receipt.get("signal").and_then(Value::as_str).filter(|signal| !signal.is_empty()))
}

fn error_response(status: StatusCode, command: &str, signal: &str) -> Response {
    (status, Json(json!({
        "schema": "caduceus.api.error.v1",
        "ok": false,
        "command": command,
        "firstMissingSignal": signal,
    }))).into_response()
}

fn finish_failure(
    _declaration: &Value,
    _request_id: &str,
    _started: Instant,
    _mutation_allowed: bool,
    command: &str,
    failure: DoorFailure,
) -> Response {
    // Refusal before dispatch cannot have changed state and leaves no deed.
    error_response(failure.status, command, &failure.signal)
}

fn request_id(_headers: &HeaderMap) -> String {
    // A caller-controlled correlation header is not safe ledger metadata.
    uuid::Uuid::new_v4().to_string()
}

fn deed_signal(signal: &str) -> &str {
    if signal.len() <= 64 && signal.split('-').all(|part| {
        !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }) {
        signal
    } else {
        "caduceus-actuator-refused"
    }
}

fn deed_missing_field(witness: Option<&Value>) -> Option<&str> {
    let witness = witness?;
    let failed = witness.get("failedStage").and_then(Value::as_str);
    let receipt = failed.and_then(|id| witness.get("stages").and_then(Value::as_array)?
        .iter().find(|stage| stage.get("stage_id").and_then(Value::as_str) == Some(id))?
        .get("receipt")).unwrap_or(witness);
    let field = receipt.get("firstMissingField").or_else(|| receipt.get("first_missing_field"))?.as_str()?;
    let mut bytes = field.bytes();
    let first = bytes.next()?;
    if field.len() <= 32 && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        Some(field)
    } else {
        None
    }
}

pub(crate) fn record_deed(
    declaration: &Value,
    request_id: &str,
    elapsed: Duration,
    outcome: &str,
    signal: &str,
    witness: Option<&Value>,
) {
    let namespace = declaration.get("namespace").and_then(Value::as_str).unwrap_or("generic");
    let aggregate = witness.filter(|value| value.get("routine_id").and_then(Value::as_str).is_some());
    let stages = aggregate.and_then(|value| value.get("stages")).and_then(Value::as_array);
    // The full stage list remains in the reply. Keep the log summary bounded
    // as stage counts grow, and keep ids and outcomes paired.
    let mut stage_ids=Vec::new();
    let mut stage_outcomes=Vec::new();
    let mut budget=200usize;
    let mut stage_count=0usize;
    for stage in stages.into_iter().flatten().take(32) {
        stage_count += 1;
        let Some(id)=stage.get("stage_id").and_then(Value::as_str) else { continue; };
        let Some(result)=stage.get("outcome").and_then(Value::as_str) else { continue; };
        if id.is_empty() || id.len()>48 || !id.chars().all(|c|c.is_ascii_alphanumeric() || "_.-".contains(c)) || !matches!(result,"stage-completed"|"stage-refused"|"stage-skipped") { continue; }
        let cost=id.len()+result.len()+8;
        if cost>budget { continue; }
        budget-=cost;
        stage_ids.push(id.to_owned());
        stage_outcomes.push(result.to_owned());
    }
    let failed_stage = aggregate.and_then(|value| value.get("failedStage"))
        .and_then(Value::as_str)
        .filter(|stage| !stage.is_empty() && stage.len() <= 48
            && stage.chars().all(|character| character.is_ascii_alphanumeric() || "_.-".contains(character)))
        .map(|stage| Value::String(stage.to_owned()))
        .unwrap_or(Value::Null);
    let ok = outcome == "success";
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ": "caduceus",
        "kind": "generic-http-door",
        "level": if ok { "info" } else { "error" },
        "ok": ok,
        "message": "generic HTTP deed",
        "correlation_id": request_id,
        "attributes_redacted": {
            "who": "owner",
            "verb": "http",
            "target": namespace,
            "routine_id": namespace,
            "request_id": request_id,
            "outcome": outcome,
            "duration_ms": elapsed.as_millis().min(u64::MAX as u128) as u64,
            "stage_ids": stage_ids,
            "stage_outcomes": stage_outcomes,
            "stage_count": stage_count,
            "failedStage": failed_stage,
            "signal": deed_signal(signal),
            "first_missing_field": deed_missing_field(witness),
        }
    }));
}
