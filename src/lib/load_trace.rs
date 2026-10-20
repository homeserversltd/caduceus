use axum::{
    body::Body,
    extract::Request,
    http::{HeaderMap, HeaderValue, Response},
    middleware::Next,
};
use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{SecondsFormat, Utc};
use serde::{ser::SerializeStruct, Serializer};
use serde_json::{json, Map, Value};
use std::{
    cell::RefCell,
    sync::{Arc, Mutex},
    time::Instant,
};
use tokio::task_local;
use uuid::Uuid;

const CORRELATION_HEADER: &str = "x-correlation-id";
const CONTEXT_HEADER: &str = "x-alkahest-context";
const MAX_CONTEXT_BYTES: usize = 16 * 1024;
const MAX_CONTEXT_HEADER_BYTES: usize = 24 * 1024;
const MAX_CORRELATION_BYTES: usize = 256;
const MAX_STAMPS: usize = 64;
const MAX_STAMP_BYTES: usize = 2048;

pub type ContextHandle = Arc<Mutex<TraceState>>;

#[derive(Debug)]
pub struct TraceState {
    raw: Option<Value>,
    raw_source: Option<Value>,
    correlation_id: Option<String>,
    echo_id: Option<HeaderValue>,
    unavailable: Option<String>,
    incomplete: Option<String>,
    benchmark: bool,
}

#[derive(Debug)]
pub struct Invocation {
    invocation_id: String,
    parent_span_id: Option<String>,
    received_at_utc: String,
    started: Instant,
}

tokio::task_local! {
    static ACTIVE_CONTEXT: ContextHandle;
}

thread_local! {
    // This slot exists only while one explicitly captured spawn_blocking closure runs.
    static BLOCKING_CONTEXT: RefCell<Option<ContextHandle>> = const { RefCell::new(None) };
}

struct RestoreBlockingContext(Option<ContextHandle>);

impl Drop for RestoreBlockingContext {
    fn drop(&mut self) {
        let previous = self.0.take();
        BLOCKING_CONTEXT.with(|slot| *slot.borrow_mut() = previous);
    }
}

fn now_utc() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn schema_id(declaration_id: &str) -> Option<String> {
    crate::routes::leaf_schema::declaration(declaration_id)
        .and_then(|declaration| declaration.get("schema"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn context_schema() -> Option<String> {
    schema_id("appliance.load.context.v1")
}

fn context_values(headers: &HeaderMap, name: &str) -> (Option<HeaderValue>, bool) {
    let values = headers.get_all(name);
    let mut iter = values.iter();
    let first = iter.next().cloned();
    (first, iter.next().is_some())
}

fn decode_context(encoded: &HeaderValue) -> Result<Value, &'static str> {
    let text = encoded
        .to_str()
        .map_err(|_| "caduceus-load-context-header-not-utf8")?;
    if text.len() > MAX_CONTEXT_HEADER_BYTES {
        return Err("caduceus-load-context-header-too-large");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .or_else(|_| URL_SAFE.decode(text))
        .map_err(|_| "caduceus-load-context-base64url-invalid")?;
    if bytes.len() > MAX_CONTEXT_BYTES {
        return Err("caduceus-load-context-too-large");
    }
    serde_json::from_slice(&bytes).map_err(|_| "caduceus-load-context-json-invalid")
}

fn source_schema(value: &Value) -> Option<&str> {
    value.get("schema").and_then(Value::as_str)
}

fn valid_context(value: &Value, expected: &str) -> bool {
    value.is_object()
        && source_schema(value) == Some(expected)
        && value
            .get("correlation_id")
            .and_then(Value::as_str)
            .is_some_and(|id| !id.is_empty() && id.len() <= MAX_CORRELATION_BYTES)
        && value.get("stamps").is_some_and(Value::is_array)
}

fn state_from_headers(headers: &HeaderMap) -> Option<ContextHandle> {
    let (correlation, duplicate_correlation) = context_values(headers, CORRELATION_HEADER);
    let (encoded, duplicate_context) = context_values(headers, CONTEXT_HEADER);
    if correlation.is_none() && encoded.is_none() && !duplicate_correlation && !duplicate_context {
        return None;
    }

    let expected = context_schema();
    let decoded = encoded.as_ref().map(decode_context);
    let raw_source = decoded.as_ref().and_then(|result| result.as_ref().ok()).cloned();
    let header_id = correlation
        .as_ref()
        .and_then(|value| std::str::from_utf8(value.as_bytes()).ok())
        .map(str::to_owned);

    let mut unavailable = if duplicate_correlation || duplicate_context {
        Some("caduceus-load-context-header-duplicated".to_owned())
    } else {
        None
    };
    if correlation.as_ref().is_some_and(|value| {
        std::str::from_utf8(value.as_bytes())
            .map(|text| text.is_empty() || text.len() > MAX_CORRELATION_BYTES)
            .unwrap_or(true)
    }) {
        unavailable.get_or_insert_with(|| "caduceus-correlation-id-invalid".to_owned());
    }
    if let Some(Err(signal)) = decoded.as_ref() {
        unavailable.get_or_insert_with(|| (*signal).to_owned());
    }
    if encoded.is_some() && expected.is_none() {
        unavailable.get_or_insert_with(|| "caduceus-load-context-seat-unavailable".to_owned());
    }

    let mut raw = raw_source.clone();
    if let (Some(value), Some(expected)) = (raw.as_ref(), expected.as_deref()) {
        if !valid_context(value, expected) {
            unavailable.get_or_insert_with(|| {
                if source_schema(value) != Some(expected) {
                    "caduceus-load-context-schema-mismatch".to_owned()
                } else {
                    "caduceus-load-context-shape-invalid".to_owned()
                }
            });
        }
    }

    let context_id = raw
        .as_ref()
        .and_then(|value| value.get("correlation_id"))
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let (Some(header_id), Some(context_id)) = (header_id.as_deref(), context_id.as_deref()) {
        if header_id != context_id {
            unavailable.get_or_insert_with(|| "caduceus-load-context-correlation-mismatch".to_owned());
        }
    }

    if encoded.is_none() && unavailable.is_none() {
        if let (Some(expected), Some(correlation_id)) = (expected.as_deref(), header_id.as_deref()) {
            raw = Some(json!({
                "schema": expected,
                "correlation_id": correlation_id,
                "stamps": []
            }));
        } else if expected.is_none() {
            unavailable = Some("caduceus-load-context-seat-unavailable".to_owned());
        }
    }

    let valid = unavailable.is_none()
        && raw
            .as_ref()
            .zip(expected.as_deref())
            .is_some_and(|(value, expected)| valid_context(value, expected));
    let correlation_id = header_id.or(context_id);
    let echo_id = correlation.or_else(|| {
        correlation_id
            .as_deref()
            .and_then(|value| HeaderValue::from_bytes(value.as_bytes()).ok())
    });
    let stamp_count = raw
        .as_ref()
        .and_then(|value| value.get("stamps"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let benchmark = raw
        .as_ref()
        .and_then(|value| value.get("benchmark"))
        .and_then(Value::as_bool)
        .unwrap_or(false);

    Some(Arc::new(Mutex::new(TraceState {
        raw: valid.then_some(raw).flatten(),
        raw_source,
        correlation_id,
        echo_id,
        unavailable,
        incomplete: if stamp_count > MAX_STAMPS {
            Some("caduceus-load-context-stamp-limit".to_owned())
        } else {
            None
        },
        benchmark,
    })))
}

pub async fn http_boundary(request: Request<Body>, next: Next) -> Response<Body> {
    let Some(context) = state_from_headers(request.headers()) else {
        return next.run(request).await;
    };
    let echo_id = context
        .lock()
        .ok()
        .and_then(|state| state.echo_id.clone());
    let mut response = ACTIVE_CONTEXT
        .scope(context, async move { next.run(request).await })
        .await;
    if let Some(value) = echo_id {
        response.headers_mut().insert(CORRELATION_HEADER, value);
    }
    response
}

pub fn current() -> Option<ContextHandle> {
    ACTIVE_CONTEXT
        .try_with(Clone::clone)
        .ok()
        .or_else(|| BLOCKING_CONTEXT.with(|slot| slot.borrow().clone()))
}

pub fn with_blocking_context<T>(context: Option<ContextHandle>, run: impl FnOnce() -> T) -> T {
    let Some(context) = context else {
        return run();
    };
    let previous = BLOCKING_CONTEXT.with(|slot| slot.borrow_mut().replace(context));
    let _restore = RestoreBlockingContext(previous);
    run()
}

fn context_snapshot(context: &ContextHandle) -> Option<Value> {
    context.lock().ok().and_then(|state| state.raw.clone())
}

fn mark_incomplete(context: &ContextHandle, signal: &str) {
    if let Ok(mut state) = context.lock() {
        state.incomplete.get_or_insert_with(|| signal.to_owned());
    }
}

fn context_parent(value: &Value) -> Option<String> {
    value
        .get("stamps")
        .and_then(Value::as_array)
        .and_then(|stamps| stamps.iter().rev().find_map(|stamp| stamp.get("span_id")))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            value
                .get("parent_span_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
}

pub fn invocation_id(invocation: &Invocation) -> &str {
    &invocation.invocation_id
}

pub fn begin_invocation(context: &ContextHandle) -> Invocation {
    let parent_span_id = context_snapshot(context).as_ref().and_then(context_parent);
    Invocation {
        invocation_id: Uuid::new_v4().to_string(),
        parent_span_id,
        received_at_utc: now_utc(),
        started: Instant::now(),
    }
}

fn detailed_requested(context: &ContextHandle, explicit: bool) -> bool {
    explicit
        || context
            .lock()
            .ok()
            .is_some_and(|state| state.benchmark)
}

pub fn finish_invocation(
    context: &ContextHandle,
    invocation: Invocation,
    operation: &str,
    road: &str,
    source_state: &str,
    cache_state: &str,
    outcome: &str,
    instrumented: Option<bool>,
    detailed: bool,
) {
    let returned_at_utc = now_utc();
    let elapsed = invocation.started.elapsed();
    let mut stamp = json!({
        "namespace": "caduceus.load_trace.v1",
        "hop": "caduceus",
        "span_id": invocation.invocation_id,
        "invocation_id": invocation.invocation_id,
        "parent_span_id": invocation.parent_span_id,
        "operation": operation,
        "received_at_utc": invocation.received_at_utc,
        "returned_at_utc": returned_at_utc,
        "at_utc": returned_at_utc,
        "build_identity": {
            "version": env!("CARGO_PKG_VERSION"),
            "build_sha": option_env!("CADUCEUS_BUILD_SHA").unwrap_or("unset")
        },
        "outcome": outcome,
        "road": road,
        "source_state": source_state,
        "cache_state": cache_state
    });
    if let Some(instrumented) = instrumented {
        stamp["staff_instrumented"] = Value::Bool(instrumented);
        if !instrumented {
            stamp["staff_observation"] = Value::String("pre-upgrade-uninstrumented".to_owned());
        }
    }
    let locus = format!("caduceus.load_trace.{operation}");
    let mut benchmark = json!({
        "schema": crate::protocol::benchmark_report_schema(),
        "timings": [crate::protocol::benchmark_timing_row(locus, elapsed, outcome == "ok")]
    });
    if detailed_requested(context, detailed) {
        benchmark["detail_requested"] = Value::Bool(true);
    }
    stamp["benchmark"] = benchmark;
    let Ok(serialized) = serde_json::to_vec(&stamp) else {
        mark_incomplete(context, "caduceus-load-context-stamp-serialization-failed");
        return;
    };
    if serialized.len() > MAX_STAMP_BYTES {
        mark_incomplete(context, "caduceus-load-context-stamp-too-large");
        return;
    }
    let Ok(mut state) = context.lock() else {
        return;
    };
    if state.incomplete.is_some() {
        return;
    }
    let Some(mut candidate) = state.raw.clone() else {
        state.incomplete = Some("caduceus-load-context-state-unavailable".to_owned());
        return;
    };
    let Some(stamps) = candidate
        .as_object_mut()
        .and_then(|raw| raw.get_mut("stamps"))
        .and_then(Value::as_array_mut)
    else {
        state.incomplete = Some("caduceus-load-context-stamps-invalid".to_owned());
        return;
    };
    if stamps.len() >= MAX_STAMPS {
        state.incomplete = Some("caduceus-load-context-stamp-limit".to_owned());
        return;
    }
    stamps.push(stamp);
    if serde_json::to_vec(&candidate).map_or(true, |bytes| bytes.len() > MAX_CONTEXT_BYTES) {
        state.incomplete = Some("caduceus-load-context-byte-limit".to_owned());
        return;
    }
    state.raw = Some(candidate);
}

pub fn attach_to_envelope(
    envelope: &mut Value,
    context: &ContextHandle,
    parent_span_id: Option<&str>,
) {
    let Some(snapshot) = context_snapshot(context) else {
        return;
    };
    let Some(envelope) = envelope.as_object_mut() else {
        mark_incomplete(context, "caduceus-load-context-envelope-invalid");
        return;
    };
    let flags = envelope.entry("flags".to_owned()).or_insert_with(|| json!({}));
    let Some(flags) = flags.as_object_mut() else {
        mark_incomplete(context, "caduceus-load-context-flags-not-object");
        return;
    };
    let mut child_context = snapshot;
    if let (Some(parent), Some(object)) = (parent_span_id, child_context.as_object_mut()) {
        let ancestry = object
            .entry("next_hop_ancestry".to_owned())
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Some(ancestry) = ancestry.as_array_mut() {
            let link = json!({
                "namespace": "caduceus.load_trace.v1",
                "parent_span_id": parent
            });
            if !ancestry.contains(&link) {
                ancestry.push(link);
            }
        }
    }
    if serde_json::to_vec(&child_context).map_or(true, |bytes| bytes.len() > MAX_CONTEXT_BYTES) {
        mark_incomplete(context, "caduceus-load-context-byte-limit");
        return;
    }
    if let Some(existing) = flags.get_mut("load_context") {
        let expected = context_schema();
        let same_request = expected.as_deref().is_some_and(|expected| {
            valid_context(existing, expected)
                && existing.get("correlation_id") == child_context.get("correlation_id")
        });
        if same_request {
            let mut merged = existing.clone();
            merge_context_values(&mut merged, &child_context);
            if serde_json::to_vec(&merged).map_or(true, |bytes| bytes.len() > MAX_CONTEXT_BYTES) {
                mark_incomplete(context, "caduceus-load-context-byte-limit");
                return;
            }
            *existing = merged;
        } else {
            mark_incomplete(context, "caduceus-load-context-existing-context-mismatch");
            return;
        }
    } else {
        flags.insert("load_context".to_owned(), child_context);
    }
    if detailed_requested(context, false) && !flags.contains_key("benchmark") {
        flags.insert("benchmark".to_owned(), Value::Bool(true));
    }
}

fn merge_context_values(target: &mut Value, returned: &Value) {
    let (Some(target), Some(returned)) = (target.as_object_mut(), returned.as_object()) else {
        return;
    };
    for (key, value) in returned {
        if key == "parent_span_id" {
            if !target.contains_key(key) {
                target.insert(key.clone(), value.clone());
            }
            continue;
        }
        if key == "next_hop_ancestry" {
            if !target.contains_key(key) {
                target.insert(key.clone(), value.clone());
            } else if let (Some(target_links), Some(returned_links)) = (
                target.get_mut(key).and_then(Value::as_array_mut),
                value.as_array(),
            ) {
                for link in returned_links {
                    if !target_links.contains(link) {
                        target_links.push(link.clone());
                    }
                }
            }
            continue;
        }
        if key == "stamps" {
            let (Some(target_stamps), Some(returned_stamps)) = (
                target.get_mut("stamps").and_then(Value::as_array_mut),
                value.as_array(),
            ) else {
                continue;
            };
            if returned_stamps.len() >= target_stamps.len()
                && returned_stamps[..target_stamps.len()] == target_stamps[..]
            {
                for stamp in &returned_stamps[target_stamps.len()..] {
                    target_stamps.push(stamp.clone());
                }
            }
        } else if !target.contains_key(key) {
            target.insert(key.clone(), value.clone());
        }
    }
}

pub fn merge_returned_context(context: &ContextHandle, returned: &Value) -> usize {
    let Some(expected) = context_schema() else {
        mark_incomplete(context, "caduceus-load-context-seat-unavailable");
        return 0;
    };
    if !valid_context(returned, &expected) {
        return 0;
    }
    let returned_id = returned.get("correlation_id").and_then(Value::as_str);
    let Ok(mut state) = context.lock() else {
        return 0;
    };
    if state.correlation_id.as_deref() != returned_id {
        state.incomplete.get_or_insert_with(|| "caduceus-load-context-correlation-mismatch".to_owned());
        return 0;
    }
    let before = state
        .raw
        .as_ref()
        .and_then(|value| value.get("stamps"))
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let Some(mut candidate) = state.raw.clone() else {
        return 0;
    };
    merge_context_values(&mut candidate, returned);
    if serde_json::to_vec(&candidate).map_or(true, |bytes| bytes.len() > MAX_CONTEXT_BYTES) {
        state
            .incomplete
            .get_or_insert_with(|| "caduceus-load-context-byte-limit".to_owned());
        return 0;
    }
    let after = candidate
        .get("stamps")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    state.raw = Some(candidate);
    after.saturating_sub(before)
}

pub fn merge_returned_context_from_envelope(context: &ContextHandle, envelope: &Value) -> usize {
    envelope
        .pointer("/flags/load_context")
        .map_or(0, |returned| merge_returned_context(context, returned))
}

fn response_context_for_state(state: &TraceState) -> Option<Value> {
    if let Some(signal) = &state.unavailable {
        let mut diagnostic = Map::new();
        diagnostic.insert(
            "trace_unavailable".to_owned(),
            json!({"signal": signal}),
        );
        if let Some(raw) = &state.raw_source {
            diagnostic.insert("raw_context".to_owned(), raw.clone());
        }
        if let Some(correlation_id) = &state.correlation_id {
            diagnostic.insert("correlation_id".to_owned(), Value::String(correlation_id.clone()));
        }
        return Some(Value::Object(diagnostic));
    }
    let mut value = state.raw.clone()?;
    if let (Some(signal), Some(object)) = (state.incomplete.as_ref(), value.as_object_mut()) {
        object
            .entry("trace_incomplete".to_owned())
            .or_insert_with(|| Value::String(signal.clone()));
    }
    Some(value)
}

pub fn response_context() -> Option<Value> {
    current().and_then(|context| {
        context
            .lock()
            .ok()
            .and_then(|state| response_context_for_state(&state))
    })
}

pub fn enrich_json(value: &mut Value) {
    let Some(context) = response_context() else {
        return;
    };
    let Some(object) = value.as_object_mut() else {
        let result = std::mem::take(value);
        *value = json!({"result": result, "load_context": context});
        return;
    };
    if !object.contains_key("load_context") {
        object.insert("load_context".to_owned(), context);
    } else {
        let expected = context_schema();
        let same_request = object.get("load_context").is_some_and(|existing| {
            expected.as_deref().is_some_and(|expected| {
                valid_context(existing, expected)
                    && existing.get("correlation_id") == context.get("correlation_id")
            })
        });
        if same_request {
            if let Some(existing) = object.get_mut("load_context") {
                merge_context_values(existing, &context);
            }
        } else {
            object
                .entry("caduceus_load_context".to_owned())
                .or_insert(context);
        }
    }
}

pub fn enrich_json_text(body: String) -> String {
    if current().is_none() {
        return body;
    }
    let Ok(mut value) = serde_json::from_str::<Value>(&body) else {
        return body;
    };
    enrich_json(&mut value);
    serde_json::to_string(&value).unwrap_or(body)
}

pub fn record_native_completion(
    context: &ContextHandle,
    command: &str,
    invocation: Invocation,
    ok: bool,
) {
    let Some((operation, source_state, cache_state)) = native_operation(command) else {
        return;
    };
    finish_invocation(
        context,
        invocation,
        operation,
        "native",
        source_state,
        cache_state,
        if ok { "ok" } else { "failed" },
        None,
        false,
    );
}

fn native_operation(command: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match command {
        "appliance stats read" => Some((
            "caduceus.appliance.stats.current",
            "shared-sample",
            "hit",
        )),
        "appliance stats history" => Some((
            "caduceus.appliance.stats.history",
            "sqlite-history",
            "not-applicable",
        )),
        "network notes" => Some((
            "caduceus.network.device.annotate.read",
            "local-state-file",
            "not-applicable",
        )),
        "network dhcp leases" => Some((
            "caduceus.network.dhcp.leases",
            "native-kea-lease-files",
            "not-applicable",
        )),
        "network dhcp reservations list" => Some((
            "caduceus.network.dhcp.reservations",
            "native-kea-configuration",
            "not-applicable",
        )),
        "hyalos tail" => Some((
            "caduceus.hyalos.channel.tail",
            "local-channel-file",
            "not-applicable",
        )),
        "network device list" => Some((
            "caduceus.network.device.list",
            "configured-read-command",
            "not-applicable",
        )),
        "network dhcp status" => Some((
            "caduceus.network.dhcp.status",
            "configured-read-command",
            "not-applicable",
        )),
        "source currency" => Some((
            "caduceus.coronatio.source_currency",
            "source-currency-query",
            "not-applicable",
        )),
        _ => None,
    }
}

pub fn outcome_for_result<T, E>(result: &Result<T, E>) -> bool {
    result.is_ok()
}

pub struct ApiErrorBodyFields<'a> {
    pub schema: &'a str,
    pub ok: bool,
    pub command: &'a str,
    pub first_missing_signal: &'a str,
}

pub fn serialize_api_error<S>(
    fields: ApiErrorBodyFields<'_>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let context = response_context();
    let mut state = serializer.serialize_struct(
        "ApiErrorBody",
        if context.is_some() { 5 } else { 4 },
    )?;
    state.serialize_field("schema", fields.schema)?;
    state.serialize_field("ok", &fields.ok)?;
    state.serialize_field("command", fields.command)?;
    state.serialize_field("firstMissingSignal", fields.first_missing_signal)?;
    if let Some(context) = context {
        state.serialize_field("load_context", &context)?;
    }
    state.end()
}

pub fn load_context_from_envelope(envelope: &Value) -> Option<Value> {
    envelope.pointer("/flags/load_context").cloned()
}

pub fn preserve_context_on_result(context: &ContextHandle, result: &Result<Value, String>) {
    if let Ok(value) = result {
        if let Some(envelope) = value.get("envelope") {
            merge_returned_context_from_envelope(context, envelope);
        }
    }
}
