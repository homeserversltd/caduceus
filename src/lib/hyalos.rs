use crate::shared::config;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{Mutex, OnceLock};

pub const EVENT_SCHEMA: &str = crate::protocol::hyalos_event_schema();
pub const CHANNEL_PATH: &str = "/var/log/appliance/appliance.log";

const LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error", "fatal"];
const MAX_LINE_BYTES: usize = 1024;
const MAX_PROJECTED_FAILURES: usize = 32;

fn metadata_text(value: Option<&Value>, limit: usize) -> Option<String> {
    let value = value?.as_str()?;
    let text: String = value
        .chars()
        .filter(|character| {
            character.is_ascii_alphanumeric() || "_-. :/".contains(*character)
        })
        .take(limit)
        .collect();
    (!text.is_empty()).then_some(text)
}

fn metadata_alias(value: &Value, names: &[&str], limit: usize) -> Option<String> {
    names
        .iter()
        .find_map(|name| metadata_text(value.get(*name), limit))
}

fn safe_id(value: Option<String>) -> Option<String> {
    value.filter(|text| {
        text.len() <= 64
            && !text.is_empty()
            && text.chars().all(|character| {
                character.is_ascii_alphanumeric() || "_-. :/".contains(character)
            })
    })
}

fn bounded_label(value: &str, limit: usize, fallback: &str) -> String {
    metadata_text(Some(&Value::String(value.to_string())), limit)
        .unwrap_or_else(|| fallback.to_string())
}

fn is_run_profile_kind(kind: &str) -> bool {
    let kind = kind.strip_prefix("schema=").unwrap_or(kind);
    matches!(kind, "harmonia.run_profile" | "schemaharmonia.run_profile")
        || ["harmonia.run_profile.v", "schemaharmonia.run_profile.v"]
            .iter()
            .any(|prefix| {
                kind.strip_prefix(prefix).is_some_and(|version| {
                    !version.is_empty() && version.bytes().all(|byte| byte.is_ascii_digit())
                })
            })
}

fn project_failures(source: &Value) -> (Vec<Value>, usize) {
    let mut failures = Vec::new();
    let mut omitted = 0;
    for failure in source
        .get("failures")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(module) = metadata_text(failure.get("module"), 48) else {
            continue;
        };
        let Some(signal) = metadata_text(failure.get("signal"), 40) else {
            continue;
        };
        if failures.len() < MAX_PROJECTED_FAILURES {
            failures.push(json!({"module": module, "signal": signal}));
        } else {
            omitted += 1;
        }
    }
    (failures, omitted)
}

fn project_attributes(event: &ChannelEvent, run_profile: bool) -> Result<Value, String> {
    let source = &event.attributes_redacted;
    let mut attributes = json!({
        "who": metadata_alias(source, &["who"], 24)
            .unwrap_or_else(|| bounded_label(&event.organ, 24, "caduceus")),
        "verb": metadata_alias(source, &["verb"], 32)
            .unwrap_or_else(|| bounded_label(&event.kind, 32, "deed")),
        "target": metadata_alias(source, &["target", "route", "noun", "check"], 48),
        "outcome": metadata_alias(source, &["outcome"], 16)
            .unwrap_or_else(|| if event.ok { "success".into() } else { "failure".into() }),
        "duration_ms": source.get("duration_ms")
            .or_else(|| source.get("durationMs"))
            .and_then(Value::as_u64),
        "signal": metadata_alias(source, &["signal", "firstMissingSignal", "first_missing_signal"], 40),
        "first_missing_field": metadata_alias(source, &["first_missing_field", "firstMissingField", "field"], 32),
    });
    if run_profile {
        let run_id = metadata_alias(source, &["run_id", "correlation_id"], 64)
            .or_else(|| event.correlation_id.clone())
            .ok_or_else(|| "hyalos-run-profile-run-id-missing".to_string())?;
        let outcome = metadata_alias(source, &["outcome"], 16)
            .filter(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "ok" | "success" | "failed" | "failure"
                )
            })
            .unwrap_or_else(|| if event.ok { "success".into() } else { "failure".into() });
        attributes["outcome"] = json!(outcome);
        attributes["run_id"] = json!(run_id);
        attributes["profile"] = json!(metadata_alias(source, &["profile"], 32));
        attributes["finished_at"] = json!(metadata_alias(source, &["finished_at"], 40));
        attributes["module_count"] = json!(source.get("module_count").and_then(Value::as_u64));
        attributes["updated_count"] = json!(source.get("updated_count").and_then(Value::as_u64));
        let (failures, failures_more) = project_failures(source);
        attributes["failures"] = json!(failures);
        if failures_more > 0 {
            attributes["failures_more"] = json!(failures_more);
        }
    }
    Ok(attributes)
}

fn project_event(mut event: ChannelEvent) -> Result<ChannelEvent, String> {
    let run_profile = is_run_profile_kind(&event.kind);
    event.timestamp = if event.timestamp.len() <= 40
        && event.timestamp.chars().all(|character| {
            character.is_ascii_alphanumeric() || ":+-.".contains(character)
        })
    {
        event.timestamp
    } else {
        now_timestamp()
    };
    event.body_id = bounded_label(&event.body_id, 24, "unknown-body");
    event.level = normalize_level(Some(event.level))?;
    event.organ = bounded_label(&event.organ, 24, "caduceus");
    event.kind = bounded_label(&event.kind, 32, "deed");
    event.world = if matches!(event.world.as_str(), "appliance" | "monad") {
        event.world
    } else {
        "appliance".into()
    };
    event.message = "deed recorded".into();
    event.correlation_id = safe_id(event.correlation_id);
    event.session_id = safe_id(event.session_id);
    event.work_id = safe_id(event.work_id);
    event.review_id = safe_id(event.review_id);
    event.strike_id = safe_id(event.strike_id);
    event.attributes_redacted = project_attributes(&event, run_profile)?;
    Ok(event)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEvent {
    pub schema: String,
    pub timestamp: String,
    pub body_id: String,
    pub level: String,
    pub organ: String,
    pub kind: String,
    pub world: String,
    pub ok: bool,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub work_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strike_id: Option<String>,
    pub attributes_redacted: Value,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TailFilters {
    #[serde(default = "default_tail_count")]
    pub count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organ: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub world: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
}

fn default_tail_count() -> usize {
    20
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Reflection {
    #[serde(default)]
    pub timestamp: Option<String>,
    #[serde(default)]
    pub stamp: Option<String>,
    #[serde(default, alias = "bodyId")]
    pub body_id: Option<String>,
    #[serde(default)]
    pub level: Option<String>,
    #[serde(default)]
    pub world: Option<String>,
    pub organ: String,
    pub kind: String,
    #[serde(default, alias = "correlationId")]
    pub correlation_id: Option<String>,
    #[serde(default, alias = "sessionId")]
    pub session_id: Option<String>,
    #[serde(default, alias = "workId")]
    pub work_id: Option<String>,
    #[serde(default, alias = "reviewId")]
    pub review_id: Option<String>,
    #[serde(default, alias = "strikeId")]
    pub strike_id: Option<String>,
    #[serde(default = "default_ok")]
    pub ok: bool,
    pub message: String,
    #[serde(
        default,
        alias = "attributesRedacted",
        alias = "payloadRedacted",
        alias = "payload_redacted",
        alias = "payload"
    )]
    pub attributes_redacted: Value,
}

fn default_ok() -> bool {
    true
}

fn redact(value: Value) -> Value {
    match value {
        Value::Object(values) => Value::Object(
            values
                .into_iter()
                .map(|(key, value)| {
                    let lowered = key.to_ascii_lowercase();
                    let value = if [
                        "password",
                        "passwd",
                        "token",
                        "secret",
                        "capability",
                        "private_key",
                        "privatekey",
                    ]
                    .iter()
                    .any(|needle| lowered.contains(needle))
                    {
                        Value::String("[REDACTED]".to_string())
                    } else {
                        redact(value)
                    };
                    (key, value)
                })
                .collect::<Map<_, _>>(),
        ),
        Value::Array(values) => Value::Array(values.into_iter().map(redact).collect()),
        other => other,
    }
}

fn now_timestamp() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn stamp_to_timestamp(stamp: &str) -> Result<String, String> {
    let millis = stamp
        .parse::<i64>()
        .map_err(|err| format!("hyalos-stamp-invalid: {err}"))?;
    let seconds = millis / 1000;
    let nanos = ((millis % 1000) * 1_000_000) as u32;
    Utc.timestamp_opt(seconds, nanos)
        .single()
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .ok_or_else(|| "hyalos-stamp-invalid".to_string())
}

fn resolve_timestamp(timestamp: Option<String>, stamp: Option<String>) -> Result<String, String> {
    if let Some(timestamp) = timestamp {
        return Ok(timestamp);
    }
    if let Some(stamp) = stamp {
        return stamp_to_timestamp(&stamp);
    }
    Ok(now_timestamp())
}

fn normalize_level(level: Option<String>) -> Result<String, String> {
    let level = level.unwrap_or_else(|| "info".to_string());
    let lowered = level.to_ascii_lowercase();
    if LEVELS.contains(&lowered.as_str()) {
        Ok(lowered)
    } else {
        Err(format!("hyalos-level-invalid: {level}"))
    }
}

fn profile_defaults() -> (String, String) {
    let profile = config::read_public_profile_value().unwrap_or_else(|_| json!({}));
    let body_id = profile
        .get("body_id")
        .or_else(|| profile.get("bodyId"))
        .or_else(|| profile.get("profile"))
        .and_then(Value::as_str)
        .unwrap_or("unknown-body")
        .to_string();
    let world = profile
        .get("world")
        .and_then(Value::as_str)
        .unwrap_or(
            if profile.get("profile").and_then(Value::as_str) == Some("homeserver") {
                "monad"
            } else {
                "appliance"
            },
        )
        .to_string();
    (body_id, world)
}

fn reflection_event(input: Reflection) -> Result<ChannelEvent, String> {
    if input.organ.trim().is_empty()
        || input.kind.trim().is_empty()
        || input.message.trim().is_empty()
    {
        return Err("hyalos-reflection-required-field-missing".to_string());
    }
    let (default_body_id, default_world) = profile_defaults();
    let event = ChannelEvent {
        schema: EVENT_SCHEMA.to_string(),
        timestamp: resolve_timestamp(input.timestamp, input.stamp)?,
        body_id: input.body_id.unwrap_or(default_body_id),
        level: normalize_level(input.level)?,
        world: input.world.unwrap_or(default_world),
        organ: input.organ,
        kind: input.kind,
        correlation_id: input.correlation_id,
        session_id: input.session_id,
        work_id: input.work_id,
        review_id: input.review_id,
        strike_id: input.strike_id,
        ok: input.ok,
        message: input.message,
        attributes_redacted: redact(input.attributes_redacted),
    };
    Ok(event)
}

pub fn reflect(input: Reflection) -> Result<ChannelEvent, String> {
    let event = reflection_event(input)?;
    append(&event)?;
    Ok(event)
}

pub fn reflect_json(input: Value) -> Result<Value, String> {
    let reflection: Reflection =
        serde_json::from_value(input).map_err(|err| format!("hyalos-reflection-invalid: {err}"))?;
    let event = reflect(reflection)?;
    Ok(json!({
        "schema": "caduceus.hyalos.reflect.v1",
        "ok": true,
        "channelPath": config::path(CHANNEL_PATH),
        "event": event,
        "firstMissingSignal": "none"
    }))
}

pub fn project_json(input: Value) -> Result<Value, String> {
    let reflection: Reflection =
        serde_json::from_value(input).map_err(|err| format!("hyalos-reflection-invalid: {err}"))?;
    let event = reflection_event(reflection)?;
    Ok(json!({
        "schema": "caduceus.hyalos.reflect.v1",
        "ok": true,
        "channelPath": config::path(CHANNEL_PATH),
        "event": event,
        "firstMissingSignal": "none"
    }))
}

pub fn append_json(input: Value) -> Result<Value, String> {
    if input.get("schema").and_then(Value::as_str) != Some(EVENT_SCHEMA) {
        return Err("hyalos-channel-event-schema-invalid".to_string());
    }
    let mut event: ChannelEvent = serde_json::from_value(input)
        .map_err(|err| format!("hyalos-channel-event-invalid: {err}"))?;
    if event.organ.trim().is_empty()
        || event.kind.trim().is_empty()
        || event.message.trim().is_empty()
    {
        return Err("hyalos-channel-event-required-field-missing".to_string());
    }
    event.level = normalize_level(Some(event.level))?;
    event.attributes_redacted = redact(event.attributes_redacted);
    append(&event)?;
    Ok(json!({
        "schema": "caduceus.hyalos.append.v1",
        "ok": true,
        "channelPath": config::path(CHANNEL_PATH),
        "event": event,
        "firstMissingSignal": "none"
    }))
}

fn serialize_line(event: &ChannelEvent) -> Result<Vec<u8>, String> {
    let mut line = serde_json::to_vec(event)
        .map_err(|_| "hyalos-channel-serialize-failed".to_string())?;
    line.push(b'\n');
    Ok(line)
}

fn projected_failures(event: &ChannelEvent) -> Vec<Value> {
    event
        .attributes_redacted
        .get("failures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn projected_failures_more(event: &ChannelEvent) -> usize {
    event
        .attributes_redacted
        .get("failures_more")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .unwrap_or_default()
}

fn set_projected_failures(event: &mut ChannelEvent, failures: &[Value], omitted: usize) {
    if let Some(attributes) = event.attributes_redacted.as_object_mut() {
        attributes.insert("failures".to_string(), Value::Array(failures.to_vec()));
        if omitted == 0 {
            attributes.remove("failures_more");
        } else {
            attributes.insert("failures_more".to_string(), json!(omitted));
        }
    }
}

fn compact_duplicate_id(slot: &mut Option<String>, seen: &mut Vec<String>) {
    if let Some(value) = slot.clone() {
        if seen.contains(&value) {
            *slot = None;
        } else {
            seen.push(value);
        }
    }
}

fn compact_duplicate_run_ids(event: &mut ChannelEvent) {
    let mut seen = event
        .attributes_redacted
        .get("run_id")
        .and_then(Value::as_str)
        .map(|value| vec![value.to_string()])
        .unwrap_or_default();
    compact_duplicate_id(&mut event.correlation_id, &mut seen);
    compact_duplicate_id(&mut event.session_id, &mut seen);
    compact_duplicate_id(&mut event.work_id, &mut seen);
    compact_duplicate_id(&mut event.review_id, &mut seen);
    compact_duplicate_id(&mut event.strike_id, &mut seen);
}

fn append(event: &ChannelEvent) -> Result<(), String> {
    static APPEND_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _guard = APPEND_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .map_err(|_| "hyalos-channel-lock-poisoned".to_string())?;
    let path = config::path(CHANNEL_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    let run_profile = is_run_profile_kind(&event.kind);
    let disk_event = project_event(event.clone())?;
    let mut disk_event = disk_event;
    let mut line = serialize_line(&disk_event)?;
    if line.len() >= MAX_LINE_BYTES {
        if !run_profile {
            return Err("hyalos-channel-event-too-large".to_string());
        }
        compact_duplicate_run_ids(&mut disk_event);
        let mut failures = projected_failures(&disk_event);
        let mut omitted = projected_failures_more(&disk_event);
        loop {
            line = serialize_line(&disk_event)?;
            if line.len() < MAX_LINE_BYTES {
                break;
            }
            if failures.pop().is_none() {
                return Err("hyalos-channel-event-too-large".to_string());
            }
            omitted += 1;
            set_projected_failures(&mut disk_event, &failures, omitted);
        }
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    file.write_all(&line)
        .map_err(|err| format!("{}: {err}", path.display()))
}

fn parse_channel_line(line: &str) -> Result<Value, String> {
    let event: Value =
        serde_json::from_str(line).map_err(|err| format!("hyalos-channel-line-invalid: {err}"))?;
    let schema = event.get("schema").and_then(Value::as_str);
    if schema != Some(EVENT_SCHEMA) {
        return Err("hyalos-channel-event-schema-invalid".to_string());
    }
    Ok(event)
}

fn event_field_str<'a>(event: &'a Value, field: &str) -> Option<&'a str> {
    event.get(field).and_then(Value::as_str)
}

fn matches_filters(event: &Value, filters: &TailFilters) -> bool {
    if let Some(kind) = filters.kind.as_deref() {
        if event_field_str(event, "kind") != Some(kind) {
            return false;
        }
    }
    if let Some(organ) = filters.organ.as_deref() {
        if event_field_str(event, "organ") != Some(organ) {
            return false;
        }
    }
    if let Some(world) = filters.world.as_deref() {
        if event_field_str(event, "world") != Some(world) {
            return false;
        }
    }
    if let Some(correlation_id) = filters.correlation_id.as_deref() {
        if event_field_str(event, "correlation_id") != Some(correlation_id) {
            return false;
        }
    }
    if let Some(level) = filters.level.as_deref() {
        if event_field_str(event, "level") != Some(level) {
            return false;
        }
    }
    if let Some(ok) = filters.ok {
        if event.get("ok").and_then(Value::as_bool) != Some(ok) {
            return false;
        }
    }
    true
}

const TAIL_BLOCK_BYTES: usize = 16 * 1024;
const TAIL_SCAN_MAX_BYTES: u64 = 4 * 1024 * 1024;
const TAIL_SCAN_MAX_LINES: usize = 65_536;
const TAIL_RESULT_MAX_BYTES: usize = 1024 * 1024;

struct TailCollector<'a> {
    filters: &'a TailFilters,
    keep: usize,
    events_newest_first: VecDeque<Value>,
    result_bytes: usize,
    invalid_lines_skipped: usize,
    oversized_lines_skipped: usize,
    torn_trailing_rows_skipped: usize,
    blank_lines_skipped: usize,
    filtered_lines: usize,
    has_more: Option<bool>,
    output_limit_reached: bool,
    count_limit_reached: bool,
}

impl TailCollector<'_> {
    fn process_line(&mut self, reversed_line: &mut Vec<u8>, oversized: bool, torn: bool) -> bool {
        if torn {
            self.torn_trailing_rows_skipped += 1;
            return false;
        }
        if oversized {
            self.oversized_lines_skipped += 1;
            return false;
        }
        if reversed_line.is_empty() {
            self.blank_lines_skipped += 1;
            return false;
        }
        reversed_line.reverse();
        let Ok(line) = std::str::from_utf8(reversed_line) else {
            self.invalid_lines_skipped += 1;
            return false;
        };
        let Ok(event) = parse_channel_line(line) else {
            self.invalid_lines_skipped += 1;
            return false;
        };
        if !matches_filters(&event, self.filters) {
            self.filtered_lines += 1;
            return false;
        }
        if self.events_newest_first.len() >= self.keep {
            self.has_more = Some(true);
            self.count_limit_reached = true;
            return true;
        }
        let event_bytes = serde_json::to_vec(&event).map_or(usize::MAX, |bytes| bytes.len() + 1);
        if self.result_bytes.saturating_add(event_bytes) > TAIL_RESULT_MAX_BYTES {
            self.has_more = Some(true);
            self.output_limit_reached = true;
            return true;
        }
        self.result_bytes += event_bytes;
        self.events_newest_first.push_back(event);
        false
    }
}

pub fn tail_json(filters: TailFilters) -> Result<Value, String> {
    let context = crate::shared::load_trace::current();
    let invocation = context
        .as_ref()
        .map(crate::shared::load_trace::begin_invocation);
    let result = tail_json_inner(filters);
    if let (Some(context), Some(invocation)) = (context, invocation) {
        crate::shared::load_trace::record_native_completion(
            &context,
            "hyalos tail",
            invocation,
            result.is_ok(),
        );
    }
    let mut result = result;
    if let Ok(value) = result.as_mut() {
        crate::shared::load_trace::enrich_json(value);
    }
    result
}

fn tail_json_inner(filters: TailFilters) -> Result<Value, String> {
    let path = config::path(CHANNEL_PATH);
    let mut file = File::open(&path).map_err(|error| {
        format!("hyalos-channel-open-failed:{:?}", error.kind())
    })?;
    let file_bytes = file
        .seek(SeekFrom::End(0))
        .map_err(|error| format!("hyalos-channel-seek-failed:{:?}", error.kind()))?;
    let scan_bytes = file_bytes.min(TAIL_SCAN_MAX_BYTES);
    let scan_start = file_bytes - scan_bytes;
    let keep = filters.count.clamp(1, 1000);
    let mut collector = TailCollector {
        filters: &filters,
        keep,
        events_newest_first: VecDeque::new(),
        result_bytes: 0,
        invalid_lines_skipped: 0,
        oversized_lines_skipped: 0,
        torn_trailing_rows_skipped: 0,
        blank_lines_skipped: 0,
        filtered_lines: 0,
        has_more: None,
        output_limit_reached: false,
        count_limit_reached: false,
    };
    let mut buffer = vec![0u8; TAIL_BLOCK_BYTES];
    let mut reversed_line = Vec::with_capacity(MAX_LINE_BYTES);
    let mut oversized = false;
    let mut trailing_torn_pending = false;
    let mut first_byte = true;
    let mut cursor = file_bytes;
    let mut bytes_scanned = 0u64;
    let mut lines_scanned = 0usize;
    let mut blocks_read = 0usize;
    let mut line_limit_reached = false;
    let mut stopped_for_more = false;

    while cursor > scan_start {
        let chunk_start = cursor.saturating_sub(TAIL_BLOCK_BYTES as u64).max(scan_start);
        let chunk_len = usize::try_from(cursor - chunk_start)
            .map_err(|_| "hyalos-channel-read-length-invalid".to_string())?;
        file.seek(SeekFrom::Start(chunk_start))
            .map_err(|error| format!("hyalos-channel-seek-failed:{:?}", error.kind()))?;
        file.read_exact(&mut buffer[..chunk_len])
            .map_err(|error| format!("hyalos-channel-read-failed:{:?}", error.kind()))?;
        bytes_scanned = bytes_scanned.saturating_add(chunk_len as u64);
        blocks_read += 1;
        let mut stop_at = None;
        for (index, byte) in buffer[..chunk_len].iter().enumerate().rev() {
            let absolute = chunk_start + index as u64;
            if first_byte {
                trailing_torn_pending = *byte != b'\n';
                first_byte = false;
                if !trailing_torn_pending {
                    continue;
                }
            }
            if *byte == b'\n' {
                lines_scanned += 1;
                let torn = trailing_torn_pending;
                trailing_torn_pending = false;
                if collector.process_line(&mut reversed_line, oversized, torn) {
                    stopped_for_more = true;
                    stop_at = Some(absolute);
                    break;
                }
                reversed_line.clear();
                oversized = false;
                if lines_scanned >= TAIL_SCAN_MAX_LINES {
                    line_limit_reached = absolute > 0;
                    stop_at = Some(absolute);
                    break;
                }
            } else if !oversized {
                if reversed_line.len() + 2 > MAX_LINE_BYTES.saturating_sub(1) {
                    oversized = true;
                    reversed_line.clear();
                } else {
                    reversed_line.push(*byte);
                }
            }
        }
        if let Some(position) = stop_at {
            cursor = position;
            break;
        }
        cursor = chunk_start;
    }

    let reached_file_start = cursor == 0 && !stopped_for_more && !line_limit_reached;
    let mut truncated_prefix_line_skipped = false;
    if !stopped_for_more && !line_limit_reached {
        if trailing_torn_pending {
            collector.torn_trailing_rows_skipped += 1;
            reversed_line.clear();
            oversized = false;
            trailing_torn_pending = false;
        }
        if reached_file_start {
            if !reversed_line.is_empty() || oversized {
                lines_scanned += 1;
                let _ = collector.process_line(&mut reversed_line, oversized, false);
            }
        } else if !reversed_line.is_empty() || oversized {
            truncated_prefix_line_skipped = true;
            if oversized {
                collector.oversized_lines_skipped += 1;
            }
        }
    }

    let scan_limit_reached = scan_start > 0 && cursor == scan_start && !stopped_for_more && !line_limit_reached;
    let truncated = scan_limit_reached
        || line_limit_reached
        || collector.output_limit_reached
        || collector.count_limit_reached
        || collector.torn_trailing_rows_skipped > 0
        || truncated_prefix_line_skipped;
    let has_more = if collector.has_more == Some(true) {
        Value::Bool(true)
    } else if scan_limit_reached || line_limit_reached {
        Value::Null
    } else {
        Value::Bool(false)
    };
    let events = collector
        .events_newest_first
        .into_iter()
        .rev()
        .collect::<Vec<_>>();
    let count = events.len();
    let first_missing_signal = if file_bytes == 0 {
        "hyalos-channel-empty"
    } else {
        "none"
    };
    Ok(json!({
        "schema": "caduceus.hyalos.tail.v1",
        "ok": true,
        "channelPath": path,
        "count": count,
        "filters": filters,
        "events": events,
        "has_more": has_more,
        "scan": {
            "bytes_available": file_bytes,
            "bytes_scanned": bytes_scanned,
            "scan_start": scan_start,
            "scan_end": file_bytes,
            "lines_scanned": lines_scanned,
            "blocks_read": blocks_read,
            "invalid_lines_skipped": collector.invalid_lines_skipped,
            "oversized_lines_skipped": collector.oversized_lines_skipped,
            "torn_trailing_rows_skipped": collector.torn_trailing_rows_skipped,
            "blank_lines_skipped": collector.blank_lines_skipped,
            "filtered_lines": collector.filtered_lines,
            "result_bytes": collector.result_bytes,
            "result_limit_bytes": TAIL_RESULT_MAX_BYTES,
            "line_limit": TAIL_SCAN_MAX_LINES,
            "line_bytes_limit_including_lf": MAX_LINE_BYTES - 1,
            "scan_limit_bytes": TAIL_SCAN_MAX_BYTES,
            "scan_limit_reached": scan_limit_reached,
            "line_limit_reached": line_limit_reached,
            "output_limit_reached": collector.output_limit_reached,
            "count_limit_reached": collector.count_limit_reached,
            "truncated_prefix_line_skipped": truncated_prefix_line_skipped,
            "truncated": truncated
        },
        "firstMissingSignal": first_missing_signal
    }))
}


