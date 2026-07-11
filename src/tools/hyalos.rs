use crate::tools::config;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;

pub const EVENT_SCHEMA: &str = "hyalos.channel.event.v2";
pub const EVENT_SCHEMA_V1: &str = "hyalos.channel.event.v1";
const CHANNEL_PATH: &str = "var/log/hyalos/channel.jsonl";

const LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error", "fatal"];

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

pub fn reflect(input: Reflection) -> Result<ChannelEvent, String> {
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

fn append(event: &ChannelEvent) -> Result<(), String> {
    let path = config::path(CHANNEL_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    serde_json::to_writer(&mut file, event)
        .map_err(|err| format!("hyalos-channel-serialize-failed: {err}"))?;
    file.write_all(b"\n")
        .map_err(|err| format!("{}: {err}", path.display()))
}

fn parse_channel_line(line: &str) -> Result<Value, String> {
    let event: Value =
        serde_json::from_str(line).map_err(|err| format!("hyalos-channel-line-invalid: {err}"))?;
    let schema = event.get("schema").and_then(Value::as_str);
    if schema != Some(EVENT_SCHEMA) && schema != Some(EVENT_SCHEMA_V1) {
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

pub fn tail_json(filters: TailFilters) -> Result<Value, String> {
    let path = config::path(CHANNEL_PATH);
    let text = fs::read_to_string(&path).unwrap_or_default();
    let mut events = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(parse_channel_line)
        .filter_map(|result| result.ok())
        .filter(|event| matches_filters(event, &filters))
        .collect::<Vec<_>>();
    let keep = filters.count.clamp(1, 1000);
    if events.len() > keep {
        events.drain(..events.len() - keep);
    }
    Ok(json!({
        "schema": "caduceus.hyalos.tail.v1",
        "ok": true,
        "channelPath": path,
        "count": events.len(),
        "filters": filters,
        "events": events,
        "firstMissingSignal": if text.trim().is_empty() { "hyalos-channel-empty" } else { "none" }
    }))
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
