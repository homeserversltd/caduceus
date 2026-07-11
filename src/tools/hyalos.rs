use crate::tools::config;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub const EVENT_SCHEMA: &str = "hyalos.channel.event.v1";
const CHANNEL_PATH: &str = "var/log/hyalos/channel.jsonl";
const PROJECTIONS_PATH: &str = "var/log/hyalos/projections";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelEvent {
    pub schema: String,
    pub stamp: String,
    pub body_id: String,
    pub world: String,
    pub organ: String,
    pub kind: String,
    pub correlation_id: Option<String>,
    pub session_id: Option<String>,
    pub work_id: Option<String>,
    pub review_id: Option<String>,
    pub strike_id: Option<String>,
    pub ok: bool,
    pub message: String,
    pub payload_redacted: Value,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Reflection {
    #[serde(default)]
    pub stamp: Option<String>,
    #[serde(default, alias = "bodyId")]
    pub body_id: Option<String>,
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
    #[serde(default, alias = "payloadRedacted", alias = "payload")]
    pub payload_redacted: Value,
}

fn default_ok() -> bool {
    true
}

fn now_stamp() -> Result<String, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .map_err(|err| format!("hyalos-clock-failed: {err}"))
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
        stamp: input.stamp.map(Ok).unwrap_or_else(now_stamp)?,
        body_id: input.body_id.unwrap_or(default_body_id),
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
        payload_redacted: redact(input.payload_redacted),
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
    event.payload_redacted = redact(event.payload_redacted);
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

pub fn tail_json(count: usize) -> Result<Value, String> {
    let path = config::path(CHANNEL_PATH);
    let text = fs::read_to_string(&path).unwrap_or_default();
    let mut events = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str::<Value>(line)
                .map_err(|err| format!("hyalos-channel-line-invalid: {err}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let keep = count.clamp(1, 1000);
    if events.len() > keep {
        events.drain(..events.len() - keep);
    }
    Ok(json!({
        "schema": "caduceus.hyalos.tail.v1",
        "ok": true,
        "channelPath": path,
        "count": events.len(),
        "events": events,
        "firstMissingSignal": if text.trim().is_empty() { "hyalos-channel-empty" } else { "none" }
    }))
}

pub fn project_upload_json() -> Result<Value, String> {
    let source_path = config::path(CHANNEL_PATH);
    let source = fs::read_to_string(&source_path).unwrap_or_default();
    let mut lines = Vec::new();
    for line in source.lines().filter(|line| !line.trim().is_empty()) {
        let event: Value = serde_json::from_str(line)
            .map_err(|err| format!("hyalos-channel-line-invalid: {err}"))?;
        if is_upload_event(&event) {
            lines.push(line);
        }
    }
    let path = config::path(&format!("{PROJECTIONS_PATH}/upload.log"));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    let body = if lines.is_empty() {
        String::new()
    } else {
        format!("{}\n", lines.join("\n"))
    };
    fs::write(&path, body).map_err(|err| format!("{}: {err}", path.display()))?;
    Ok(json!({
        "schema": "caduceus.hyalos.projection.v1",
        "ok": true,
        "projection": "upload",
        "projectionPath": path,
        "eventCount": lines.len(),
        "sourcePath": config::path(CHANNEL_PATH),
        "authority": "derived-view",
        "firstMissingSignal": "none"
    }))
}

fn is_upload_event(event: &Value) -> bool {
    event.get("kind").and_then(Value::as_str) == Some("upload")
        || event.get("organ").and_then(Value::as_str) == Some("file-ingress")
        || event
            .pointer("/payload_redacted/projection")
            .and_then(Value::as_str)
            == Some("upload")
        || event
            .pointer("/payload_redacted/classification")
            .and_then(Value::as_str)
            == Some("file-ingress")
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
