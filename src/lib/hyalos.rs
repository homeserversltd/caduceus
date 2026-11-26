use crate::shared::config;
use chrono::{TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::io::Write;
use std::time::Instant;

#[path = "hyalos_store.rs"]
mod store;
pub(crate) use store::{
    body_level, prepare_existing, prune_expired, read_harmonia_runs, read_page, LogFilters, DB_PATH,
};
use store::{Disposition, OfferMode};

pub const EVENT_SCHEMA: &str = crate::protocol::hyalos_event_schema();

const LEVELS: &[&str] = &["trace", "debug", "info", "warn", "error", "fatal"];
const MAX_LINE_BYTES: usize = 1024;
const MAX_PROJECTED_FAILURES: usize = 32;
const CLEAR_DEED: &str = "hyalos-clear";

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

fn is_history_verb(verb: &str) -> bool {
    matches!(verb, "harmonia.run_profile" | "harmonia.run_profile.v1")
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
    // Fit "deleted " and the full decimal count in the seated outcome word.
    let outcome_limit = if event.organ == "caduceus" && event.kind == CLEAR_DEED {
        32
    } else {
        16
    };
    let mut attributes = json!({
        "who": metadata_alias(source, &["who"], 24)
            .unwrap_or_else(|| bounded_label(&event.organ, 24, "caduceus")),
        "verb": metadata_alias(source, &["verb"], 32)
            .unwrap_or_else(|| bounded_label(&event.kind, 32, "deed")),
        "target": metadata_alias(source, &["target", "route", "noun", "check"], 48),
        "outcome": metadata_alias(source, &["outcome"], outcome_limit)
            .unwrap_or_else(|| if event.ok { "success".into() } else { "failure".into() }),
        "duration_ms": source.get("duration_ms")
            .or_else(|| source.get("durationMs"))
            .and_then(Value::as_u64),
        "signal": metadata_alias(source, &["signal", "firstMissingSignal", "first_missing_signal"], if event.kind == "generic-http-door" { 64 } else { 40 }),
        "first_missing_field": metadata_alias(source, &["first_missing_field", "firstMissingField", "field"], 32),
    });
    if event.organ == "harmonia" {
        // History identifies the sender's profile kind by verb. A verb
        // override must neither hide a profile run nor turn a step into one.
        if is_history_verb(&event.kind) {
            attributes["verb"] = json!(event.kind);
        } else if attributes["verb"].as_str().is_some_and(is_history_verb) {
            let kind = bounded_label(&event.kind, 32, "deed");
            attributes["verb"] = json!(if is_history_verb(&kind) { "deed" } else { &kind });
        }
    }
    if event.organ == "caduceus" && event.kind == "caduceus.maintenance" {
        attributes["freed_bytes"] = json!(source.get("freed_bytes").and_then(Value::as_u64));
        attributes["rotated"] = json!(source.get("rotated").and_then(Value::as_bool));
    }
    if event.organ == "sbin"
        && matches!(
            attributes["verb"].as_str(),
            Some("backblaze-bucket-run" | "forgejo-backup-b2")
        )
    {
        for key in ["added_bytes", "total_bytes"] {
            if let Some(count) = source
                .get("counts")
                .and_then(|counts| counts.get(key))
                .and_then(Value::as_u64)
            {
                attributes[key] = json!(count);
            }
        }
    }
    if event.organ == "file-ingress" && event.kind == "upload" {
        // Budget JSON bytes as well as characters. The native upload deed
        // has no ids and leaves 512 bytes for the filename and folder text.
        fn json_width(ch: char) -> usize {
            match ch {
                '\0'..='\x1f' => 6, // At most one \uXXXX escape.
                '"' | '\\' => 2,
                _ => ch.len_utf8(),
            }
        }
        fn prefix(text: &str, max_chars: usize, mut bytes: usize) -> &str {
            for (index, (offset, ch)) in text.char_indices().enumerate() {
                let width = json_width(ch);
                if index == max_chars || width > bytes {
                    return &text[..offset];
                }
                bytes -= width;
            }
            text
        }

        let filename = source.get("filename").and_then(Value::as_str).filter(|name| {
            std::path::Path::new(name).file_name().and_then(|part| part.to_str()) == Some(*name)
        });
        if let Some(filename) = filename {
            const NAME_CHARS: usize = 160;
            const NAME_BYTES: usize = 320;
            let short = prefix(filename, NAME_CHARS, NAME_BYTES);
            let extension = std::path::Path::new(filename)
                .extension()
                .and_then(|ext| ext.to_str())
                .filter(|ext| !ext.is_empty());
            attributes["filename"] = match extension.filter(|_| short.len() < filename.len()) {
                Some(ext) => {
                    let (stem, suffix) = filename.split_at(filename.len() - ext.len() - 1);
                    let suffix_chars = suffix.chars().count();
                    let suffix_bytes = suffix.chars().map(json_width).sum::<usize>();
                    if suffix_chars < NAME_CHARS && suffix_bytes <= NAME_BYTES - 6 {
                        let stem = prefix(stem, NAME_CHARS - suffix_chars, NAME_BYTES - suffix_bytes);
                        json!(format!("{stem}{suffix}"))
                    } else {
                        json!(short)
                    }
                }
                None => json!(short),
            };
            // An upload target names the file, not an ASCII-filtered label.
            attributes["target"] = json!(prefix(filename, 48, 48));
        }
        if let Some(destination) = source.get("destination").and_then(Value::as_str) {
            attributes["destination"] = json!(prefix(destination, 192, 192));
        }
        if let Some(bytes) = source.get("bytes").and_then(Value::as_u64) {
            attributes["bytes"] = json!(bytes);
        }
    }
    if event.organ == "sbin" && event.kind == "sbin.chord" {
        if let Some(stages) = source.get("stages").and_then(Value::as_array) {
            let stages: Vec<String> = stages
                .iter()
                .filter_map(|pair| {
                    let pair = pair.as_array()?;
                    if pair.len() != 2 {
                        return None;
                    }
                    let id = pair[0].as_str()?;
                    if id.is_empty()
                        || !id.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || b"_.-".contains(&byte)
                        })
                    {
                        return None;
                    }
                    let id = metadata_text(Some(&pair[0]), 24)?;
                    let word = pair[1].as_str()?;
                    if !matches!(word, "changed" | "kept" | "refused" | "skipped" | "completed") {
                        return None;
                    }
                    Some(format!("{id}:{word}"))
                })
                .take(8)
                .collect();
            attributes["stages"] = json!(stages);
        }
    }
    if event.kind == "generic-http-door" {
        // The routine id is the target for a generic deed; do not duplicate it.
        attributes.as_object_mut().expect("object").remove("target");
        attributes["routine_id"] = json!(metadata_alias(source, &["routine_id"], 48));
        attributes["failedStage"] = json!(metadata_alias(source, &["failedStage"], 48));
        let ids = source.get("stage_ids").and_then(Value::as_array);
        let outcomes = source.get("stage_outcomes").and_then(Value::as_array);
        if let (Some(ids), Some(outcomes)) = (ids, outcomes) {
            let stages: Vec<(String, &str)> = ids.iter().zip(outcomes).filter_map(|(id, outcome)| {
                let id = metadata_text(Some(id), 48)?;
                let outcome = match outcome.as_str()? {
                    "stage-completed" => "C",
                    "stage-refused" => "R",
                    "stage-skipped" => "S",
                    _ => return None,
                };
                Some((id, outcome))
            }).collect();
            let stage_ids = stages.iter().map(|(id, _)| id.as_str()).collect::<Vec<_>>().join(",");
            let stage_outcomes = stages.iter().map(|(_, outcome)| *outcome).collect::<String>();
            attributes["stages"] = json!([stage_ids, stage_outcomes]);
        }
    }
    if event.organ == "agathodaimon"
        && event.kind == "crossing-change"
        && source.get("verb").and_then(Value::as_str) == Some("dictate")
    {
        attributes["state"] = json!(source.get("state").and_then(Value::as_str)
            .filter(|state| matches!(*state, "recording" | "transcribed")));
        if let Some(chars) = source.get("chars").and_then(Value::as_u64) {
            attributes["chars"] = json!(chars);
        }
    }
    if run_profile {
        let run_id = metadata_alias(source, &["run_id"], 64)
            .or_else(|| event.correlation_id.clone())
            .or_else(|| metadata_alias(source, &["correlation_id"], 64))
            .ok_or_else(|| "hyalos-run-profile-run-id-missing".to_string())?;
        let outcome = metadata_alias(source, &["outcome"], 16)
            .filter(|value| {
                matches!(
                    value.to_ascii_lowercase().as_str(),
                    "ok" | "success" | "failed" | "failure" | "refused"
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
    if event.timestamp.len() > 40
        || !event.timestamp.chars().all(|character| {
            character.is_ascii_alphanumeric() || ":+-. ".contains(character)
        })
    {
        // Bound the projection without inventing a time before the write.
        // An empty stamp takes the same SQLite fallback as any invalid date.
        event.timestamp.clear();
    }
    event.body_id = bounded_label(&event.body_id, 24, "unknown-body");
    event.level = normalize_level(Some(event.level))?;
    event.organ = bounded_label(&event.organ, 24, "caduceus");
    event.kind = bounded_label(&event.kind, 32, "deed");
    event.world = if matches!(event.world.as_str(), "appliance" | "monad") {
        event.world
    } else {
        "appliance".into()
    };
    // Preserve the validation bound; messages are not stored in the row.
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
    #[serde(default)]
    pub debug: Value,
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
        Err("hyalos-level-invalid".to_string())
    }
}

fn profile_defaults() -> (String, String) {
    let profile = config::carapace();
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
    reflect_and_offer(input).map(|(event, _)| event)
}

fn reflect_and_offer(input: Reflection) -> Result<(ChannelEvent, Disposition), String> {
    let mode = offer_mode(input.debug.as_bool());
    let event = reflection_event(input)?;
    let stored = record(&event, mode)?;
    Ok((event, stored))
}

pub fn reflect_json(input: Value) -> Result<Value, String> {
    let reflection: Reflection =
        serde_json::from_value(input).map_err(|_| "hyalos-reflection-invalid".to_string())?;
    let (event, stored) = reflect_and_offer(reflection)?;
    Ok(json!({
        "schema": "caduceus.hyalos.reflect.v1",
        "ok": true,
        "channelPath": config::path(DB_PATH),
        "stored": stored,
        "event": event,
        "firstMissingSignal": "none"
    }))
}

/// A lawful drop is handled, but a failed write remains visible to callers
/// that report a deed advisory. `record` owns the single stderr diagnostic.
pub(crate) fn reflect_json_with_stderr_fallback(input: Value) -> Result<bool, String> {
    let reflection: Reflection =
        serde_json::from_value(input).map_err(|err| format!("hyalos-reflection-invalid: {err}"))?;
    reflect_and_offer(reflection).map(|(_, stored)| !matches!(stored, Disposition::Failed))
}

pub fn project_json(input: Value) -> Result<Value, String> {
    let reflection: Reflection =
        serde_json::from_value(input).map_err(|err| format!("hyalos-reflection-invalid: {err}"))?;
    let event = reflection_event(reflection)?;
    Ok(json!({
        "schema": "caduceus.hyalos.reflect.v1",
        "ok": true,
        "channelPath": config::path(DB_PATH),
        "event": event,
        "firstMissingSignal": "none"
    }))
}

pub fn append_json(input: Value) -> Result<Value, String> {
    if input.get("schema").and_then(Value::as_str) != Some(EVENT_SCHEMA) {
        return Err("hyalos-channel-event-schema-invalid".to_string());
    }
    let mode = offer_mode(input.get("debug").and_then(Value::as_bool));
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
    let stored = record(&event, mode)?;
    Ok(json!({
        "schema": "caduceus.hyalos.append.v1",
        "ok": true,
        "channelPath": config::path(DB_PATH),
        "stored": stored,
        "event": event,
        "firstMissingSignal": "none"
    }))
}

fn projected_size(event: &ChannelEvent) -> Result<usize, String> {
    serde_json::to_vec(event)
        .map(|bytes| bytes.len() + 1)
        .map_err(|_| "hyalos-channel-serialize-failed".to_string())
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

fn bounded_projection(event: &ChannelEvent) -> Result<ChannelEvent, String> {
    let run_profile = is_run_profile_kind(&event.kind);
    let mut projected = project_event(event.clone())?;
    let mut size = projected_size(&projected)?;
    if size >= MAX_LINE_BYTES && projected.organ == "sbin" && projected.kind == "sbin.chord" {
        if let Some(attributes) = projected.attributes_redacted.as_object_mut() {
            attributes.remove("stages");
        }
        size = projected_size(&projected)?;
    }
    if size >= MAX_LINE_BYTES {
        if projected.kind == "generic-http-door" || !run_profile {
            return Err("hyalos-channel-event-too-large".into());
        }
        compact_duplicate_run_ids(&mut projected);
        let mut failures = projected_failures(&projected);
        let mut omitted = projected_failures_more(&projected);
        while projected_size(&projected)? >= MAX_LINE_BYTES {
            if failures.pop().is_none() {
                return Err("hyalos-channel-event-too-large".into());
            }
            omitted += 1;
            set_projected_failures(&mut projected, &failures, omitted);
        }
    }
    Ok(projected)
}

fn offer_mode(debug: Option<bool>) -> OfferMode {
    if debug == Some(true) { OfferMode::Debug } else { OfferMode::Normal }
}

fn record(event: &ChannelEvent, mode: OfferMode) -> Result<Disposition, String> {
    let projected = bounded_projection(event)?;
    Ok(match store::offer(event, &projected, mode) {
        Ok(disposition) => disposition,
        Err(error) => {
            // The error is a fixed store signal, never a body or a SQLite message.
            let _ = writeln!(std::io::stderr().lock(), "hyalos-store-write-failed: {error}");
            Disposition::Failed
        }
    })
}

pub(crate) fn record_prune(deleted: usize, freed_bytes: u64) -> Result<(), String> {
    if deleted == 0 {
        return Ok(());
    }
    let event = reflection_event(Reflection {
        organ: "caduceus".into(),
        kind: "caduceus.maintenance".into(),
        message: "maintenance".into(),
        ok: true,
        attributes_redacted: json!({
            "verb": "maintenance",
            "target": format!("hyalos/expired-rows/{deleted}"),
            "freed_bytes": freed_bytes,
        }),
        ..Reflection::default()
    })?;
    record(&event, OfferMode::Upkeep).map(|_| ())
}

pub(crate) const CLEAR_INVALID: &str = "caduceus-hyalos-clear-request-invalid";
pub(crate) const LEVEL_INVALID: &str = "caduceus-hyalos-level-invalid";
pub(crate) type DoorResult = Result<Value, &'static str>; // Err means a malformed request.

pub(crate) fn door_error(signal: &str) -> Value {
    json!({"ok": false, "firstMissingSignal": signal})
}

fn record_hyalos_change(kind: &str, mut attributes: Value, mode: OfferMode, started: Instant) {
    attributes["duration_ms"] = json!(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
    let event = reflection_event(Reflection {
        organ: "caduceus".into(),
        kind: kind.into(),
        message: "hyalos changed".into(),
        ok: true,
        attributes_redacted: attributes,
        ..Reflection::default()
    });
    // The deed describes an act that has already happened. A store failure
    // is reported once by record; a rejected projection gets this fixed line.
    if !matches!(event.and_then(|event| record(&event, mode)),
        Ok(Disposition::Written | Disposition::Failed))
    {
        let _ = writeln!(std::io::stderr().lock(), "hyalos-deed-unwritten: {kind}");
    }
}

pub(crate) fn clear_json(body: &Value) -> DoorResult {
    let body = body.as_object().ok_or(CLEAR_INVALID)?;
    // A misplaced selector must not be mistaken for an unfiltered clear.
    if body.keys().any(|key| !matches!(key.as_str(), "kind" | "verb" | "flags")) {
        return Err(CLEAR_INVALID);
    }
    let mut no_clobber = false;
    if let Some(flags) = body.get("flags") {
        let flags = flags.as_object().ok_or(CLEAR_INVALID)?;
        if flags.is_empty() || flags.keys().any(|key| !matches!(key.as_str(), "exousia" | "no_clobber")) {
            return Err(CLEAR_INVALID);
        }
        if let Some(exousia) = flags.get("exousia") {
            let exousia = exousia.as_object().ok_or(CLEAR_INVALID)?;
            if exousia.len() != 1 || !exousia.contains_key("pin") {
                return Err(CLEAR_INVALID);
            }
        }
        if let Some(flag) = flags.get("no_clobber") {
            no_clobber = flag.as_bool().ok_or(CLEAR_INVALID)?;
        }
    }
    let filter = match (body.get("kind"), body.get("verb")) {
        (None, None) => None,
        (Some(kind), Some(verb)) => {
            let kind = kind.as_str().ok_or(CLEAR_INVALID)?;
            let verb = verb
                .as_str()
                .filter(|verb| !verb.is_empty())
                .ok_or(CLEAR_INVALID)?;
            match store::recognizes_kind(kind) {
                Ok(true) => Some((kind, verb)),
                Ok(false) => return Err(CLEAR_INVALID),
                Err(signal) => {
                    return Ok(if no_clobber {
                        json!({"ok": false, "deleted": 0, "restored": true, "changed": false, "firstMissingSignal": signal})
                    } else {
                        door_error(signal)
                    });
                }
            }
        }
        _ => return Err(CLEAR_INVALID),
    };

    if no_clobber {
        let (deleted, signal, restored) = match store::rehearse_clear(filter) {
            Ok(deleted) => (deleted, "none", true),
            Err(signal) => (0, signal, signal != "caduceus-hyalos-rehearsal-rollback-failed"),
        };
        return Ok(json!({
            "ok": signal == "none",
            "deleted": deleted,
            "restored": restored,
            "changed": false,
            "firstMissingSignal": signal,
        }));
    }

    let started = Instant::now();
    let (deleted, interruption) = match store::clear(filter) {
        Ok(pass) => (pass.deleted, pass.interruption),
        Err(signal) => (0, Some(signal)),
    };
    if deleted > 0 {
        let target = match filter {
            Some((kind, verb)) => format!("hyalos/{kind}/{verb}"),
            None => "hyalos/all".into(),
        };
        record_hyalos_change(
            CLEAR_DEED,
            json!({"verb": "remove", "target": target, "outcome": format!("deleted {deleted}")}),
            OfferMode::Upkeep,
            started,
        );
    }
    store::forget_troubles();
    Ok(json!({
        "ok": interruption.is_none(),
        "deleted": deleted,
        "firstMissingSignal": interruption.unwrap_or("none"),
    }))
}

pub(crate) fn level_json() -> Value {
    store::level_status().unwrap_or_else(door_error)
}

pub(crate) fn set_level_json(body: &Value) -> DoorResult {
    let level = body.get("level").and_then(Value::as_i64).ok_or(LEVEL_INVALID)?;
    let started = Instant::now();
    let answer = match store::set_level(level) {
        Ok(Some(answer)) => answer,
        Ok(None) => return Err(LEVEL_INVALID),
        Err(signal) => return Ok(door_error(&signal)),
    };
    if answer["changed"] == true {
        record_hyalos_change(
            "hyalos-level",
            json!({"verb": "set", "target": format!("hyalos/level/{level}")}),
            OfferMode::Normal,
            started,
        );
    }
    Ok(answer)
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
    // `world` was event metadata; the seated row has no such field. Do not
    // silently broaden an old world-filtered request to the whole Hyalos.
    if filters.world.is_some() {
        return Err("hyalos-tail-world-unavailable".into());
    }
    const RESULT_MAX_BYTES: usize = 1024 * 1024;
    let keep = filters.count.clamp(1, 1000);
    let (rows, file_size) = store::read_tail(&filters, keep + 1)?;
    let lines_scanned = rows.len();
    let count_limit_reached = lines_scanned > keep;
    let mut result_bytes = 0;
    let mut output_limit_reached = false;
    let mut events = Vec::new();
    for row in rows.into_iter().take(keep) {
        let bytes = row.to_string().len() + 1;
        if result_bytes + bytes > RESULT_MAX_BYTES {
            output_limit_reached = true;
            break;
        }
        result_bytes += bytes;
        events.push(row);
    }
    // The window is the newest matching rows, in the tail's existing display order.
    events.reverse();
    let has_more = count_limit_reached || output_limit_reached;
    Ok(json!({
        "schema": "caduceus.hyalos.tail.v1",
        "ok": true,
        "channelPath": config::path(DB_PATH),
        "count": events.len(),
        "filters": filters,
        "events": events,
        "has_more": has_more,
        // The file-scan counters are retired; lines_scanned counts SQL rows
        // returned for this window (including the lookahead), not index visits.
        "scan": {
            "bytes_available": file_size,
            "bytes_scanned": 0,
            "scan_start": 0,
            "scan_end": 0,
            "lines_scanned": lines_scanned,
            "blocks_read": 0,
            "invalid_lines_skipped": 0,
            "oversized_lines_skipped": 0,
            "torn_trailing_rows_skipped": 0,
            "blank_lines_skipped": 0,
            "filtered_lines": 0,
            "result_bytes": result_bytes,
            "result_limit_bytes": RESULT_MAX_BYTES,
            "line_limit": keep,
            "line_bytes_limit_including_lf": 0,
            "scan_limit_bytes": 0,
            "scan_limit_reached": false,
            "line_limit_reached": false,
            "output_limit_reached": output_limit_reached,
            "count_limit_reached": count_limit_reached,
            "truncated_prefix_line_skipped": false,
            "truncated": has_more,
        },
        "firstMissingSignal": "none",
    }))
}
