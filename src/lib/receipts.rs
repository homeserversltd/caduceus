use crate::shared::hyalos;
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptMetadata {
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    mutation: Option<bool>,
    #[serde(default)]
    mutation_performed: Option<bool>,
    #[serde(default)]
    verb: Option<String>,
    #[serde(default)]
    transition: Option<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    route: Option<String>,
    #[serde(default, alias = "first_missing_signal")]
    first_missing_signal: Option<String>,
    #[serde(default, alias = "first_missing_field", alias = "field")]
    first_missing_field: Option<String>,
    #[serde(default, alias = "correlation_id")]
    correlation_id: Option<String>,
    #[serde(default, alias = "session_id")]
    session_id: Option<String>,
    #[serde(default, alias = "work_id")]
    work_id: Option<String>,
    #[serde(default, alias = "review_id")]
    review_id: Option<String>,
    #[serde(default, alias = "strike_id")]
    strike_id: Option<String>,
    #[serde(default, alias = "duration_ms")]
    duration_ms: Option<u64>,
}

fn parse_text_metadata(body: &str) -> ReceiptMetadata {
    let mut metadata = ReceiptMetadata::default();
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "ok" => metadata.ok = match value { "true" => Some(true), "false" => Some(false), _ => None },
            "mutation" => metadata.mutation = match value { "true" => Some(true), "false" => Some(false), _ => None },
            "mutation_performed" | "mutationPerformed" => metadata.mutation_performed = match value { "true" => Some(true), "false" => Some(false), _ => None },
            "verb" => metadata.verb = Some(value.to_string()),
            "transition" => metadata.transition = Some(value.to_string()),
            "command" => metadata.command = Some(value.to_string()),
            "target" | "device_id" => metadata.target = Some(value.to_string()),
            "route" => metadata.route = Some(value.to_string()),
            "first_missing_signal" | "firstMissingSignal" => metadata.first_missing_signal = Some(value.to_string()),
            "first_missing_field" | "firstMissingField" | "field" => metadata.first_missing_field = Some(value.to_string()),
            "duration_ms" | "durationMs" => metadata.duration_ms = value.parse().ok(),
            _ => {}
        }
    }
    metadata
}

pub fn write_latest(body: &str) -> Result<(), String> {
    write_latest_inner(body, None)
}

pub fn write_latest_with_duration(body: &str, duration_ms: u64) -> Result<(), String> {
    write_latest_inner(body, Some(duration_ms))
}

fn write_latest_inner(body: &str, duration_ms: Option<u64>) -> Result<(), String> {
    let mut metadata = serde_json::from_str::<ReceiptMetadata>(body)
        .unwrap_or_else(|_| parse_text_metadata(body));
    if let Some(duration_ms) = duration_ms {
        metadata.duration_ms = Some(duration_ms);
    }
    let ok = metadata.ok.unwrap_or(true);
    let outcome = if let Some(ok) = metadata.ok {
        if ok { "success" } else { "failure" }
    } else if metadata.mutation_performed == Some(false) || metadata.mutation == Some(false) {
        "unchanged"
    } else {
        "attempted"
    };
    hyalos::reflect_json(json!({
        "organ": "caduceus",
        "kind": "receipt",
        "ok": ok,
        "level": if ok { "info" } else { "warn" },
        "message": "receipt deed",
        "correlation_id": metadata.correlation_id,
        "session_id": metadata.session_id,
        "work_id": metadata.work_id,
        "review_id": metadata.review_id,
        "strike_id": metadata.strike_id,
        "attributes_redacted": {
            "who": "caduceus",
            "verb": metadata.verb.or(metadata.transition).or(metadata.command).unwrap_or_else(|| "receipt".into()),
            "target": metadata.target.or(metadata.route).unwrap_or_else(|| "appliance".into()),
            "outcome": outcome,
            "duration_ms": metadata.duration_ms,
            "signal": metadata.first_missing_signal,
            "first_missing_field": metadata.first_missing_field,
        }
    }))
    .map(|_| ())
}
