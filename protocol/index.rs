use serde_json::{json, Map, Value};
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/protocol_seat.rs"));

pub const SCHEMA_ID: &str = "caduceus.staff.v1";

pub fn seat() -> Result<Value, String> {
    crate::routes::leaf_schema::declaration(SCHEMA_ID)
        .cloned()
        .ok_or_else(|| "protocol-seat-absent".to_owned())
}

pub const fn hyalos_event_schema() -> &'static str {
    HYALOS_EVENT_SCHEMA
}

pub fn benchmark_report_schema() -> &'static str {
    BENCHMARK_REPORT_SCHEMA
}

pub fn benchmark_enabled(envelope: &Value) -> bool {
    envelope
        .get("flags")
        .and_then(Value::as_object)
        .and_then(|flags| flags.get(BENCHMARK_FLAG_NAME))
        .and_then(Value::as_bool)
        == Some(true)
}

pub fn benchmark_receive_locus() -> Result<String, String> {
    let seat = crate::routes::leaf_schema::declaration(SCHEMA_ID)
        .ok_or_else(|| format!("protocol-seat-absent:{SCHEMA_ID}"))?;
    seat.pointer("/flags/families")
        .and_then(Value::as_object)
        .and_then(|families| families.values().find_map(|family| family.get("native_benchmark")))
        .and_then(|native| native.get("receive_locus"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("protocol-seat-field-missing:{SCHEMA_ID}:receive_locus"))
}

pub fn benchmark_timing_row(locus: String, elapsed: Duration, ok: bool) -> Value {
    json!({
        "locus": locus,
        "elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "ok": ok
    })
}

pub fn benchmark_serve_locus(ordinal: usize, band: &str) -> String {
    BENCHMARK_SERVE_LOCUS
        .replace(
            "<ordinal>",
            &(ordinal as u64 + BENCHMARK_SERVE_ORDINAL_BASE).to_string(),
        )
        .replace("<band>", band)
}

fn valid_benchmark_timing_row(value: &Value) -> bool {
    value.get("locus").and_then(Value::as_str).is_some()
        && value.get("elapsed_ms").and_then(Value::as_f64).is_some()
        && value.get("ok").and_then(Value::as_bool).is_some()
}

pub fn append_benchmark_reply(payload: &mut Value, elapsed: Duration, stamps: &[&Value]) {
    let mut timings = Vec::new();
    let mut staff_reports = Vec::new();
    for stamp in stamps {
        let Some(benchmark) = stamp.get("benchmarkStamp") else {
            continue;
        };
        if let Some(rows) = benchmark.get("timings").and_then(Value::as_array) {
            timings.extend(rows.iter().cloned());
        }
        if let Some(reports) = benchmark.get("staff_reports").and_then(Value::as_array) {
            staff_reports.extend(reports.iter().cloned());
        }
    }
    for report in &staff_reports {
        if let Some(rows) = report.get("timings").and_then(Value::as_array) {
            timings.extend(
                rows.iter()
                    .filter(|row| valid_benchmark_timing_row(row))
                    .cloned(),
            );
        }
    }
    let mut benchmark = json!({
        "schema": BENCHMARK_REPORT_SCHEMA,
        "total_elapsed_ms": elapsed.as_secs_f64() * 1000.0,
        "timings": timings
    });
    if !staff_reports.is_empty() {
        benchmark["staff_reports"] = json!(staff_reports);
    }
    if let Some(object) = payload.as_object_mut() {
        object.insert("benchmark".into(), benchmark);
    }
}

#[derive(Clone, Debug)]
pub struct Envelope {
    raw: Value,
    schema: String,
    intent_id: Option<String>,
    transition: Option<String>,
    origin_of_intent: Value,
    flags: Option<Value>,
}

// Keep literal comparisons at the reader without giving an absent transition a value.
pub struct EnvelopeTransition<'a>(Option<&'a str>);

impl PartialEq<&str> for EnvelopeTransition<'_> {
    fn eq(&self, expected: &&str) -> bool {
        self.0 == Some(*expected)
    }
}

impl Envelope {
    pub fn parse(raw: Value) -> Result<Self, String> {
        let object = raw
            .as_object()
            .ok_or_else(|| "protocol-envelope-not-object".to_string())?;
        let declaration = crate::routes::leaf_schema::declaration(SCHEMA_ID);
        let schema = match declaration {
            Some(declaration) => required_kernel_string(object, declaration, 0)?,
            None => required_string(object, "schema")?,
        };
        if schema != SCHEMA_ID {
            return Err("protocol-schema-mismatch".into());
        }
        let (intent_id, transition) = match declaration {
            Some(declaration) => (
                Some(required_kernel_string(object, declaration, 1)?),
                Some(required_kernel_string(object, declaration, 2)?),
            ),
            None => (
                kernel_string(object, "intent_id"),
                kernel_string(object, "transition"),
            ),
        };
        let origin_of_intent = object
            .get("origin_of_intent")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| Value::String("near".to_string()));
        let flags = object.get("flags").cloned();
        Ok(Self {
            raw,
            schema,
            intent_id,
            transition,
            origin_of_intent,
            flags,
        })
    }

    pub fn raw(&self) -> &Value {
        &self.raw
    }
    pub fn schema(&self) -> &str {
        &self.schema
    }
    pub fn intent_id(&self) -> Option<&str> {
        self.intent_id.as_deref()
    }
    pub fn transition(&self) -> EnvelopeTransition<'_> {
        EnvelopeTransition(self.transition.as_deref())
    }
    pub fn origin_of_intent(&self) -> &Value {
        &self.origin_of_intent
    }
    pub fn flags(&self) -> Option<&Value> {
        self.flags.as_ref()
    }
    pub fn into_raw(self) -> Value {
        self.raw
    }
}

fn required_kernel_string(
    object: &Map<String, Value>,
    declaration: &Value,
    index: usize,
) -> Result<String, String> {
    let field = declaration["kernel"]["required"]
        .as_array()
        .and_then(|fields| fields.get(index))
        .and_then(Value::as_str)
        .ok_or_else(|| format!("protocol-kernel-definition-missing:{index}"))?;
    required_string(object, field)
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String, String> {
    kernel_string(object, field).ok_or_else(|| format!("protocol-kernel-field-missing:{field}"))
}

fn kernel_string(object: &Map<String, Value>, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}
