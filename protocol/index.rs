use serde_json::{Map, Value};

include!(concat!(env!("OUT_DIR"), "/protocol_seat.rs"));

pub fn seat() -> Result<Value, String> {
    serde_json::from_str(SEAT_JSON).map_err(|error| format!("protocol-seat-invalid:{error}"))
}

#[derive(Clone, Debug)]
pub struct Envelope {
    raw: Value,
    schema: String,
    intent_id: String,
    transition: String,
    origin_of_intent: Value,
    flags: Option<Value>,
}

impl Envelope {
    pub fn parse(raw: Value) -> Result<Self, String> {
        let object = raw
            .as_object()
            .ok_or_else(|| "protocol-envelope-not-object".to_string())?;
        let schema = required_kernel_string(object, 0)?;
        if schema != SCHEMA_ID {
            return Err("protocol-schema-mismatch".into());
        }
        let intent_id = required_kernel_string(object, 1)?;
        let transition = required_kernel_string(object, 2)?;
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
    pub fn intent_id(&self) -> &str {
        &self.intent_id
    }
    pub fn transition(&self) -> &str {
        &self.transition
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

fn required_kernel_string(object: &Map<String, Value>, index: usize) -> Result<String, String> {
    let field = KERNEL_FIELDS
        .get(index)
        .ok_or_else(|| format!("protocol-kernel-definition-missing:{index}"))?;
    object
        .get(*field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("protocol-kernel-field-missing:{field}"))
}
