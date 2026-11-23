//! Project registrations using the public seat files, not the embedded route registry.
use serde_json::Value;
use std::sync::OnceLock;

pub(super) fn routine_seat() -> Result<&'static Value, &'static str> {
    static SEAT: OnceLock<Value> = OnceLock::new();
    if let Some(seat) = SEAT.get() {
        return Ok(seat);
    }
    let bytes = crate::shared::config::read_public_file(&format!(
        "opt/caduceus/source/schema/{}.json",
        super::SCHEMA
    ))
    .map_err(|_| "pid2-routine-seat-absent")?;
    let seat: Value = serde_json::from_str(&bytes).map_err(|_| "pid2-routine-seat-invalid")?;
    if seat.get("schema").and_then(Value::as_str) != Some(super::SCHEMA) {
        return Err("pid2-routine-seat-foreign");
    }
    if !seat.get("fields").is_some_and(Value::is_object) {
        return Err("pid2-routine-seat-fields-invalid");
    }
    // Cache only a usable seat; a later request can recover an absent file.
    Ok(SEAT.get_or_init(|| seat))
}

fn allows_container(seat: &Value, kind: &str) -> bool {
    seat.get("type").is_none_or(|types| {
        types.as_str() == Some(kind)
            || types
                .as_array()
                .is_some_and(|types| types.iter().any(|ty| ty.as_str() == Some(kind)))
    })
}

pub(super) fn project(value: Value, seat: &Value) -> Value {
    let fields = seat.get("fields").or_else(|| seat.get("properties"));
    match value {
        Value::Object(object) => Value::Object(match fields {
            Some(fields) => object
                .into_iter()
                .filter_map(|(name, value)| {
                    let field = fields.get(&name)?;
                    Some((name, project(value, field)))
                })
                .collect(),
            // An open object is declared as a whole, not emptied.
            None if allows_container(seat, "object") => object,
            // A container in a scalar or array slot cannot carry object fields.
            None => Default::default(),
        }),
        Value::Array(array) => Value::Array(match seat.get("items") {
            Some(item) => array.into_iter().map(|value| project(value, item)).collect(),
            None if fields.is_none() && allows_container(seat, "array") => array,
            None => Vec::new(),
        }),
        scalar => scalar,
    }
}

pub(super) fn stored(raw: &[u8], seat: &Value) -> Result<Value, String> {
    let value = serde_json::from_slice(raw).map_err(|error| error.to_string())?;
    Ok(project(value, seat))
}

pub(super) fn echo(raw: &[u8]) -> Result<(Value, String), String> {
    let envelope = stored(raw, routine_seat()?)?;
    let raw_envelope = envelope.to_string();
    Ok((envelope, raw_envelope))
}
