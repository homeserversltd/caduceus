//! Project registrations using the public seat files, not the embedded route registry.
use serde_json::Value;
use std::sync::OnceLock;

pub(super) fn routine_seat() -> Result<&'static Value, &'static str> {
    static SEAT: OnceLock<Value> = OnceLock::new();
    public_seat(
        &SEAT,
        super::SCHEMA,
        [
            "pid2-routine-seat-absent",
            "pid2-routine-seat-invalid",
            "pid2-routine-seat-foreign",
            "pid2-routine-seat-fields-invalid",
        ],
    )
}

pub(super) fn schedule_seat(schema: &str) -> Result<&'static Value, &'static str> {
    static SEAT: OnceLock<Value> = OnceLock::new();
    public_seat(
        &SEAT,
        schema,
        [
            "pid2-schedule-seat-absent",
            "pid2-schedule-seat-invalid",
            "pid2-schedule-seat-foreign",
            "pid2-schedule-seat-fields-invalid",
        ],
    )
}

fn public_seat(
    cache: &'static OnceLock<Value>,
    schema: &str,
    [absent, invalid, foreign, fields_invalid]: [&'static str; 4],
) -> Result<&'static Value, &'static str> {
    if let Some(seat) = cache.get() {
        return Ok(seat);
    }
    let bytes = crate::shared::config::read_public_file(&format!(
        "opt/caduceus/source/schema/{schema}.json"
    ))
    .map_err(|_| absent)?;
    let seat: Value = serde_json::from_str(&bytes).map_err(|_| invalid)?;
    if seat.get("schema").and_then(Value::as_str) != Some(schema) {
        return Err(foreign);
    }
    if !seat.get("fields").is_some_and(Value::is_object) {
        return Err(fields_invalid);
    }
    // Cache only a usable seat; a later request can recover an absent file.
    Ok(cache.get_or_init(|| seat))
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
    echo_for(raw, routine_seat()?)
}

pub(super) fn echo_for(raw: &[u8], seat: &Value) -> Result<(Value, String), String> {
    let envelope = stored(raw, seat)?;
    let raw_envelope = envelope.to_string();
    Ok((envelope, raw_envelope))
}
