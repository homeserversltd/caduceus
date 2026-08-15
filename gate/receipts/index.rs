use crate::protocol::Envelope;
use serde_json::Value;

pub fn append_stamp(
    envelope: &Envelope,
    admittance: &str,
    attendance_witness: bool,
    registers_lit: bool,
    ok: bool,
    first_missing_signal: Option<&str>,
) -> Value {
    let mut receipt = envelope.raw().as_object().cloned().unwrap_or_default();
    receipt.insert("admittance".into(), Value::String(admittance.into()));
    receipt.insert(
        "attendance".into(),
        Value::String(
            if attendance_witness {
                "witness"
            } else {
                "absent"
            }
            .into(),
        ),
    );
    receipt.insert("registers_lit".into(), Value::Bool(registers_lit));
    receipt.insert("ok".into(), Value::Bool(ok));
    if let Some(signal) = first_missing_signal {
        receipt.insert("first_missing_signal".into(), Value::String(signal.into()));
    }
    Value::Object(receipt)
}
