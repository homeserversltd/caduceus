use serde_json::{json, Value};
use std::collections::HashMap;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const BIND_LAUNCHER: &str = "/usr/local/sbin/caduceus-bind";
const VERIFY_LAUNCHER: &str = "/usr/local/sbin/caduceus-verify";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Attendance {
    document_id: String,
    document_incarnation: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BoundVerifier {
    public_key: String,
    epoch: String,
}

#[derive(Default)]
struct AttendanceState {
    current: HashMap<String, Attendance>,
    verifier: Option<BoundVerifier>,
}

static STATE: OnceLock<Mutex<AttendanceState>> = OnceLock::new();
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

fn state() -> &'static Mutex<AttendanceState> {
    STATE.get_or_init(|| Mutex::new(AttendanceState::default()))
}

fn text(body: &Value, field: &str) -> Result<String, String> {
    let value = body
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| format!("caduceus-attendance-{field}-missing"))?;
    Ok(value.to_string())
}

fn envelope(ok: bool, code: &'static str) -> Value {
    json!({
        "schema": "caduceus.attendance.v1",
        "ok": ok,
        "code": code,
        "firstMissingSignal": if ok { "none" } else { code },
    })
}

fn crossing(bin: &str, args: &[&str]) -> Result<Value, String> {
    let output = Command::new("sudo")
        .arg("-n")
        .arg(bin)
        .args(args)
        .output()
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    if !output.status.success() || value.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(value
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-pin-not-yet-provisioned")
            .to_string());
    }
    Ok(value)
}

/// Bind only public verifier material at process startup. Any unsuccessful crossing is UNBOUND.
pub fn bind() {
    let bound = crossing(BIND_LAUNCHER, &[]).ok().and_then(|value| {
        let public_key = value.get("publicKey")?.as_str()?.to_string();
        let epoch = match value.get("epoch")? {
            Value::String(value) if !value.is_empty() => value.clone(),
            Value::Number(value) => value.to_string(),
            _ => return None,
        };
        if public_key.is_empty() { None } else { Some(BoundVerifier { public_key, epoch }) }
    });
    if let Ok(mut guard) = state().lock() {
        guard.verifier = bound;
    }
}

fn verifier() -> Result<BoundVerifier, String> {
    state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?
        .verifier
        .clone()
        .ok_or_else(|| "caduceus-pin-not-yet-provisioned".to_string())
}

fn pin_verified(pin: &str, public_key: &str) -> bool {
    crossing(VERIFY_LAUNCHER, &[pin, public_key])
        .ok()
        .and_then(|value| value.get("verified").and_then(Value::as_bool))
        == Some(true)
}

pub fn open_json(body: &Value) -> Result<Value, String> {
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let pin = text(body, "pin")?;
    let verifier = verifier()?;
    if !pin_verified(&pin, &verifier.public_key) {
        return Ok(envelope(false, "caduceus-attendance-pin-refused"));
    }
    let mut guard = state().lock().map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    let attendance = format!("attendance-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    guard.current.insert(
        attendance.clone(),
        Attendance { document_id: document_id.clone(), document_incarnation: document_incarnation.clone() },
    );
    let mut result = envelope(true, "none");
    result["attendance"] = Value::String(attendance);
    result["documentId"] = Value::String(document_id);
    result["documentIncarnation"] = Value::String(document_incarnation);
    Ok(result)
}

pub fn validate_json(body: &Value) -> Result<Value, String> {
    let attendance = text(body, "attendance")?;
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let guard = state().lock().map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    let Some(current) = guard.current.get(&attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id || current.document_incarnation != document_incarnation {
        return Ok(envelope(false, "caduceus-attendance-document-incarnation-mismatch"));
    }
    Ok(envelope(true, "none"))
}

pub fn invalidate_json(body: &Value) -> Result<Value, String> {
    let attendance = text(body, "attendance")?;
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let mut guard = state().lock().map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    let Some(current) = guard.current.get(&attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id || current.document_incarnation != document_incarnation {
        return Ok(envelope(false, "caduceus-attendance-document-incarnation-mismatch"));
    }
    guard.current.remove(&attendance);
    Ok(envelope(true, "none"))
}

pub fn admits(attendance: &str, document_id: &str, document_incarnation: &str) -> bool {
    state().lock().ok().and_then(|guard| guard.current.get(attendance).cloned()).is_some_and(|current| {
        current.document_id == document_id && current.document_incarnation == document_incarnation
    })
}

pub fn reset_for_tests() {
    if let Ok(mut guard) = state().lock() {
        guard.current.clear();
        guard.verifier = None;
    }
}
