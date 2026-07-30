use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const BIND_LAUNCHER: &str = "/usr/local/sbin/caduceus-bind";
const VERIFY_LAUNCHER: &str = "/usr/local/sbin/caduceus-verify";
const ATTENDANCE_INACTIVITY_LIMIT: Duration = Duration::from_secs(15 * 60);

#[derive(Clone, Debug, PartialEq, Eq)]
struct Attendance {
    document_id: String,
    document_incarnation: String,
    created_at: Instant,
    last_touch: Instant,
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

fn expired(attendance: &Attendance, now: Instant) -> bool {
    let last_touch = attendance.last_touch.max(attendance.created_at);
    now.saturating_duration_since(last_touch) >= ATTENDANCE_INACTIVITY_LIMIT
}

fn evict_expired(current: &mut HashMap<String, Attendance>, now: Instant) {
    current.retain(|_, attendance| !expired(attendance, now));
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

fn crossing(bin: &str, input: &Value) -> Result<Value, String> {
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg(bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    let payload = serde_json::to_vec(input)
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    child.stdin.take()
        .ok_or_else(|| "caduceus-pin-not-yet-provisioned".to_string())?
        .write_all(&payload)
        .map_err(|_| "caduceus-pin-not-yet-provisioned".to_string())?;
    let output = child.wait_with_output()
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
    let (bound, posture, signal) = match crossing(BIND_LAUNCHER, &json!({})) {
        Ok(value) => {
            let public_key = value.get("publicKey").and_then(Value::as_str);
            let epoch = value.get("epoch").and_then(|value| match value {
                Value::String(value) if !value.is_empty() => Some(value.clone()),
                Value::Number(value) => Some(value.to_string()),
                _ => None,
            });
            match (public_key, epoch) {
                (Some(public_key), Some(epoch)) if !public_key.is_empty() => (
                    Some(BoundVerifier { public_key: public_key.to_string(), epoch }),
                    "DERIVED_BOUND",
                    "none".to_string(),
                ),
                _ => (None, "UNBOUND", "caduceus-derived-unbound".to_string()),
            }
        }
        Err(signal) => (None, "UNBOUND", signal),
    };
    if let Ok(mut guard) = state().lock() {
        guard.verifier = bound;
    }
    eprintln!("{}", json!({
        "event": "caduceus-access-bind",
        "posture": posture,
        "firstMissingSignal": signal,
    }));
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
    crossing(VERIFY_LAUNCHER, &json!({ "pin": pin, "publicKey": public_key }))
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
    let now = Instant::now();
    let mut guard = state().lock().map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, now);
    let attendance = format!("attendance-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    guard.current.insert(
        attendance.clone(),
        Attendance {
            document_id: document_id.clone(),
            document_incarnation: document_incarnation.clone(),
            created_at: now,
            last_touch: now,
        },
    );
    let mut result = envelope(true, "none");
    result["attendance"] = Value::String(attendance);
    result["documentId"] = Value::String(document_id);
    result["documentIncarnation"] = Value::String(document_incarnation);
    Ok(result)
}

pub fn validate_json(body: &Value) -> Result<Value, String> {
    // Validation is observation only: background transport must not renew human activity.
    // Only touch_json advances last_touch.
    let attendance = text(body, "attendance")?;
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let mut guard = state().lock().map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, Instant::now());
    let Some(current) = guard.current.get(&attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id || current.document_incarnation != document_incarnation {
        return Ok(envelope(false, "caduceus-attendance-document-incarnation-mismatch"));
    }
    Ok(envelope(true, "none"))
}

pub fn touch_json(body: &Value) -> Result<Value, String> {
    let attendance = text(body, "attendance")?;
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let now = Instant::now();
    let mut guard = state().lock().map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, now);
    let Some(current) = guard.current.get_mut(&attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id || current.document_incarnation != document_incarnation {
        return Ok(envelope(false, "caduceus-attendance-document-incarnation-mismatch"));
    }
    current.last_touch = now;
    Ok(envelope(true, "none"))
}

pub fn invalidate_json(body: &Value) -> Result<Value, String> {
    let attendance = text(body, "attendance")?;
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let mut guard = state().lock().map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, Instant::now());
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
    state().lock().ok().is_some_and(|mut guard| {
        evict_expired(&mut guard.current, Instant::now());
        guard.current.get(attendance).is_some_and(|current| {
            current.document_id == document_id && current.document_incarnation == document_incarnation
        })
    })
}

pub fn reset_for_tests() {
    if let Ok(mut guard) = state().lock() {
        guard.current.clear();
        guard.verifier = None;
    }
}
