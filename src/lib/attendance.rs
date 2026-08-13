use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const PIN_MODE_PATH: &str = "var/lib/caduceus/access-pin-mode.json";
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

fn pin_mode_path() -> std::path::PathBuf {
    crate::shared::config::path(PIN_MODE_PATH)
}

pub fn pin_mode_json() -> Value {
    let pin_required = fs::read_to_string(pin_mode_path())
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .and_then(|value| value.get("pin_required").and_then(Value::as_bool))
        .unwrap_or(true);
    json!({
        "schema": "caduceus.access.pin.mode.v1",
        "ok": true,
        "pin_required": pin_required,
        "firstMissingSignal": "none",
    })
}

pub fn set_pin_mode_json(body: &Value) -> Result<Value, String> {
    let object = body
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or_else(|| "caduceus-access-pin-mode-invalid".to_string())?;
    let pin_required = object
        .get("pin_required")
        .and_then(Value::as_bool)
        .ok_or_else(|| "caduceus-access-pin-mode-invalid".to_string())?;
    let path = pin_mode_path();
    let parent = path
        .parent()
        .ok_or_else(|| "caduceus-access-pin-mode-unavailable".to_string())?;
    fs::create_dir_all(parent).map_err(|_| "caduceus-access-pin-mode-unavailable".to_string())?;
    let temporary = parent.join(format!(".access-pin-mode-{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec(&json!({"pin_required": pin_required}))
        .map_err(|_| "caduceus-access-pin-mode-unavailable".to_string())?;
    fs::write(&temporary, bytes).map_err(|_| "caduceus-access-pin-mode-unavailable".to_string())?;
    if fs::rename(&temporary, &path).is_err() {
        let _ = fs::remove_file(&temporary);
        return Err("caduceus-access-pin-mode-unavailable".to_string());
    }
    Ok(pin_mode_json())
}

fn bound_verifier(value: &Value) -> Option<BoundVerifier> {
    let public_key = value.get("publicKey").and_then(Value::as_str)?;
    if public_key.is_empty() {
        return None;
    }
    let epoch = value.get("epoch").and_then(|value| match value {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    })?;
    Some(BoundVerifier {
        public_key: public_key.to_string(),
        epoch,
    })
}

/// Bind only public verifier material at process startup. Any unsuccessful crossing is UNBOUND.
pub fn bind() {
    let (bound, posture, signal) =
        match crate::shared::agathodaimon::crossing("attendance", "bind", &json!({})) {
            Ok(value) => match bound_verifier(&value) {
                Some(verifier) => (Some(verifier), "DERIVED_BOUND", "none".to_string()),
                None => (None, "UNBOUND", "caduceus-derived-unbound".to_string()),
            },
            Err(signal) => (None, "UNBOUND", signal),
        };
    if let Ok(mut guard) = state().lock() {
        guard.verifier = bound;
    }
    eprintln!(
        "{}",
        json!({
            "event": "caduceus-access-bind",
            "posture": posture,
            "firstMissingSignal": signal,
        })
    );
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
    crate::shared::agathodaimon::crossing(
        "attendance",
        "verify",
        &json!({ "pin": pin, "publicKey": public_key }),
    )
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
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
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
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, Instant::now());
    let Some(current) = guard.current.get(&attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id || current.document_incarnation != document_incarnation {
        return Ok(envelope(
            false,
            "caduceus-attendance-document-incarnation-mismatch",
        ));
    }
    Ok(envelope(true, "none"))
}

pub fn touch_json(body: &Value) -> Result<Value, String> {
    let attendance = text(body, "attendance")?;
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let now = Instant::now();
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, now);
    let Some(current) = guard.current.get_mut(&attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id || current.document_incarnation != document_incarnation {
        return Ok(envelope(
            false,
            "caduceus-attendance-document-incarnation-mismatch",
        ));
    }
    current.last_touch = now;
    Ok(envelope(true, "none"))
}

pub fn change_pin_json(body: &Value) -> Result<Value, String> {
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let attendance = text(body, "attendance")?;
    let current_pin = text(body, "currentPin")?;
    let new_pin = text(body, "newPin")?;
    let now = Instant::now();
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, now);
    let Some(current) = guard.current.get(&attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id || current.document_incarnation != document_incarnation {
        return Ok(envelope(
            false,
            "caduceus-attendance-document-incarnation-mismatch",
        ));
    }
    let verifier = guard
        .verifier
        .clone()
        .ok_or_else(|| "caduceus-pin-not-yet-provisioned".to_string())?;
    if !pin_verified(&current_pin, &verifier.public_key) {
        return Ok(envelope(false, "caduceus-attendance-pin-refused"));
    }
    let receipt = match crate::shared::agathodaimon::crossing(
        "pin",
        "change",
        &json!({ "oldPin": current_pin, "newPin": new_pin }),
    ) {
        Ok(value) => value,
        Err(_) => return Ok(envelope(false, "caduceus-attendance-change-failed")),
    };
    let Some(rebound) = bound_verifier(&receipt) else {
        return Ok(envelope(false, "caduceus-attendance-change-failed"));
    };

    guard.verifier = Some(rebound);
    guard.current.retain(|key, _| key == &attendance);
    if let Some(current) = guard.current.get_mut(&attendance) {
        current.last_touch = now;
    }
    Ok(envelope(true, "none"))
}

pub fn change_pin_access_json(
    document_id: &str,
    attendance: &str,
    body: &Value,
) -> Result<Value, String> {
    let object = body
        .as_object()
        .filter(|object| object.len() == 2)
        .ok_or_else(|| "caduceus-access-pin-change-invalid".to_string())?;
    let current_pin = object
        .get("current_pin")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| "caduceus-access-pin-current_pin-missing".to_string())?;
    let new_pin = object
        .get("new_pin")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| "caduceus-access-pin-new_pin-missing".to_string())?;
    let now = Instant::now();
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, now);
    let Some(current) = guard.current.get(attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    }
    let verifier = guard
        .verifier
        .clone()
        .ok_or_else(|| "caduceus-pin-not-yet-provisioned".to_string())?;
    if !pin_verified(current_pin, &verifier.public_key) {
        return Ok(envelope(false, "caduceus-attendance-pin-refused"));
    }
    let receipt = match crate::shared::agathodaimon::crossing(
        "pin",
        "change",
        &json!({ "oldPin": current_pin, "newPin": new_pin }),
    ) {
        Ok(value) => value,
        Err(_) => return Ok(envelope(false, "caduceus-attendance-change-failed")),
    };
    let Some(rebound) = bound_verifier(&receipt) else {
        return Ok(envelope(false, "caduceus-attendance-change-failed"));
    };
    guard.verifier = Some(rebound);
    guard.current.retain(|key, _| key == attendance);
    if let Some(current) = guard.current.get_mut(attendance) {
        current.last_touch = now;
    }
    Ok(envelope(true, "none"))
}

pub fn reset_default_pin_json() -> Result<Value, String> {
    let receipt = crate::shared::agathodaimon::crossing("pin", "reset-default", &json!({}))?;
    let rebound =
        bound_verifier(&receipt).ok_or_else(|| "caduceus-pin-default-reset-failed".to_string())?;
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    guard.verifier = Some(rebound);
    guard.current.clear();
    Ok(envelope(true, "none"))
}

pub fn invalidate_json(body: &Value) -> Result<Value, String> {
    let attendance = text(body, "attendance")?;
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, Instant::now());
    let Some(current) = guard.current.get(&attendance) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if current.document_id != document_id || current.document_incarnation != document_incarnation {
        return Ok(envelope(
            false,
            "caduceus-attendance-document-incarnation-mismatch",
        ));
    }
    guard.current.remove(&attendance);
    Ok(envelope(true, "none"))
}

pub fn admits(attendance: &str, document_id: &str, document_incarnation: &str) -> bool {
    state().lock().ok().is_some_and(|mut guard| {
        evict_expired(&mut guard.current, Instant::now());
        guard.current.get(attendance).is_some_and(|current| {
            current.document_id == document_id
                && current.document_incarnation == document_incarnation
        })
    })
}

/// Admit an exact document target for a standalone Caduceus mutation.
/// The attendance was already PIN-verified when opened and remains inactivity-bounded.
pub fn admits_target(attendance: &str, document_id: &str) -> bool {
    state().lock().ok().is_some_and(|mut guard| {
        evict_expired(&mut guard.current, Instant::now());
        guard
            .current
            .get(attendance)
            .is_some_and(|current| current.document_id == document_id)
    })
}

pub fn reset_for_tests() {
    if let Ok(mut guard) = state().lock() {
        guard.current.clear();
        guard.verifier = None;
    }
}
