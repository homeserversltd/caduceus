use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

const ATTENDANCE_INACTIVITY_LIMIT: Duration = Duration::from_secs(15 * 60);
const FIREWALL_DOCUMENT_TARGET: &str = "/api/v1/network/firewall/policies/{mac}";
const AGENT_SERVICE_DOCUMENT_TARGETS: &[(&str, &str)] = &[
    ("status", "/api/v1/appliance/service/{service}/status"),
    ("start", "/api/v1/appliance/service/{service}/start"),
    ("stop", "/api/v1/appliance/service/{service}/stop"),
    ("restart", "/api/v1/appliance/service/{service}/restart"),
    ("enable", "/api/v1/appliance/service/{service}/enable"),
    ("disable", "/api/v1/appliance/service/{service}/disable"),
];
const FILE_INGRESS_DOCUMENT_TARGETS: &[&str] = &[
    "/api/v1/file/ingress/start",
    "/api/v1/file/ingress/{upload_id}/chunk/{index}",
    "/api/v1/file/ingress/{upload_id}/complete",
    "/api/v1/file/ingress/{upload_id}",
];
const NETWORK_DNS_DOCUMENT_TARGETS: &[&str] = &[
    "/api/v1/network/dns/device-name/create",
    "/api/v1/network/dns/device-name/remove",
    "/api/v1/network/dns/adblock",
    "/api/v1/network/dns/blocklist/update",
    "/api/v1/network/dns/upstream",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttendanceOrigin {
    BrowserUnix,
    BrowserUntrusted,
    DirectPin,
    AgentPin,
    DerivedChild,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DerivationScope {
    Firewall,
    PortalService,
    FileIngress,
    NetworkDns,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Attendance {
    document_id: String,
    document_incarnation: String,
    origin: AttendanceOrigin,
    derivation_scope: Option<DerivationScope>,
    created_at: Instant,
    last_touch: Instant,
}

#[derive(Default)]
struct AttendanceState {
    current: HashMap<String, Attendance>,
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

pub(crate) fn text(body: &Value, field: &str) -> Result<String, String> {
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

pub fn pin_mode_json() -> Value {
    let pin_required = crate::shared::config::get_json("global.admin.pin_required")
        .ok()
        .and_then(|value| value.get("value").and_then(Value::as_bool))
        .unwrap_or(false);
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
    crate::shared::config::patch_json(json!({
        "global": {"admin": {"pin_required": pin_required}}
    }))
    .map_err(|_| "caduceus-access-pin-mode-unavailable".to_string())?;
    Ok(pin_mode_json())
}

pub fn sudo_mode_json() -> Value {
    let passwordless_sudo = crate::shared::config::get_json("global.admin.passwordless_sudo")
        .ok()
        .and_then(|value| value.get("value").and_then(Value::as_bool))
        .unwrap_or(false);
    json!({
        "schema": "caduceus.access.sudo.mode.v1",
        "ok": true,
        "passwordless_sudo": passwordless_sudo,
        "firstMissingSignal": "none",
    })
}

fn sudo_mode_refusal(wrapper: &Value, fallback: &str) -> String {
    wrapper
        .get("receiptPayload")
        .and_then(|receipt| receipt.get("firstMissingSignal"))
        .and_then(Value::as_str)
        .filter(|signal| !signal.is_empty() && *signal != "none")
        .or_else(|| {
            wrapper
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .filter(|signal| !signal.is_empty() && *signal != "none")
        })
        .unwrap_or(fallback)
        .to_string()
}

pub fn set_sudo_mode_json(body: &Value) -> Result<Value, String> {
    let object = body
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or_else(|| "caduceus-access-sudo-mode-invalid".to_string())?;
    let passwordless_sudo = object
        .get("passwordless_sudo")
        .and_then(Value::as_bool)
        .ok_or_else(|| "caduceus-access-sudo-mode-invalid".to_string())?;
    crate::shared::config::patch_json(json!({
        "global": {"admin": {"passwordless_sudo": passwordless_sudo}}
    }))
    .map_err(|_| "caduceus-access-sudo-mode-unavailable".to_string())?;

    // Keep the local switch even when the staff band refuses; the next POST retries it.
    let band = "appliance/sudo-passwordless";
    let envelope = json!({
        "schema": crate::protocol::SCHEMA_ID,
        "intent_id": format!("caduceus-{band}"),
        "transition": band,
        "origin_of_intent": "near",
        "payload": {"passwordless": passwordless_sudo},
    });
    let refusal = "caduceus-sudo-passwordless-result-unobserved";
    let wrapper = crate::gate::snake::run(band, &envelope)?;
    if wrapper.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(sudo_mode_refusal(&wrapper, refusal));
    }
    let Some(receipt) = wrapper.get("receiptPayload") else {
        return Err(sudo_mode_refusal(&wrapper, refusal));
    };
    if receipt.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(sudo_mode_refusal(&wrapper, refusal));
    }
    if receipt.get("schema").and_then(Value::as_str)
        != Some("agathodaimon.appliance.sudo-passwordless.v1")
    {
        return Err(sudo_mode_refusal(
            &wrapper,
            "caduceus-sudo-passwordless-receipt-schema-unobserved",
        ));
    }
    let Some(echoed_passwordless) = receipt.get("passwordless").and_then(Value::as_bool) else {
        return Err(sudo_mode_refusal(
            &wrapper,
            "caduceus-sudo-passwordless-switch-unobserved",
        ));
    };
    if echoed_passwordless != passwordless_sudo {
        return Err(sudo_mode_refusal(
            &wrapper,
            "caduceus-sudo-passwordless-switch-mismatch",
        ));
    }
    let Some(fragment_present) = receipt.get("fragment_present").and_then(Value::as_bool) else {
        return Err(sudo_mode_refusal(
            &wrapper,
            "caduceus-sudo-passwordless-fragment-presence-unobserved",
        ));
    };
    if fragment_present != passwordless_sudo {
        return Err(sudo_mode_refusal(
            &wrapper,
            "caduceus-sudo-passwordless-fragment-presence-mismatch",
        ));
    }
    let Some(changed) = receipt.get("changed").and_then(Value::as_bool) else {
        return Err(sudo_mode_refusal(
            &wrapper,
            "caduceus-sudo-passwordless-change-unobserved",
        ));
    };
    Ok(json!({
        "schema": "caduceus.access.sudo.mode.v1",
        "ok": true,
        "passwordless_sudo": passwordless_sudo,
        "fragment_present": fragment_present,
        "changed": changed,
        "firstMissingSignal": "none",
    }))
}

const PIN_NOT_PROVISIONED: &str = "caduceus-pin-not-yet-provisioned";
const PIN_DEFAULT_RESET_FAILED: &str = "caduceus-pin-default-reset-failed";

/// Read the live PIN seat for each operation; never cache or delegate verification.
fn configured_pin() -> Result<String, String> {
    let value = crate::shared::config::get_json("global.admin.pin")
        .map_err(|_| PIN_NOT_PROVISIONED.to_string())?;
    value
        .get("value")
        .and_then(Value::as_str)
        .filter(|pin| !pin.is_empty() && pin.len() <= 512)
        .map(str::to_string)
        .ok_or_else(|| PIN_NOT_PROVISIONED.to_string())
}

fn pin_matches(pin: &str) -> Result<bool, String> {
    Ok(pin == configured_pin()?)
}

/// Startup posture is the live config seat, independent of staff or signer material.
pub fn bind() {
    let (posture, signal) = if configured_pin().is_ok() {
        ("BOUND", "none")
    } else {
        ("UNBOUND", PIN_NOT_PROVISIONED)
    };
    eprintln!(
        "{}",
        json!({
            "event": "caduceus-access-bind",
            "posture": posture,
            "firstMissingSignal": signal,
        })
    );
}

pub(crate) fn verify_administrative_pin(pin: &str) -> Result<(), String> {
    if pin.is_empty() || pin.len() > 512 {
        return Err("caduceus-administrative-pin-required".to_string());
    }
    if pin_matches(pin)? {
        Ok(())
    } else {
        Err("caduceus-administrative-pin-wrong".to_string())
    }
}

fn open_verified_json(body: &Value, origin: AttendanceOrigin) -> Result<Value, String> {
    let document_id = text(body, "documentId")?;
    let document_incarnation = text(body, "documentIncarnation")?;
    let pin = text(body, "pin")?;
    if !pin_matches(&pin)? {
        return Ok(envelope(false, "caduceus-attendance-pin-wrong"));
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
            origin,
            derivation_scope: None,
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

pub fn open_json(body: &Value) -> Result<Value, String> {
    open_verified_json(body, AttendanceOrigin::DirectPin)
}

fn agent_target(body: &Value) -> Result<(String, String, String, String), String> {
    let envelope = crate::protocol::Envelope::parse(body.clone())?;
    if envelope.transition() != "exousia.open" {
        return Err("caduceus-attendance-transition-invalid".to_string());
    }
    let target = body
        .get("target")
        .and_then(Value::as_object)
        .ok_or_else(|| "caduceus-attendance-target-missing".to_string())?;
    let document = target
        .get("document")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-attendance-target-document-missing".to_string())?;
    let service = target
        .get("service")
        .and_then(Value::as_str)
        .filter(|value| crate::routes::control_service::safe_service_name(value))
        .ok_or_else(|| "caduceus-attendance-target-service-invalid".to_string())?;
    let action = target
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-attendance-target-action-missing".to_string())?;
    let canonical = AGENT_SERVICE_DOCUMENT_TARGETS
        .iter()
        .find(|(candidate, _)| *candidate == action)
        .map(|(_, document)| *document)
        .ok_or_else(|| "caduceus-attendance-target-action-invalid".to_string())?;
    if document != canonical {
        return Err("caduceus-attendance-target-document-invalid".to_string());
    }
    let pin = body
        .pointer("/flags/exousia/pin")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 512)
        .ok_or_else(|| "caduceus-attendance-pin-missing".to_string())?;
    Ok((
        document.to_string(),
        service.to_string(),
        action.to_string(),
        pin.to_string(),
    ))
}

fn derivation_scope(document: &str) -> Option<DerivationScope> {
    if document == FIREWALL_DOCUMENT_TARGET {
        Some(DerivationScope::Firewall)
    } else if AGENT_SERVICE_DOCUMENT_TARGETS
        .iter()
        .any(|(_, candidate)| *candidate == document)
    {
        Some(DerivationScope::PortalService)
    } else if FILE_INGRESS_DOCUMENT_TARGETS
        .iter()
        .any(|candidate| *candidate == document)
    {
        Some(DerivationScope::FileIngress)
    } else if NETWORK_DNS_DOCUMENT_TARGETS
        .iter()
        .any(|candidate| *candidate == document)
    {
        Some(DerivationScope::NetworkDns)
    } else {
        None
    }
}

fn derive_browser_child_json(
    parent: &str,
    document_id: &str,
    document_incarnation: &str,
    target_document: &str,
) -> Result<Value, String> {
    let Some(scope) = derivation_scope(target_document) else {
        return Ok(envelope(false, "caduceus-attendance-target-not-derivable"));
    };
    let now = Instant::now();
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    evict_expired(&mut guard.current, now);
    let Some(parent_attendance) = guard.current.get_mut(parent) else {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    };
    if parent_attendance.origin != AttendanceOrigin::BrowserUnix
        || parent_attendance.document_id != document_id
        || parent_attendance.document_incarnation != document_incarnation
    {
        return Ok(envelope(false, "caduceus-attendance-not-current"));
    }
    if let Some(bound_scope) = parent_attendance.derivation_scope {
        if bound_scope != scope {
            return Ok(envelope(
                false,
                "caduceus-attendance-derivation-scope-mismatch",
            ));
        }
    } else {
        parent_attendance.derivation_scope = Some(scope);
    }
    let attendance = format!("attendance-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed));
    guard.current.insert(
        attendance.clone(),
        Attendance {
            document_id: target_document.to_string(),
            document_incarnation: target_document.to_string(),
            origin: AttendanceOrigin::DerivedChild,
            derivation_scope: None,
            created_at: now,
            last_touch: now,
        },
    );
    let mut result = envelope(true, "none");
    result["attendance"] = Value::String(attendance);
    result["documentId"] = Value::String(target_document.to_string());
    result["documentIncarnation"] = Value::String(target_document.to_string());
    Ok(result)
}

pub fn open_request_json(body: &Value, trusted_unix_carrier: bool) -> Result<Value, String> {
    if body.get("schema").and_then(Value::as_str) == Some("caduceus.staff.v1") {
        if body.pointer("/flags/exousia/attendance").is_some() {
            let parsed = crate::protocol::Envelope::parse(body.clone())?;
            if parsed.transition() != "exousia.open" {
                return Err("caduceus-attendance-transition-invalid".to_string());
            }
            let parent = body
                .pointer("/flags/exousia/attendance")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 512)
                .ok_or_else(|| "caduceus-attendance-attendance-missing".to_string())?;
            let document_id = body
                .pointer("/flags/exousia/documentId")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 512)
                .ok_or_else(|| "caduceus-attendance-documentId-missing".to_string())?;
            let document_incarnation = body
                .pointer("/flags/exousia/documentIncarnation")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 512)
                .ok_or_else(|| "caduceus-attendance-documentIncarnation-missing".to_string())?;
            let target_document = body
                .pointer("/target/document")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty() && value.len() <= 512)
                .ok_or_else(|| "caduceus-attendance-target-document-missing".to_string())?;
            if !trusted_unix_carrier {
                return Ok(envelope(false, "caduceus-attendance-derivation-untrusted"));
            }
            derive_browser_child_json(parent, document_id, document_incarnation, target_document)
        } else {
            let (document, service, action, pin) = agent_target(body)?;
            if !pin_matches(&pin)? {
                return Ok(envelope(false, "caduceus-attendance-pin-wrong"));
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
                    document_id: document.clone(),
                    document_incarnation: document.clone(),
                    origin: AttendanceOrigin::AgentPin,
                    derivation_scope: None,
                    created_at: now,
                    last_touch: now,
                },
            );
            let mut result = envelope(true, "none");
            result["attendance"] = Value::String(attendance);
            result["documentId"] = Value::String(document.clone());
            result["documentIncarnation"] = Value::String(document);
            result["target"] = json!({"service": service, "action": action});
            Ok(result)
        }
    } else {
        open_verified_json(
            body,
            if trusted_unix_carrier {
                AttendanceOrigin::BrowserUnix
            } else {
                AttendanceOrigin::BrowserUntrusted
            },
        )
    }
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
    if !pin_matches(&current_pin)? {
        return Ok(envelope(false, "caduceus-attendance-pin-wrong"));
    }
    if crate::shared::config::set_json("global.admin.pin", Value::String(new_pin)).is_err() {
        return Ok(envelope(false, "caduceus-attendance-change-failed"));
    }

    guard.current.retain(|key, _| key == &attendance);
    if let Some(current) = guard.current.get_mut(&attendance) {
        current.last_touch = now;
    }
    Ok(envelope(true, "none"))
}

fn provisioned_default_pin() -> Result<String, String> {
    let path = crate::shared::config::path("/etc/appliance/config.factory");
    let text = fs::read_to_string(path).map_err(|_| PIN_DEFAULT_RESET_FAILED.to_string())?;
    let document: Value =
        serde_json::from_str(&text).map_err(|_| PIN_DEFAULT_RESET_FAILED.to_string())?;
    document
        .pointer("/global/admin/pin")
        .and_then(Value::as_str)
        .filter(|pin| !pin.is_empty() && pin.len() <= 512)
        .map(str::to_string)
        .ok_or_else(|| PIN_DEFAULT_RESET_FAILED.to_string())
}

pub fn reset_default_pin_json(_body: &Value) -> Result<Value, String> {
    // The request shape remains; the provisioned factory seat is the only reset value.
    let default_pin = provisioned_default_pin()?;
    let mut guard = state()
        .lock()
        .map_err(|_| "caduceus-attendance-unavailable".to_string())?;
    crate::shared::config::set_json("global.admin.pin", Value::String(default_pin))
        .map_err(|_| PIN_DEFAULT_RESET_FAILED.to_string())?;
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

pub fn posture_json() -> Result<Value, String> {
    let bound = configured_pin().is_ok();
    let posture = if bound { "BOUND" } else { "UNBOUND" };
    // These schema fields describe retired signer-derived verifier material and stay false.
    Ok(json!({
        "schema": "caduceus.exousia.posture.v1",
        "ok": true,
        "posture": posture,
        "bound": bound,
        "storedVerifierPresent": false,
        "currentPresent": false,
        "epochMatches": false,
    }))
}

pub fn reset_for_tests() {
    if let Ok(mut guard) = state().lock() {
        guard.current.clear();
    }
}
