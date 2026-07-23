use crate::tools::config;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    Unsigned,
    Expired,
    Scope,
    Malformed,
    Profile(String),
}

impl Reason {
    pub fn signal(&self) -> &'static str {
        match self {
            Reason::Unsigned => "caduceus-capability-unsigned",
            Reason::Expired => "caduceus-capability-expired",
            Reason::Scope => "caduceus-capability-scope",
            Reason::Malformed => "caduceus-capability-malformed",
            Reason::Profile(_) => "caduceus-profile-missing",
        }
    }
}

#[derive(Debug, Deserialize)]
struct CapabilityPayload {
    actor: String,
    action: String,
    target: String,
    exp: u64,
}

pub fn load_profile_value() -> Result<Value, String> {
    config::read_public_profile_value()
}

pub fn allows_command(command: &str) -> Result<bool, String> {
    let profile = load_profile_value()?;
    let Some(commands) = profile.get("commands").and_then(Value::as_array) else {
        return Ok(false);
    };
    Ok(commands
        .iter()
        .filter_map(Value::as_str)
        .any(|allowed| allowed == command))
}

pub fn capability_admits(command: &str, target: &str, token: Option<&str>) -> Result<(), Reason> {
    let token = token
        .filter(|token| !token.trim().is_empty())
        .ok_or(Reason::Unsigned)?;
    let verifying_key = household_verifying_key()?;
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(Reason::Malformed)?;
    if sig_b64.contains('.') {
        return Err(Reason::Malformed);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| Reason::Malformed)?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| Reason::Malformed)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| Reason::Malformed)?;
    verifying_key
        .verify_strict(&payload, &signature)
        .map_err(|_| Reason::Unsigned)?;
    let payload: CapabilityPayload =
        serde_json::from_slice(&payload).map_err(|_| Reason::Malformed)?;
    let now = now_epoch_seconds()?;
    if payload.exp <= now {
        return Err(Reason::Expired);
    }
    if payload.actor.is_empty() || payload.action != command || payload.target != target {
        return Err(Reason::Scope);
    }
    Ok(())
}

fn now_epoch_seconds() -> Result<u64, Reason> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Reason::Malformed)
}

fn household_verifying_key() -> Result<VerifyingKey, Reason> {
    let profile = load_profile_value().map_err(Reason::Profile)?;
    let key_text = household_verifying_key_text(&profile).ok_or(Reason::Unsigned)?;
    let key_bytes = decode_key_material(key_text).ok_or(Reason::Malformed)?;
    let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| Reason::Malformed)?;
    VerifyingKey::from_bytes(&key_bytes).map_err(|_| Reason::Malformed)
}

fn household_verifying_key_text(profile: &Value) -> Option<&str> {
    [
        profile.get("household_verifying_key"),
        profile.get("householdVerifyingKey"),
        profile
            .get("capability")
            .and_then(|capability| capability.get("household_verifying_key")),
        profile
            .get("capability")
            .and_then(|capability| capability.get("householdVerifyingKey")),
        profile
            .get("appliance_keyman")
            .and_then(|keyman| keyman.get("household_verifying_key")),
        profile
            .get("applianceKeyman")
            .and_then(|keyman| keyman.get("householdVerifyingKey")),
    ]
    .into_iter()
    .flatten()
    .filter_map(Value::as_str)
    .find(|value| !value.trim().is_empty())
}

fn decode_key_material(text: &str) -> Option<Vec<u8>> {
    let text = text.trim();
    decode_hex(text)
        .or_else(|| STANDARD.decode(text).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(text).ok())
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    let hex = text.strip_prefix("0x").unwrap_or(text);
    if hex.len() % 2 != 0 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let pair = std::str::from_utf8(pair).ok()?;
        bytes.push(u8::from_str_radix(pair, 16).ok()?);
    }
    Some(bytes)
}
