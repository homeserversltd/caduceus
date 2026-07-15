use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub const SESSION_SECONDS: u64 = 1800;
pub const CAPABILITY_SECONDS: u64 = 60;
pub const DIAGNOSTIC_TTL_SECONDS: u64 = 15 * 60;
pub const DIAGNOSTIC_LIMIT: usize = 128;

pub trait Clock: Send + Sync {
    fn now(&self) -> u64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

#[derive(Clone)]
struct Projection {
    key: VerifyingKey,
    epoch: u64,
}

#[derive(Clone)]
pub struct AccessState {
    pub clock: Arc<dyn Clock>,
    consumed: Arc<Mutex<HashSet<String>>>,
    projection: Arc<Mutex<Option<Projection>>>,
    diagnostics: Arc<Mutex<VecDeque<DiagnosticEvent>>>,
}

impl Default for AccessState {
    fn default() -> Self {
        Self {
            clock: Arc::new(SystemClock),
            consumed: Arc::new(Mutex::new(HashSet::new())),
            projection: Arc::new(Mutex::new(None)),
            diagnostics: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

impl AccessState {
    pub fn install_public_projection(&self, text: &str, epoch: u64) -> Result<(), AccessReason> {
        let bytes = decode_hex(text).ok_or(AccessReason::Malformed)?;
        let key = VerifyingKey::from_bytes(&bytes.try_into().map_err(|_| AccessReason::Malformed)?)
            .map_err(|_| AccessReason::Malformed)?;
        *self
            .projection
            .lock()
            .map_err(|_| AccessReason::Unavailable)? = Some(Projection { key, epoch });
        self.consumed
            .lock()
            .map_err(|_| AccessReason::Unavailable)?
            .clear();
        Ok(())
    }

    pub fn has_projection(&self) -> Result<bool, AccessReason> {
        Ok(self
            .projection
            .lock()
            .map_err(|_| AccessReason::Unavailable)?
            .is_some())
    }

    pub fn verify_and_consume(
        &self,
        token: &str,
        action: &str,
        target: &str,
        profile: &str,
    ) -> Result<(), AccessReason> {
        let (payload64, signature64) = token.split_once('.').ok_or(AccessReason::Malformed)?;
        if signature64.contains('.') {
            return Err(AccessReason::Malformed);
        }
        let payload = URL_SAFE_NO_PAD
            .decode(payload64)
            .map_err(|_| AccessReason::Malformed)?;
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(signature64)
                .map_err(|_| AccessReason::Malformed)?,
        )
        .map_err(|_| AccessReason::Malformed)?;
        let projection = self
            .projection
            .lock()
            .map_err(|_| AccessReason::Unavailable)?
            .clone()
            .ok_or(AccessReason::Unsigned)?;
        projection
            .key
            .verify_strict(&payload, &signature)
            .map_err(|_| AccessReason::Unsigned)?;
        let capability: Capability =
            serde_json::from_slice(&payload).map_err(|_| AccessReason::Malformed)?;
        if capability.exp <= self.clock.now() {
            return Err(AccessReason::Expired);
        }
        if capability.action != action
            || capability.target != target
            || capability.profile != profile
        {
            return Err(AccessReason::Scope);
        }
        if capability.epoch != projection.epoch {
            return Err(AccessReason::StaleEpoch);
        }
        if capability.id.is_empty() {
            return Err(AccessReason::Malformed);
        }
        let mut consumed = self
            .consumed
            .lock()
            .map_err(|_| AccessReason::Unavailable)?;
        if !consumed.insert(capability.id) {
            return Err(AccessReason::Replay);
        }
        Ok(())
    }

    pub fn record_diagnostic(&self, event: DiagnosticEvent) {
        let now = self.clock.now();
        if let Ok(mut events) = self.diagnostics.lock() {
            events.retain(|item| item.observed_at.saturating_add(DIAGNOSTIC_TTL_SECONDS) > now);
            events.push_back(event);
            while events.len() > DIAGNOSTIC_LIMIT {
                events.pop_front();
            }
        }
    }

    #[cfg(test)]
    pub fn diagnostics(&self) -> Vec<DiagnosticEvent> {
        self.diagnostics
            .lock()
            .map(|items| items.iter().cloned().collect())
            .unwrap_or_default()
    }
}

#[derive(Deserialize)]
struct Capability {
    id: String,
    action: String,
    target: String,
    profile: String,
    epoch: u64,
    exp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessReason {
    Unsigned,
    Expired,
    Scope,
    Malformed,
    Replay,
    StaleEpoch,
    Unavailable,
    Session,
}

impl AccessReason {
    pub fn signal(&self) -> &'static str {
        match self {
            Self::Unsigned => "caduceus-capability-unsigned",
            Self::Expired => "caduceus-capability-expired",
            Self::Scope => "caduceus-capability-scope",
            Self::Malformed => "caduceus-capability-malformed",
            Self::Replay => "caduceus-capability-replay",
            Self::StaleEpoch => "caduceus-capability-stale-epoch",
            Self::Unavailable => "caduceus-staff-unavailable",
            Self::Session => "caduceus-session-invalid",
        }
    }
}

fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
        .collect()
}

#[derive(Clone, Debug, Serialize)]
pub struct DiagnosticEvent {
    pub section: &'static str,
    pub correlation_id: String,
    pub phase: String,
    pub outcome: &'static str,
    pub duration_ms: u128,
    pub first_missing_signal: String,
    pub observed_at: u64,
}

impl DiagnosticEvent {
    pub fn new(
        section: &'static str,
        correlation_id: &str,
        phase: &str,
        outcome: &'static str,
        duration: Instant,
        signal: &str,
        observed_at: u64,
    ) -> Self {
        Self {
            section,
            correlation_id: safe_correlation(correlation_id),
            phase: phase.to_string(),
            outcome,
            duration_ms: duration.elapsed().as_millis(),
            first_missing_signal: signal.to_string(),
            observed_at,
        }
    }
}

fn safe_correlation(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
        .take(128)
        .collect()
}

/// One transient request/reply over Harmonia's root-only private staff socket.
/// The request may contain a PIN or ticket, but no request is persisted or logged.
pub fn staff_request(
    socket_path: &Path,
    request: &serde_json::Value,
) -> Result<serde_json::Value, AccessReason> {
    let mut stream = UnixStream::connect(socket_path).map_err(|_| AccessReason::Unavailable)?;
    let encoded = serde_json::to_vec(request).map_err(|_| AccessReason::Malformed)?;
    stream
        .write_all(&encoded)
        .map_err(|_| AccessReason::Unavailable)?;
    stream
        .write_all(b"\n")
        .map_err(|_| AccessReason::Unavailable)?;
    let mut line = String::new();
    BufReader::new(stream)
        .read_line(&mut line)
        .map_err(|_| AccessReason::Unavailable)?;
    serde_json::from_str(&line).map_err(|_| AccessReason::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;

    struct TestClock(AtomicU64);
    impl Clock for TestClock {
        fn now(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }
    fn signed(
        seed: [u8; 32],
        id: &str,
        action: &str,
        target: &str,
        profile: &str,
        epoch: u64,
        exp: u64,
    ) -> String {
        let key = SigningKey::from_bytes(&seed);
        let payload = serde_json::json!({"id":id,"action":action,"target":target,"profile":profile,"epoch":epoch,"exp":exp});
        let bytes = serde_json::to_vec(&payload).unwrap();
        format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(&bytes),
            URL_SAFE_NO_PAD.encode(key.sign(&bytes).to_bytes())
        )
    }
    #[test]
    fn consumes_once_and_refuses_wrong_scope_expiry_epoch_unsigned_and_malformed() {
        let seed = [7; 32];
        let key = SigningKey::from_bytes(&seed);
        let state = AccessState {
            clock: Arc::new(TestClock(AtomicU64::new(100))),
            ..Default::default()
        };
        state
            .install_public_projection(
                &key.verifying_key()
                    .to_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                3,
            )
            .unwrap();
        let ok = signed(seed, "once", "update now", "local", "homeserver", 3, 160);
        assert_eq!(
            state.verify_and_consume(&ok, "update now", "local", "homeserver"),
            Ok(())
        );
        assert_eq!(
            state.verify_and_consume(&ok, "update now", "local", "homeserver"),
            Err(AccessReason::Replay)
        );
        assert_eq!(
            state.verify_and_consume(
                &signed(seed, "scope", "other", "local", "homeserver", 3, 160),
                "update now",
                "local",
                "homeserver"
            ),
            Err(AccessReason::Scope)
        );
        assert_eq!(
            state.verify_and_consume(
                &signed(seed, "expired", "update now", "local", "homeserver", 3, 100),
                "update now",
                "local",
                "homeserver"
            ),
            Err(AccessReason::Expired)
        );
        assert_eq!(
            state.verify_and_consume(
                &signed(seed, "epoch", "update now", "local", "homeserver", 2, 160),
                "update now",
                "local",
                "homeserver"
            ),
            Err(AccessReason::StaleEpoch)
        );
        assert_eq!(
            state.verify_and_consume("invalid", "update now", "local", "homeserver"),
            Err(AccessReason::Malformed)
        );
    }
    #[test]
    fn concurrent_replay_has_exactly_one_winner() {
        let seed = [9; 32];
        let key = SigningKey::from_bytes(&seed);
        let state = AccessState {
            clock: Arc::new(TestClock(AtomicU64::new(100))),
            ..Default::default()
        };
        state
            .install_public_projection(
                &key.verifying_key()
                    .to_bytes()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>(),
                1,
            )
            .unwrap();
        let token = signed(seed, "race", "update now", "local", "homeserver", 1, 160);
        let a = state.clone();
        let b = state.clone();
        let token_left = token.clone();
        let left = thread::spawn(move || {
            a.verify_and_consume(&token_left, "update now", "local", "homeserver")
                .is_ok()
        });
        let right = thread::spawn(move || {
            b.verify_and_consume(&token, "update now", "local", "homeserver")
                .is_ok()
        });
        assert_eq!(left.join().unwrap() as u8 + right.join().unwrap() as u8, 1);
    }
    #[test]
    fn diagnostics_are_bounded_redacted_and_expire() {
        let state = AccessState {
            clock: Arc::new(TestClock(AtomicU64::new(100))),
            ..Default::default()
        };
        state.record_diagnostic(DiagnosticEvent::new(
            "access.session",
            "ticket-secret",
            "mint",
            "refused",
            Instant::now(),
            "caduceus-session-invalid",
            100,
        ));
        let rendered = serde_json::to_string(&state.diagnostics()).unwrap();
        assert!(!rendered.contains("PIN"));
        assert!(!rendered.contains("capability"));
        for n in 0..(DIAGNOSTIC_LIMIT + 5) {
            state.record_diagnostic(DiagnosticEvent::new(
                "access.capability",
                &format!("id-{n}"),
                "mint",
                "ok",
                Instant::now(),
                "none",
                100,
            ));
        }
        assert_eq!(state.diagnostics().len(), DIAGNOSTIC_LIMIT);
    }
}
