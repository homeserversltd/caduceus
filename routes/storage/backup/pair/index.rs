// HomeServer backup-box pairing. The request carries only the digest.
use axum::extract::OriginalUri;
use axum::{extract::ConnectInfo, http::StatusCode, response::{IntoResponse, Response}, Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::{io::Write, process::{Command, Stdio}, time::{Instant, SystemTime, UNIX_EPOCH}};

// A report and its generation are serialized under this mutex. Waiters read
// the store only after a changed generation, never on a timer.
type WakeMap = std::collections::HashMap<String, (u64, Instant)>;
static REPORT_WAKE: std::sync::OnceLock<(std::sync::Mutex<WakeMap>, std::sync::Condvar)> = std::sync::OnceLock::new();
fn report_wake() -> &'static (std::sync::Mutex<WakeMap>, std::sync::Condvar) {
    REPORT_WAKE.get_or_init(|| (std::sync::Mutex::new(WakeMap::new()), std::sync::Condvar::new()))
}

pub(crate) struct ConductorPair { pub mac: String, pub hostname: String, pub inlet_name: Option<String> }
pub(crate) struct ConductorReport { pub outcome: String, pub signal: String }

// Ask the existing schema door's startup registry, rather than carrying a
// second copy of the pull seat. A missing or unusable seat fails closed.
fn pull_signal_seat() -> Option<&'static Value> {
    static SEAT: std::sync::OnceLock<Option<Value>> = std::sync::OnceLock::new();
    SEAT.get_or_init(|| {
        use tower::ServiceExt;
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().ok()?;
        runtime.block_on(async {
            let request = axum::http::Request::builder().uri("/api/v1/schema/intents/storage/backup/mirror/pull").body(axum::body::Body::empty()).ok()?;
            let response = crate::routes::leaf_schema::register(Router::new()).oneshot(request).await.ok()?;
            if !response.status().is_success() { return None; }
            let bytes = axum::body::to_bytes(response.into_body(), 65536).await.ok()?;
            serde_json::from_slice::<Value>(&bytes).ok()
        })
    }).as_ref()
}

// The seat uses JSON Schema regular expressions. Translate noncapturing
// groups to POSIX ERE; unsupported extensions fail closed rather than being
// interpreted as a broader expression.
fn declared_pattern(pattern: &str, value: &str) -> bool {
    let translated = pattern.replace("(?:", "(");
    if translated.contains("(?") || translated.contains('\\') { return false; }
    let (Ok(pattern), Ok(value)) = (std::ffi::CString::new(translated), std::ffi::CString::new(value)) else { return false; };
    unsafe {
        let mut compiled: libc::regex_t = std::mem::zeroed();
        if libc::regcomp(&mut compiled, pattern.as_ptr(), libc::REG_EXTENDED | libc::REG_NOSUB) != 0 { return false; }
        let matched = libc::regexec(&compiled, value.as_ptr(), 0, std::ptr::null_mut(), 0) == 0;
        libc::regfree(&mut compiled);
        matched
    }
}

fn report_signal(value: &str) -> &str {
    if matches!(value, "none" | "pull-failed" | "kernel-error-on-backup-drive") { return value; }
    let allowed = pull_signal_seat().and_then(|seat| seat.pointer("/returns/firstMissingSignal/anyOf"))
        .and_then(Value::as_array).is_some_and(|rules| rules.iter().any(|rule| {
            rule.get("enum").and_then(Value::as_array).is_some_and(|items| items.iter().any(|item| item.as_str() == Some(value)))
                || rule.get("pattern").and_then(Value::as_str).is_some_and(|pattern| declared_pattern(pattern,value))
        }));
    if allowed { value } else { "box-signal-undeclared" }
}

pub(crate) fn conductor_pairs() -> Result<Vec<ConductorPair>, String> {
    with_db(|db| {
        let mut q = db.prepare("SELECT mac,hostname,inlet_name FROM backup_pairs WHERE state='accepted' ORDER BY accepted_at,mac").map_err(|_| UNAVAILABLE)?;
        let rows = q.query_map([], |r| Ok(ConductorPair { mac:r.get(0)?, hostname:r.get::<_,Option<String>>(1)?.unwrap_or_default(), inlet_name:r.get(2)? })).map_err(|_| UNAVAILABLE)?;
        rows.collect::<Result<Vec<_>,_>>().map_err(|_| UNAVAILABLE)
    }).map_err(|_| "backup-pair-unavailable".into())
}

pub(crate) fn report_counter(mac: &str) -> Result<u64, String> {
    let guard = report_wake().0.lock().map_err(|_| "backup-pair-unavailable")?;
    Ok(guard.get(mac).map_or(0, |row| row.0))
}

pub(crate) fn wait_report(mac: &str, mut seen: u64, started: i64, act_started: Instant, deadline: Instant) -> Result<Option<ConductorReport>, String> {
    let (mutex, wake) = report_wake();
    let mut guard = mutex.lock().map_err(|_| "backup-pair-unavailable")?;
    loop {
        if let Some(&(generation, committed)) = guard.get(mac) {
            if generation != seen {
                seen = generation;
                if committed >= act_started {
                    let report = with_db(|db| {
                        db.query_row("SELECT report_outcome,report_signal,report_received_at FROM backup_pairs WHERE mac=?1 AND state='accepted'", [mac], |r| Ok((r.get::<_,Option<String>>(0)?,r.get::<_,Option<String>>(1)?,r.get::<_,Option<i64>>(2)?))).optional().map_err(|_| UNAVAILABLE)
                    }).map_err(|_| "backup-pair-unavailable")?;
                    if let Some((Some(outcome),Some(signal),Some(received))) = report {
                        if received >= started { return Ok(Some(ConductorReport { outcome, signal })); }
                    }
                }
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() { return Ok(None); }
        let (next, _) = wake.wait_timeout(guard, remaining).map_err(|_| "backup-pair-unavailable")?;
        guard = next;
    }
}

type Failure = (StatusCode, &'static str);
const UNAVAILABLE: Failure = (StatusCode::SERVICE_UNAVAILABLE, "backup-pair-unavailable");
const INVALID: Failure = (StatusCode::BAD_REQUEST, "backup-pair-invalid");
const UNKNOWN: Failure = (StatusCode::UNAUTHORIZED, "backup-pair-unknown");

fn initialize(db: &Connection) -> Result<(), Failure> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS backup_pairs (mac TEXT PRIMARY KEY, hostname TEXT, ipv4 TEXT, credential_sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','accepted')), requested_at INTEGER NOT NULL, accepted_at INTEGER);").map_err(|_| UNAVAILABLE)?;
    let mut stmt = db.prepare("PRAGMA table_info(backup_pairs)").map_err(|_| UNAVAILABLE)?;
    let columns = stmt.query_map([], |r| r.get::<_, String>(1)).map_err(|_| UNAVAILABLE)?
        .collect::<Result<Vec<_>, _>>().map_err(|_| UNAVAILABLE)?;
    for (name, ty) in [("inlet_name", "TEXT"), ("report_outcome", "TEXT"), ("report_signal", "TEXT"), ("report_at", "TEXT"), ("report_duration_ms", "INTEGER"), ("report_received_at", "INTEGER")] {
        if !columns.iter().any(|c| c == name) {
            db.execute_batch(&format!("ALTER TABLE backup_pairs ADD COLUMN {name} {ty}")).map_err(|_| UNAVAILABLE)?;
        }
    }
    Ok(())
}

fn with_db<T>(action: impl FnOnce(&mut Connection) -> Result<T, Failure>) -> Result<T, Failure> {
    match crate::stats::open_db() {
        Ok(shared) => {
            let mut db = shared.lock().map_err(|_| UNAVAILABLE)?;
            initialize(&db)?;
            action(&mut db)
        }
        Err(_) => {
            // The shared stats opener caches an initial failure. Retry this
            // store independently so a repaired directory needs no restart.
            static FALLBACK: std::sync::Mutex<()> = std::sync::Mutex::new(());
            let _guard = FALLBACK.lock().map_err(|_| UNAVAILABLE)?;
            let path = crate::stats::db_path();
            std::fs::create_dir_all(path.parent().ok_or(UNAVAILABLE)?).map_err(|_| UNAVAILABLE)?;
            let mut db = Connection::open(path).map_err(|_| UNAVAILABLE)?;
            initialize(&db)?;
            action(&mut db)
        }
    }
}

fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().min(i64::MAX as u64) as i64 }
fn valid_mac(mac: &str) -> bool {
    let b = mac.as_bytes();
    b.len() == 17 && b.iter().enumerate().all(|(i, c)| if i % 3 == 2 { *c == b':' } else { c.is_ascii_digit() || (b'a'..=b'f').contains(c) })
}
fn valid_digest(digest: &str) -> bool {
    digest.len() == 64 && digest.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn valid_credential(value: &str) -> bool {
    (32..=128).contains(&value.len()) && value.bytes().all(|c| (0x20..=0x7e).contains(&c))
}

// Coreutils is part of the appliance OS. The credential crosses stdin, never argv.
fn digest(credential: &str) -> Result<String, Failure> {
    let mut child = Command::new("/usr/bin/sha256sum").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_| UNAVAILABLE)?;
    let sent = child.stdin.take().ok_or(UNAVAILABLE)?.write_all(credential.as_bytes());
    let output = child.wait_with_output().map_err(|_| UNAVAILABLE)?;
    if sent.is_err() || !output.status.success() { return Err(UNAVAILABLE); }
    let digest = std::str::from_utf8(&output.stdout).ok().and_then(|s| s.split_whitespace().next()).ok_or(UNAVAILABLE)?;
    if !valid_digest(digest) { return Err(UNAVAILABLE); }
    Ok(digest.to_owned())
}

// Both values are fixed-size lowercase hex. Do not exit early on a mismatch.
fn equal_digest(left: &str, right: &str) -> bool {
    if !valid_digest(left) || !valid_digest(right) { return false; }
    let mut different = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) { different |= std::hint::black_box(a ^ b); }
    std::hint::black_box(different) == 0
}

fn matching_state(mac: &str, credential: &str) -> Result<Option<String>, Failure> {
    if !valid_mac(mac) || !valid_credential(credential) { return Ok(None); }
    let supplied = digest(credential)?;
    with_db(|db| {
        let row: Option<(String, String)> = db.query_row("SELECT credential_sha256,state FROM backup_pairs WHERE mac=?1", [mac], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_| UNAVAILABLE)?;
        Ok(row.and_then(|(stored,state)| if equal_digest(&stored,&supplied) { Some(state) } else { None }))
    })
}

/// The mirror and key doors call this with the presented credential, not its digest.
pub fn admitted(mac: &str, credential: &str) -> bool {
    matches!(matching_state(mac, credential), Ok(Some(state)) if state == "accepted")
}

// The bounded export-and-act step is shared by the conductor and copy-now.
#[cfg(leaf_ruyi)]
fn remaining(deadline: Instant) -> std::time::Duration { deadline.saturating_duration_since(Instant::now()) }

#[cfg(leaf_ruyi)]
fn signal(value: Option<&str>, secret: &str) -> String {
    value.filter(|s| (1..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && *s != "none" && !(!secret.is_empty() && s.contains(secret)))
        .unwrap_or("road-act-failed").to_owned()
}

#[cfg(leaf_ruyi)]
pub(crate) fn queue_pull(mac: &str, inlet: Option<&str>, deadline: Instant) -> Result<(u64, i64, Instant), String> {
    if remaining(deadline).is_zero() { return Err("no-report".into()); }
    let name = inlet.filter(|s| !s.is_empty()).ok_or("pin-inlet-missing")?;
    let mut crossing = crate::gate::snake::crossing_path_with_timeout("storage/backup/pin-inlet/export", &json!({"name":name}), remaining(deadline).min(std::time::Duration::from_secs(30)))
        .map_err(|_| "pin-inlet-missing".to_owned())?;
    if crossing["ok"] != true { return Err("pin-inlet-missing".into()); }
    let mut result = crossing.as_object_mut().and_then(|v|v.remove("receiptPayload")).ok_or("pin-inlet-missing")?;
    drop(crossing);
    if result["ok"] != true || result["username"].as_str() != Some(mac) { return Err("pin-inlet-missing".into()); }
    let pin = result.as_object_mut().and_then(|o| o.remove("password")).and_then(|v| match v { Value::String(s) => Some(s), _ => None })
        .filter(|s| !s.is_empty()).ok_or("pin-inlet-missing")?;
    drop(result);
    // This owned buffer is wiped even if runtime construction or the act fails.
    struct Secret(Vec<u8>);
    impl Drop for Secret { fn drop(&mut self) { for byte in &mut self.0 { unsafe { std::ptr::write_volatile(byte, 0) }; } std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst); } }
    let pin = Secret(pin.into_bytes());
    let text = std::str::from_utf8(&pin.0).map_err(|_| "pin-inlet-missing".to_owned())?;
    let seen = report_counter(mac).map_err(|_| "backup-pair-unavailable".to_owned())?;
    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().min(i64::MAX as u64) as i64;
    if remaining(deadline).is_zero() { return Err("no-report".into()); }
    let request = json!({"schema":crate::routes::leaf_schema::row_schema(),"target":mac,"thing":"backup-pull","flags":{"exousia":{"pin":text}}});
    let bytes = serde_json::to_vec(&request).map_err(|_| "road-act-failed".to_owned())?;
    drop(request);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| "road-act-failed".to_owned())?;
    let act_started = Instant::now();
    let answer = runtime.block_on(async { tokio::time::timeout(remaining(deadline), crate::routes::leaf_ruyi::road::post(bytes.into())).await });
    let queued = match answer {
        Ok(Ok((_, axum::Json(value)))) => {
            let entry = &value["answers"][0];
            if entry["signal"].is_null() && entry.pointer("/answer/answers/0/answer/state").and_then(Value::as_str) == Some("Queued") { Ok(()) }
            else { Err(signal(entry.get("signal").and_then(Value::as_str), text)) }
        },
        _ => Err("road-act-failed".into()),
    };
    drop(pin);
    queued?;
    Ok((seen, start, act_started))
}

fn request(mac: &str, hostname: &str, supplied: &str, ipv4: &str) -> Result<(Value, bool), Failure> {
    if !valid_mac(mac) || !valid_digest(supplied) || hostname.is_empty() || hostname.len() > 253 { return Err(INVALID); }
    with_db(|db| {
    let tx = db.transaction().map_err(|_| UNAVAILABLE)?;
    let old: Option<(String,String)> = tx.query_row("SELECT credential_sha256,state FROM backup_pairs WHERE mac=?1", [mac], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|_| UNAVAILABLE)?;
    if let Some((digest, _)) = old.as_ref().filter(|(_, state)| state == "accepted") {
        if equal_digest(digest, supplied) {
            return Ok((json!({"ok":true,"state":"accepted"}), false));
        }
        return Err((StatusCode::CONFLICT, "backup-pair-already-accepted"));
    }
    tx.execute("INSERT INTO backup_pairs(mac,hostname,ipv4,credential_sha256,state,requested_at,accepted_at) VALUES(?1,?2,?3,?4,'pending',?5,NULL) ON CONFLICT(mac) DO UPDATE SET hostname=excluded.hostname,ipv4=excluded.ipv4,credential_sha256=excluded.credential_sha256,state='pending',requested_at=excluded.requested_at,accepted_at=NULL", params![mac,hostname,ipv4,supplied,now()]).map_err(|_| UNAVAILABLE)?;
    tx.commit().map_err(|_| UNAVAILABLE)?;
    Ok((json!({"ok":true,"state":"pending"}), true))
    })
}

fn list() -> Result<Value, Failure> {
    with_db(|db| {
    let has_ruyi: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='ruyi')", [], |r| r.get(0)).map_err(|_| UNAVAILABLE)?;
    let sql = if has_ruyi { "SELECT p.mac,COALESCE(json_extract(r.row,'$.hostname'),p.hostname),p.ipv4,p.state,p.requested_at,p.accepted_at,p.report_outcome,p.report_signal,p.report_at,p.report_duration_ms FROM backup_pairs p LEFT JOIN ruyi r ON r.mac=p.mac ORDER BY CASE p.state WHEN 'accepted' THEN 0 ELSE 1 END, CASE WHEN p.state='accepted' THEN p.accepted_at ELSE p.requested_at END, p.mac" } else { "SELECT mac,hostname,ipv4,state,requested_at,accepted_at,report_outcome,report_signal,report_at,report_duration_ms FROM backup_pairs ORDER BY CASE state WHEN 'accepted' THEN 0 ELSE 1 END, CASE WHEN state='accepted' THEN accepted_at ELSE requested_at END, mac" };
    let mut query = db.prepare(sql).map_err(|_| UNAVAILABLE)?;
    let rows = query.query_map([], |r| Ok(json!({"mac":r.get::<_,String>(0)?,"hostname":r.get::<_,Option<String>>(1)?,"ipv4":r.get::<_,Option<String>>(2)?,"state":r.get::<_,String>(3)?,"requested_at":r.get::<_,i64>(4)?,"accepted_at":r.get::<_,Option<i64>>(5)?,"report_outcome":r.get::<_,Option<String>>(6)?,"report_signal":r.get::<_,Option<String>>(7)?,"report_at":r.get::<_,Option<String>>(8)?,"report_duration_ms":r.get::<_,Option<i64>>(9)?}))).map_err(|_| UNAVAILABLE)?;
    let rows = rows.collect::<Result<Vec<_>,_>>().map_err(|_| UNAVAILABLE)?;
    Ok(json!({"ok":true,"pairs":rows}))
    })
}

fn change(mac: &str, accept: bool) -> Result<(Value, bool), Failure> {
    if !valid_mac(mac) { return Err(INVALID); }
    with_db(|db| {
    if accept {
        let count = db.execute("UPDATE backup_pairs SET state='accepted',accepted_at=?2 WHERE mac=?1 AND state='pending'", params![mac,now()]).map_err(|_| UNAVAILABLE)?;
        if count == 0 { return Err((StatusCode::NOT_FOUND,"backup-pair-not-pending")); }
        Ok((json!({"ok":true,"state":"accepted"}), true))
    } else {
        let count = db.execute("DELETE FROM backup_pairs WHERE mac=?1", [mac]).map_err(|_| UNAVAILABLE)?;
        if count == 0 { return Err((StatusCode::NOT_FOUND,"backup-pair-unknown")); }
        Ok((json!({"ok":true}), true))
    }
    })
}

fn record(verb: &str, target: &str, success: bool, signal: &str, started: Instant) {
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ":"backup-pair", "kind":"deed", "ok":success, "message":"backup pair deed",
        "attributes_redacted":{"who":if verb == "request" {"lan"} else if verb == "report" {"box"} else {"owner"},"verb":verb,"target":target,"outcome":if success {"complete"} else {"refused"},"signal":signal,"duration_ms":started.elapsed().as_millis().min(u64::MAX as u128) as u64}
    }));
}

static PAIR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T, Failure> + Send + 'static) -> Result<T, Failure> {
    crate::gate::blocking_task("backup-pair", f).await.map_err(|_| UNAVAILABLE)?
}

fn pair_row(mac: &str) -> Result<(String, Option<String>, String), Failure> {
    if !valid_mac(mac) { return Err(INVALID); }
    with_db(|db| {
        let has_ruyi: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='ruyi')", [], |r| r.get(0)).map_err(|_| UNAVAILABLE)?;
        let sql = if has_ruyi { "SELECT COALESCE(json_extract(r.row,'$.hostname'),p.hostname),p.inlet_name,p.state FROM backup_pairs p LEFT JOIN ruyi r ON r.mac=p.mac WHERE p.mac=?1" } else { "SELECT hostname,inlet_name,state FROM backup_pairs WHERE mac=?1" };
        db.query_row(sql, [mac], |r| Ok((r.get::<_, Option<String>>(0)?.unwrap_or_default(), r.get(1)?, r.get(2)?)))
            .optional().map_err(|_| UNAVAILABLE)?.ok_or((StatusCode::NOT_FOUND, "backup-pair-unknown"))
    })
}

fn inlet_name(hostname: &str) -> Result<String, Failure> {
    let stem: String = hostname.to_lowercase().chars().map(|c| if c.is_ascii_lowercase() || c.is_ascii_digit() { c } else { '_' }).collect();
    if stem.is_empty() || stem.len() > 54 || !stem.as_bytes()[0].is_ascii_lowercase() {
        return Err((StatusCode::BAD_REQUEST, "backup-pair-inlet-name-invalid"));
    }
    Ok(format!("{stem}_pin_inlet"))
}

async fn act(mac: &str, pin: &str, thing: &str, payload: Option<Value>) -> Result<Value, Failure> {
    let mut request = json!({"schema":crate::routes::leaf_schema::row_schema(),"target":mac,"thing":thing,"flags":{"exousia":{"pin":pin}}});
    if let Some(payload) = payload { request["payload"] = payload; }
    let bytes = serde_json::to_vec(&request).map_err(|_| UNAVAILABLE)?;
    let (_, Json(answer)) = crate::routes::leaf_ruyi::road::post(bytes.into()).await.map_err(|_| UNAVAILABLE)?;
    Ok(answer)
}

async fn accept(mac: String, pin: String) -> Result<(Value, bool), Failure> {
    let key = mac.clone();
    let (hostname, previous, state) = blocking(move || pair_row(&key)).await?;
    if state != "pending" { return Err((StatusCode::NOT_FOUND, "backup-pair-not-pending")); }
    if pin.is_empty() { return Err((StatusCode::BAD_REQUEST, "backup-pair-box-pin-required")); }
    if pin.len() > 511 || pin.bytes().any(|c| matches!(c, 0 | b'\r' | b'\n' | b'"')) { return Err(INVALID); }
    let name = inlet_name(&hostname)?;
    if previous.as_deref().is_some_and(|old| old != name) { return Err((StatusCode::CONFLICT, "backup-pair-inlet-name-invalid")); }
    let key = mac.clone(); let proposed = name.clone();
    let taken = blocking(move || with_db(|db| db.query_row("SELECT EXISTS(SELECT 1 FROM backup_pairs WHERE mac<>?1 AND inlet_name=?2)", params![key, proposed], |r| r.get::<_, bool>(0)).map_err(|_| UNAVAILABLE))).await?;
    if taken { return Err((StatusCode::CONFLICT, "backup-pair-inlet-name-taken")); }
    let checked = act(&mac, &pin, "pin-check", None).await.map_err(|_| (StatusCode::BAD_GATEWAY, "backup-pair-box-unreachable"))?;
    let signal = checked.pointer("/answers/0/signal").and_then(Value::as_str);
    if signal == Some("exousia-pin-wrong") { return Err((StatusCode::FORBIDDEN, "backup-pair-box-pin-wrong")); }
    if checked.pointer("/answers/0/signal") != Some(&Value::Null) || checked.pointer("/answers/0/answer/answers/0/answer/verified").and_then(Value::as_bool) != Some(true) {
        return Err((StatusCode::BAD_GATEWAY, "backup-pair-box-unreachable"));
    }
    let key = mac.clone(); let inlet = name.clone(); let secret = pin.clone();
    blocking(move || {
        with_db(|db| {
            let n = db.execute("UPDATE backup_pairs SET inlet_name=?2 WHERE mac=?1 AND state='pending'", params![key,inlet]).map_err(|_| UNAVAILABLE)?;
            if n != 1 { return Err(UNAVAILABLE); } Ok(())
        })?;
        let value = match crate::gate::snake::crossing_path("storage/backup/pin-inlet/put", &json!({"name":inlet,"username":key,"password":secret})) {
            Ok(value) => value,
            Err(signal) if signal == "pin-inlet-name-taken" => {
                with_db(|db| {
                    db.execute("UPDATE backup_pairs SET inlet_name=NULL WHERE mac=?1 AND state='pending' AND inlet_name=?2", params![key,inlet]).map_err(|_| UNAVAILABLE)?;
                    Ok(())
                })?;
                return Err((StatusCode::CONFLICT, "backup-pair-inlet-name-taken"));
            }
            Err(_) => return Err((StatusCode::BAD_GATEWAY, "backup-pair-inlet-store-failed")),
        };
        if value.get("ok").and_then(Value::as_bool) != Some(true) { return Err((StatusCode::BAD_GATEWAY, "backup-pair-inlet-store-failed")); }
        Ok(())
    }).await?;
    let home = blocking(|| Ok(crate::routes::leaf_ruyi::current_identity().mac)).await?
        .filter(|m| valid_mac(m)).ok_or((StatusCode::BAD_GATEWAY, "backup-pair-enroll-failed"))?;
    let enrolled = act(&mac, &pin, "backup-enroll", Some(json!({"home":{"mac":home}}))).await
        .map_err(|_| (StatusCode::BAD_GATEWAY, "backup-pair-enroll-failed"))?;
    if enrolled.pointer("/answers/0/signal") != Some(&Value::Null) || enrolled.pointer("/answers/0/answer/answers/0/answer/enrolled").and_then(Value::as_bool) != Some(true) {
        return Err((StatusCode::BAD_GATEWAY, "backup-pair-enroll-failed"));
    }
    blocking(move || change(&mac, true)).await
}

async fn revoke(mac: String) -> Result<(Value, bool), Failure> {
    let key = mac.clone();
    let (_, inlet, _) = blocking(move || {
        let row = pair_row(&key)?;
        with_db(|db| {
            let n = db.execute("UPDATE backup_pairs SET state='pending',accepted_at=NULL WHERE mac=?1", [&key]).map_err(|_| UNAVAILABLE)?;
            if n != 1 { return Err((StatusCode::NOT_FOUND, "backup-pair-unknown")); }
            Ok(())
        })?;
        Ok(row)
    }).await?;
    if let Some(inlet) = inlet {
        let owner = mac.clone();
        blocking(move || {
            let value = crate::gate::snake::crossing_path("storage/backup/pin-inlet/delete", &json!({"name":inlet,"username":owner}))
                .map_err(|_| (StatusCode::BAD_GATEWAY, "backup-pair-inlet-delete-failed"))?;
            if value.get("ok").and_then(Value::as_bool) != Some(true) { return Err((StatusCode::BAD_GATEWAY, "backup-pair-inlet-delete-failed")); }
            Ok(())
        }).await?;
    }
    blocking(move || {
        let (mut value, changed) = change(&mac, false)?;
        #[cfg(leaf_storage_nas_locked_in_list)]
        {
            let signal = if crate::routes::leaf_storage_nas_locked_in_list::delete_by_holder(&mac).is_err() { "nas-lock-in-unavailable" } else { "none" };
            value["firstMissingSignal"] = json!(signal);
        }
        Ok((value, changed))
    }).await
}

fn report(body: &Value) -> Result<(Value, bool), Failure> {
    let mac = body.get("mac").and_then(Value::as_str).ok_or(INVALID)?;
    let credential = body.get("credential").and_then(Value::as_str).ok_or(INVALID)?;
    let outcome = body.get("outcome").and_then(Value::as_str).filter(|s| matches!(*s, "ok" | "failed" | "refused")).ok_or(INVALID)?;
    let signal = body.get("signal").and_then(Value::as_str).filter(|s| (1..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')).ok_or(INVALID)?;
    let at = body.get("at").and_then(Value::as_str).filter(|s| (s.ends_with('Z') || s.ends_with("+00:00")) && chrono::DateTime::parse_from_rfc3339(s).is_ok()).ok_or(INVALID)?;
    let duration = body.get("durationMs").and_then(Value::as_i64).filter(|n| *n >= 0).ok_or(INVALID)?;
    if !valid_mac(mac) { return Err(INVALID); }
    if !matches!(matching_state(mac, credential)?, Some(state) if state == "accepted") { return Err(UNKNOWN); }
    if signal.contains(credential) { return Err(INVALID); }
    let signal = report_signal(signal);
    let (mutex, wake) = report_wake();
    let mut guard = mutex.lock().map_err(|_| UNAVAILABLE)?;
    let result = with_db(|db| {
        let count = db.execute("UPDATE backup_pairs SET report_outcome=?2,report_signal=?3,report_at=?4,report_duration_ms=?5,report_received_at=?6 WHERE mac=?1 AND state='accepted'", params![mac,outcome,signal,at,duration,now()]).map_err(|_| UNAVAILABLE)?;
        if count != 1 { return Err(UNKNOWN); }
        Ok((json!({"ok":true}), true))
    })?;
    let entry = guard.entry(mac.to_owned()).or_insert((0, Instant::now()));
    entry.0 = entry.0.wrapping_add(1);
    entry.1 = Instant::now();
    wake.notify_all();
    drop(guard);
    #[cfg(leaf_notifications)]
    if outcome == "ok" {
        let _ = crate::routes::leaf_notifications::clear_update_check(json!({"clear":true,"notification":{"id":format!("backup-box-missed:{mac}"),"kind":"backup-box-missed"}}));
    }
    Ok(result)
}

fn copy_now(mac: String) -> Result<(Value, bool), Failure> {
    #[cfg(leaf_pid2)]
    {
        let status = crate::pid2::schedule::status("nas-sync").map_err(|_| UNAVAILABLE)?;
        if matches!(status.pointer("/last_fire/state").and_then(Value::as_str), Some("Queued" | "Running")) {
            return Err((StatusCode::CONFLICT, "backup-copy-night-running"));
        }
    }
    if !valid_mac(&mac) { return Err((StatusCode::NOT_FOUND, "backup-pair-unknown")); }
    let (_, inlet, state) = pair_row(&mac)?;
    if state != "accepted" { return Err((StatusCode::NOT_FOUND, "backup-pair-unknown")); }
    #[cfg(leaf_ruyi)]
    {
        let deadline = Instant::now() + std::time::Duration::from_secs(35);
        queue_pull(&mac, inlet.as_deref(), deadline).map_err(|signal| match signal.as_str() {
            "pin-inlet-missing" => (StatusCode::BAD_GATEWAY, "pin-inlet-missing"),
            "backup-pull-not-enrolled" => (StatusCode::CONFLICT, "backup-pull-not-enrolled"),
            "pid2-schedule-fire-running" => (StatusCode::CONFLICT, "pid2-schedule-fire-running"),
            "backup-pair-box-unreachable" => (StatusCode::BAD_GATEWAY, "backup-pair-box-unreachable"),
            "backup-pair-unavailable" => UNAVAILABLE,
            _ => (StatusCode::BAD_GATEWAY, "road-act-failed"),
        })?;
        Ok((json!({"ok":true,"state":"Queued","mac":mac,"firstMissingSignal":"none"}), true))
    }
    #[cfg(not(leaf_ruyi))]
    { let _ = inlet; Err(UNAVAILABLE) }
}

fn basic(verb: &str, body: &Value, peer: Option<ConnectInfo<crate::gate::ConnectionInfo>>) -> Result<(Value, bool), Failure> {
    let mac = body.get("mac").and_then(Value::as_str).unwrap_or("");
    match verb {
        "request" => {
            let hostname = body.get("hostname").and_then(Value::as_str).unwrap_or("");
            let supplied = body.get("credential_sha256").and_then(Value::as_str).unwrap_or("");
            let ipv4 = match peer { Some(ConnectInfo(crate::gate::ConnectionInfo::Tcp(address))) => match address.ip() { std::net::IpAddr::V4(ip) => ip.to_string(), _ => return Err(INVALID) }, _ => return Err(INVALID) };
            request(mac, hostname, supplied, &ipv4)
        }
        "status" => {
            let credential = body.get("credential").and_then(Value::as_str).unwrap_or("");
            let state = matching_state(mac, credential)?.ok_or(UNKNOWN)?;
            Ok((json!({"ok":true,"state":state}), false))
        }
        "list" => Ok((list()?, false)),
        "report" => report(body),
        _ => Err(INVALID),
    }
}

async fn handle(OriginalUri(uri): OriginalUri, peer: Option<ConnectInfo<crate::gate::ConnectionInfo>>, Json(body): Json<Value>) -> Response {
    let verb = uri.path().rsplit('/').next().unwrap_or("").to_owned();
    let started = Instant::now();
    let mutation = matches!(verb.as_str(), "request" | "accept" | "revoke" | "report" | "copy-now");
    let is_copy_now = verb == "copy-now";
    let work = async move {
        let deed = verb.clone();
        let target = if verb == "copy-now" { body.get("mac").and_then(Value::as_str).filter(|mac| valid_mac(mac)).unwrap_or("backup-pair").to_owned() } else { "backup-pair".to_owned() };
        let result = if verb == "copy-now" {
            let mac = target.clone();
            let _guard = PAIR_LOCK.lock().await;
            blocking(move || copy_now(mac)).await
        } else if verb == "accept" || verb == "revoke" {
            let pin = body.pointer("/flags/exousia/pin").and_then(Value::as_str).unwrap_or("").to_owned();
            let mac = body.get("mac").and_then(Value::as_str).unwrap_or("").to_owned();
            let box_pin = body.pointer("/flags/inlet/pin").and_then(Value::as_str).unwrap_or("").to_owned();
            drop(body);
            let verified = blocking(move || crate::shared::attendance::verify_administrative_pin(&pin).map_err(|signal| match signal.as_str() {
                "exousia-pin-required" => (StatusCode::FORBIDDEN, "exousia-pin-required"),
                "exousia-pin-wrong" => (StatusCode::FORBIDDEN, "exousia-pin-wrong"),
                _ => UNAVAILABLE,
            })).await;
            match verified {
                Err(error) => Err(error),
                Ok(()) => {
                    let _guard = PAIR_LOCK.lock().await;
                    if verb == "accept" { accept(mac, box_pin).await } else { revoke(mac).await }
                },
            }
        } else if verb == "request" || verb == "report" {
            let _guard = PAIR_LOCK.lock().await;
            blocking(move || basic(&verb, &body, peer)).await
        } else { blocking(move || basic(&verb, &body, peer)).await };
        if mutation {
            let deed_outcome = match &result {
                Ok((value, true)) => Some((true, if deed == "revoke" && value["firstMissingSignal"] == "nas-lock-in-unavailable" { "nas-lock-in-unavailable" } else { "none" })),
                Err((_, signal)) => Some((false, *signal)),
                _ => None,
            };
            if let Some((success, signal)) = deed_outcome {
                let _ = blocking(move || { record(&deed, &target, success, signal, started); Ok(()) }).await;
            }
        }
        result
    };
    // Detached mutation owns its deed even after a client disconnects.
    let result = if mutation { tokio::spawn(work).await.unwrap_or(Err(UNAVAILABLE)) } else { work.await };
    match result {
        Ok((value, _)) => (StatusCode::OK,Json(value)).into_response(),
        Err((status,signal)) if is_copy_now => (status,Json(json!({"ok":false,"signal":signal,"firstMissingSignal":signal}))).into_response(),
        Err((status,signal)) => (status,Json(json!({"ok":false,"signal":signal}))).into_response(),
    }
}

pub fn register(router: Router) -> Router {
    let _ = with_db(|_| Ok(()));
    router
        .route("/api/v1/storage/backup/pair/request", axum::routing::post(handle))
        .route("/api/v1/storage/backup/pair/status", axum::routing::post(handle))
        .route("/api/v1/storage/backup/pair/list", axum::routing::post(handle))
        .route("/api/v1/storage/backup/pair/accept", axum::routing::post(handle))
        .route("/api/v1/storage/backup/pair/revoke", axum::routing::post(handle))
        .route("/api/v1/storage/backup/pair/report", axum::routing::post(handle))
        .route("/api/v1/storage/backup/pair/copy-now", axum::routing::post(handle))
}
