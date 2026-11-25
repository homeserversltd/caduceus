// HomeServer backup-box pairing. The request carries only the digest.
use axum::extract::OriginalUri;
use axum::{extract::ConnectInfo, http::StatusCode, response::{IntoResponse, Response}, Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::{io::Write, process::{Command, Stdio}, time::{Instant, SystemTime, UNIX_EPOCH}};

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
    let sql = if has_ruyi { "SELECT p.mac,COALESCE(json_extract(r.row,'$.hostname'),p.hostname),p.ipv4,p.state,p.requested_at,p.accepted_at FROM backup_pairs p LEFT JOIN ruyi r ON r.mac=p.mac ORDER BY CASE p.state WHEN 'accepted' THEN 0 ELSE 1 END, CASE WHEN p.state='accepted' THEN p.accepted_at ELSE p.requested_at END, p.mac" } else { "SELECT mac,hostname,ipv4,state,requested_at,accepted_at FROM backup_pairs ORDER BY CASE state WHEN 'accepted' THEN 0 ELSE 1 END, CASE WHEN state='accepted' THEN accepted_at ELSE requested_at END, mac" };
    let mut query = db.prepare(sql).map_err(|_| UNAVAILABLE)?;
    let rows = query.query_map([], |r| Ok(json!({"mac":r.get::<_,String>(0)?,"hostname":r.get::<_,Option<String>>(1)?,"ipv4":r.get::<_,Option<String>>(2)?,"state":r.get::<_,String>(3)?,"requested_at":r.get::<_,i64>(4)?,"accepted_at":r.get::<_,Option<i64>>(5)?}))).map_err(|_| UNAVAILABLE)?;
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

fn record(verb: &str, success: bool, signal: &str, started: Instant) {
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ":"backup-pair", "kind":"deed", "ok":success, "message":"backup pair deed",
        "attributes_redacted":{"who":if verb == "request" {"lan"} else {"owner"},"verb":verb,"target":"backup-pair","outcome":if success {"complete"} else {"refused"},"signal":signal,"duration_ms":started.elapsed().as_millis().min(u64::MAX as u128) as u64}
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
    blocking(move || change(&mac, false)).await
}

fn report(body: &Value) -> Result<(Value, bool), Failure> {
    let mac = body.get("mac").and_then(Value::as_str).ok_or(INVALID)?;
    let credential = body.get("credential").and_then(Value::as_str).ok_or(INVALID)?;
    let outcome = body.get("outcome").and_then(Value::as_str).filter(|s| matches!(*s, "ok" | "failed" | "refused")).ok_or(INVALID)?;
    let signal = body.get("signal").and_then(Value::as_str).filter(|s| (1..=40).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')).ok_or(INVALID)?;
    let at = body.get("at").and_then(Value::as_str).filter(|s| (s.ends_with('Z') || s.ends_with("+00:00")) && chrono::DateTime::parse_from_rfc3339(s).is_ok()).ok_or(INVALID)?;
    let duration = body.get("durationMs").and_then(Value::as_i64).filter(|n| *n >= 0).ok_or(INVALID)?;
    if !valid_mac(mac) { return Err(INVALID); }
    if !admitted(mac, credential) { return Err(UNKNOWN); }
    if signal.contains(credential) { return Err(INVALID); }
    with_db(|db| {
        let count = db.execute("UPDATE backup_pairs SET report_outcome=?2,report_signal=?3,report_at=?4,report_duration_ms=?5,report_received_at=?6 WHERE mac=?1 AND state='accepted'", params![mac,outcome,signal,at,duration,now()]).map_err(|_| UNAVAILABLE)?;
        if count != 1 { return Err(UNKNOWN); }
        Ok((json!({"ok":true}), true))
    })
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
    let mutation = matches!(verb.as_str(), "request" | "accept" | "revoke" | "report");
    let work = async move {
        let deed = verb.clone();
        let result = if verb == "accept" || verb == "revoke" {
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
        } else if verb == "request" {
            let _guard = PAIR_LOCK.lock().await;
            blocking(move || basic(&verb, &body, peer)).await
        } else { blocking(move || basic(&verb, &body, peer)).await };
        if mutation {
            let deed_outcome = match &result {
                Ok((_, true)) => Some((true, "none")),
                Err((_, signal)) => Some((false, *signal)),
                _ => None,
            };
            if let Some((success, signal)) = deed_outcome {
                let _ = blocking(move || { record(&deed, success, signal, started); Ok(()) }).await;
            }
        }
        result
    };
    // Detached mutation owns its deed even after a client disconnects.
    let result = if mutation { tokio::spawn(work).await.unwrap_or(Err(UNAVAILABLE)) } else { work.await };
    match result {
        Ok((value, _)) => (StatusCode::OK,Json(value)).into_response(),
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
}
