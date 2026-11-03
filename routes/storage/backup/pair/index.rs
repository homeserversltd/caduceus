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
    db.execute_batch("CREATE TABLE IF NOT EXISTS backup_pairs (mac TEXT PRIMARY KEY, hostname TEXT, ipv4 TEXT, credential_sha256 TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','accepted')), requested_at INTEGER NOT NULL, accepted_at INTEGER);").map_err(|_| UNAVAILABLE)
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
    if old.as_ref().is_some_and(|(digest,state)| state == "accepted" && equal_digest(digest,supplied)) {
        return Ok((json!({"ok":true,"state":"accepted"}), false));
    }
    tx.execute("INSERT INTO backup_pairs(mac,hostname,ipv4,credential_sha256,state,requested_at,accepted_at) VALUES(?1,?2,?3,?4,'pending',?5,NULL) ON CONFLICT(mac) DO UPDATE SET hostname=excluded.hostname,ipv4=excluded.ipv4,credential_sha256=excluded.credential_sha256,state='pending',requested_at=excluded.requested_at,accepted_at=NULL", params![mac,hostname,ipv4,supplied,now()]).map_err(|_| UNAVAILABLE)?;
    tx.commit().map_err(|_| UNAVAILABLE)?;
    Ok((json!({"ok":true,"state":"pending"}), true))
    })
}

fn list() -> Result<Value, Failure> {
    with_db(|db| {
    let has_ruyi: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='ruyi')", [], |r| r.get(0)).map_err(|_| UNAVAILABLE)?;
    let sql = if has_ruyi { "SELECT p.mac,COALESCE(json_extract(r.row,'$.hostname'),p.hostname),p.ipv4,p.state,p.requested_at,p.accepted_at FROM backup_pairs p LEFT JOIN ruyi r ON r.mac=p.mac ORDER BY p.mac" } else { "SELECT mac,hostname,ipv4,state,requested_at,accepted_at FROM backup_pairs ORDER BY mac" };
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

async fn handle(OriginalUri(uri): OriginalUri, peer: Option<ConnectInfo<crate::gate::ConnectionInfo>>, Json(body): Json<Value>) -> Response {
    let verb = uri.path().rsplit('/').next().unwrap_or("").to_owned();
    let started = Instant::now();
    let mutation = matches!(verb.as_str(), "request" | "accept" | "revoke");
    let deed = verb.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(Value,bool),Failure> {
        let mac = body.get("mac").and_then(Value::as_str).unwrap_or("");
        match verb.as_str() {
            "request" => {
                let hostname = body.get("hostname").and_then(Value::as_str).unwrap_or("");
                let supplied = body.get("credential_sha256").and_then(Value::as_str).unwrap_or("");
                let ipv4 = match peer { Some(ConnectInfo(crate::gate::ConnectionInfo::Tcp(address))) => match address.ip() { std::net::IpAddr::V4(ip) => ip.to_string(), _ => return Err(INVALID) }, _ => return Err(INVALID) };
                request(mac,hostname,supplied,&ipv4)
            }
            "status" => {
                let credential = body.get("credential").and_then(Value::as_str).unwrap_or("");
                let state = matching_state(mac,credential)?.ok_or(UNKNOWN)?;
                Ok((json!({"ok":true,"state":state}),false))
            }
            "list" => Ok((list()?,false)),
            "accept" => change(mac,true),
            "revoke" => change(mac,false),
            _ => Err(INVALID),
        }
    }).await.unwrap_or(Err(UNAVAILABLE));
    match result {
        Ok((value, changed)) => { if mutation && changed { record(&deed,true,"none",started); } (StatusCode::OK,Json(value)).into_response() }
        Err((status,signal)) => { if mutation { record(&deed,false,signal,started); } (status,Json(json!({"ok":false,"signal":signal}))).into_response() }
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
}
