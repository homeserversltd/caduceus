//! PID-2 registration and boot-scoped state live in the stats database.
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) static ACTION_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
pub mod solver;
pub mod events;

const SCHEMA: &str = "caduceus.pid2.routine.v1";

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

fn tables(db: &rusqlite::Connection) -> Result<(), String> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS pid2_boot (id INTEGER PRIMARY KEY CHECK(id=1), boot_id TEXT NOT NULL, began_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS pid2_registrations (routine_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL, envelope BLOB NOT NULL, registered_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS pid2_lines (routine_id TEXT NOT NULL, line TEXT NOT NULL, value TEXT, state TEXT NOT NULL, observed_at INTEGER NOT NULL, reason TEXT, PRIMARY KEY(routine_id,line));
        CREATE TABLE IF NOT EXISTS pid2_programs (unit TEXT NOT NULL, scope TEXT NOT NULL, routine_id TEXT NOT NULL, desired TEXT NOT NULL, life TEXT NOT NULL, last_receipt TEXT, updated_at INTEGER NOT NULL, PRIMARY KEY(unit,scope,routine_id));").map_err(|e| e.to_string())
}

/// The boot id is compared and runtime rows are cleared atomically; registrations survive.
pub fn reset_gate() -> Result<bool, String> {
    let boot = std::fs::read_to_string(crate::shared::config::path("proc/sys/kernel/random/boot_id"))
        .map_err(|e| format!("pid2-boot-id-unavailable: {e}"))?;
    let boot = boot.trim();
    if boot.is_empty() { return Err("pid2-boot-id-empty".into()); }
    let mut db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    tables(&db)?;
    let tx = db.transaction().map_err(|e| e.to_string())?;
    let previous: Option<String> = tx.query_row("SELECT boot_id FROM pid2_boot WHERE id=1", [], |r| r.get(0)).optional().map_err(|e| e.to_string())?;
    let changed = previous.as_deref() != Some(boot);
    if changed {
        tx.execute("DELETE FROM pid2_lines", []).map_err(|e| e.to_string())?;
        tx.execute("DELETE FROM pid2_programs", []).map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO pid2_boot(id,boot_id,began_at) VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET boot_id=excluded.boot_id,began_at=excluded.began_at", params![boot,now()]).map_err(|e| e.to_string())?;
    }
    tx.commit().map_err(|e| e.to_string())?;
    Ok(changed)
}

pub fn enable(raw: &[u8]) -> Result<Value, String> {
    let envelope: Value = serde_json::from_slice(raw).map_err(|e| format!("pid2-invalid-json: {e}"))?;
    if envelope.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        return Err(format!("pid2-schema-desync: expected {SCHEMA}, observed {}", envelope.get("schema").unwrap_or(&Value::Null)));
    }
    let seat = crate::routes::leaf_schema::declaration(SCHEMA).ok_or("pid2-schema-seat-missing")?;
    let kernel = seat.get("required").and_then(Value::as_array).ok_or("pid2-schema-kernel-missing")?;
    for field in kernel {
        let key = field.as_str().ok_or("pid2-schema-kernel-invalid")?;
        if envelope.get(key).is_none() {
            return Err(format!("pid2-kernel-missing: {key}"));
        }
    }
    let id = envelope.pointer("/routine/routine_id").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("pid2-routine-id-unavailable")?;
    let action_guard=ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    tables(&db)?;
    let changed=db.execute("INSERT INTO pid2_registrations(routine_id,enabled,envelope,registered_at) VALUES(?1,1,?2,?3) ON CONFLICT(routine_id) DO UPDATE SET enabled=1,envelope=excluded.envelope,registered_at=excluded.registered_at WHERE enabled<>1 OR envelope<>excluded.envelope", params![id, raw, now()]).map_err(|e| e.to_string())?;
    drop(db);
    drop(action_guard);
    if changed != 0 { solver::deed("enable",id,"success",None); events::notify(); }
    Ok(json!({"ok":true,"routine_id":id,"enabled":true,"changed":changed!=0,"readback":status(id)?}))
}

pub fn disable(id: &str) -> Result<Value, String> {
    let action_guard=ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    tables(&db)?;
    let changed = db.execute("UPDATE pid2_registrations SET enabled=0 WHERE routine_id=?1 AND enabled<>0", [id]).map_err(|e| e.to_string())?;
    drop(db);
    drop(action_guard);
    if changed != 0 { solver::deed("disable",id,"success",None); events::notify(); }
    Ok(json!({"ok":true,"routine_id":id,"changed":changed != 0,"readback":status(id)?}))
}

pub fn list() -> Result<Value, String> {
    let Some(db) = read_db()? else { return Ok(json!({"registrations":[],"programs":[]})); };
    if !table_exists(&db, "pid2_registrations")? { return Ok(json!({"registrations":[],"programs":[]})); }
    let mut q = db.prepare("SELECT routine_id,enabled,envelope,registered_at FROM pid2_registrations ORDER BY routine_id").map_err(|e| e.to_string())?;
    let rows = q.query_map([], |r| Ok((r.get::<_,String>(0)?,r.get::<_,bool>(1)?,r.get::<_,Vec<u8>>(2)?,r.get::<_,i64>(3)?))).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for row in rows {
        let (id, enabled, raw, at) = row.map_err(|e| e.to_string())?;
        let envelope: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let raw_envelope = String::from_utf8(raw).map_err(|e| e.to_string())?;
        out.push(json!({"routine_id":id,"enabled":enabled,"registered_at":at,"envelope":envelope,"raw_envelope":raw_envelope}));
    }
    drop(q);
    let mut programs=Vec::new();
    if table_exists(&db,"pid2_programs")? {
        let mut query=db.prepare("SELECT unit,scope,routine_id,desired,life,last_receipt,updated_at FROM pid2_programs ORDER BY unit,scope,routine_id").map_err(|e|e.to_string())?;
        let rows=query.query_map([],|r|Ok(json!({"unit":r.get::<_,String>(0)?,"scope":r.get::<_,String>(1)?,"routine_id":r.get::<_,String>(2)?,"desired":r.get::<_,String>(3)?,"life":r.get::<_,String>(4)?,"last_receipt":r.get::<_,Option<String>>(5)?,"updated_at":r.get::<_,i64>(6)?}))).map_err(|e|e.to_string())?;
        for row in rows { programs.push(row.map_err(|e|e.to_string())?); }
    }
    drop(db);
    observe_programs(&mut programs);
    Ok(json!({"registrations":out,"programs":programs}))
}

fn read_db() -> Result<Option<rusqlite::Connection>, String> {
    let path = crate::stats::db_path();
    if !path.exists() { return Ok(None); }
    rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map(Some).map_err(|e| e.to_string())
}

fn table_exists(db: &rusqlite::Connection, name: &str) -> Result<bool, String> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1)", [name], |row| row.get(0)).map_err(|e| e.to_string())
}

pub fn status(id: &str) -> Result<Value, String> {
    let Some(db) = read_db()? else { return Ok(json!({"registration":null,"lines":[],"programs":[]})); };
    if !table_exists(&db,"pid2_registrations")? { return Ok(json!({"registration":null,"lines":[],"programs":[]})); }
    let stored: Option<(String,bool,Vec<u8>,i64)> = db.query_row("SELECT routine_id,enabled,envelope,registered_at FROM pid2_registrations WHERE routine_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|e|e.to_string())?;
    let registration = match stored {
        None=>None,
        Some((name,enabled,raw,registered_at))=>{
            let envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
            let raw_envelope=String::from_utf8(raw).map_err(|e|e.to_string())?;
            Some(json!({"routine_id":name,"enabled":enabled,"registered_at":registered_at,"envelope":envelope,"raw_envelope":raw_envelope}))
        }
    };
    if !table_exists(&db, "pid2_lines")? || !table_exists(&db, "pid2_programs")? { return Ok(json!({"registration":registration,"lines":[],"programs":[]})); }
    let mut lines = Vec::new();
    let mut statement = db.prepare("SELECT routine_id,line,value,state,observed_at,reason FROM pid2_lines WHERE routine_id=?1 ORDER BY line").map_err(|e| e.to_string())?;
    let rows = statement.query_map([id], |r| Ok(json!({"routine_id":r.get::<_,String>(0)?, "line":r.get::<_,String>(1)?, "value":r.get::<_,Option<String>>(2)?, "state":r.get::<_,String>(3)?, "observed_at":r.get::<_,i64>(4)?, "reason":r.get::<_,Option<String>>(5)?}))).map_err(|e| e.to_string())?;
    for row in rows { lines.push(row.map_err(|e| e.to_string())?); }
    drop(statement);
    let mut programs = Vec::new();
    let mut statement = db.prepare("SELECT unit,scope,routine_id,desired,life,last_receipt,updated_at FROM pid2_programs WHERE routine_id=?1 OR unit=?1 ORDER BY unit,scope,routine_id").map_err(|e| e.to_string())?;
    let rows = statement.query_map([id], |r| Ok(json!({"unit":r.get::<_,String>(0)?, "scope":r.get::<_,String>(1)?, "routine_id":r.get::<_,String>(2)?, "desired":r.get::<_,String>(3)?, "life":r.get::<_,String>(4)?, "last_receipt":r.get::<_,Option<String>>(5)?, "updated_at":r.get::<_,i64>(6)?}))).map_err(|e| e.to_string())?;
    for row in rows { programs.push(row.map_err(|e| e.to_string())?); }
    drop(statement);
    drop(db);
    observe_programs(&mut programs);
    Ok(json!({"registration":registration,"lines":lines,"programs":programs}))
}

fn observe_programs(programs: &mut [Value]) {
    for entry in programs {
        let unit=entry["unit"].as_str().unwrap_or("");
        let scope=entry["scope"].as_str().unwrap_or("");
        let observed=match solver::unit_status(unit,scope) {
            Ok(value)=>json!({"observed":true,"readback":value.get("readback").cloned()}),
            Err(signal)=>json!({"observed":false,"first_missing_signal":signal}),
        };
        entry["systemd"] = observed;
    }
}

pub fn request_unit(action: &str, unit: &str) -> Result<Value, String> {
    let seat = crate::routes::leaf_schema::declaration(SCHEMA).ok_or("pid2-schema-seat-missing")?;
    let entry = seat.get("unit_enum").and_then(Value::as_array).and_then(|units| units.iter().find(|entry| entry.get("unit").and_then(Value::as_str) == Some(unit))).ok_or("pid2-unit-not-declared")?;
    if entry.get("observe_only").and_then(Value::as_bool)==Some(true) { return Err("pid2-unit-observe-only".into()); }
    let scope = entry.get("scope").and_then(Value::as_str).ok_or("pid2-unit-scope-missing")?;
    let (desired, life) = match action {
        "start" => ("Run", "Queued"), "stop" => ("Stop", "Queued"), "restart" => ("Run", "Stopping"),
        _ => return Err("pid2-action-unknown".into()),
    };
    let action_guard=ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    tables(&db)?;
    let mut after = String::new();
    let mut owner: Option<String> = None;
    loop {
        let row: Option<(String,Vec<u8>)> = db.query_row("SELECT routine_id,envelope FROM pid2_registrations WHERE routine_id>?1 ORDER BY routine_id LIMIT 1", [&after], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
        let Some((id,raw))=row else { break; };
        after=id.clone();
        let value: Value = serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        let contains = value.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten().flat_map(|s| s.get("actions").and_then(Value::as_array).into_iter().flatten()).any(|a| a.get("unit").and_then(Value::as_str)==Some(unit));
        if contains { if owner.is_some() { return Err("pid2-unit-registration-ambiguous".into()); } owner=Some(id); }
    }
    let routine_id = owner.ok_or("pid2-unit-not-registered")?;
    db.execute("INSERT INTO pid2_programs(unit,scope,routine_id,desired,life,updated_at) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(unit,scope,routine_id) DO UPDATE SET desired=excluded.desired,life=excluded.life,last_receipt=NULL,updated_at=excluded.updated_at", params![unit,scope,routine_id,desired,life,now()]).map_err(|e| e.to_string())?;
    drop(db);
    drop(action_guard);
    solver::deed(action,unit,"queued",None);
    events::notify();
    Ok(json!({"ok":true,"unit":unit,"scope":scope,"desired":desired,"life":life,"readback":status(unit)?}))
}

pub fn cli(args: &[String]) -> i32 {
    use std::io::Read;
    let result = match args {
        [verb] if verb == "enable" => {
            let mut raw = Vec::new();
            std::io::stdin().take(1024*1024+1).read_to_end(&mut raw).map_err(|e| e.to_string()).and_then(|_| if raw.len()>1024*1024 {Err("pid2-envelope-too-large".into())} else {enable(&raw)})
        }
        [verb] if verb == "list" => list(),
        [verb, pattern] if verb == "pid2-observe-drm" => solver::observe_drm(pattern).map(|value| json!({"observer":"drm-connector","pattern":pattern,"value":value})),
        [verb,id] if verb == "status" => status(id),
        [verb,id] if verb == "disable" => disable(id),
        [verb,id] if ["start","stop","restart"].contains(&verb.as_str()) => request_unit(verb,id),
        _ => Err("pid2-arguments-invalid".into()),
    };
    match result {
        Ok(value) => { println!("{value}"); 0 }
        Err(error) => { eprintln!("{error}"); 1 }
    }
}
