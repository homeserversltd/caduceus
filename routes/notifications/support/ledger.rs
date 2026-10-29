use super::{gateway_profile, unavailable, Failure};
use axum::http::StatusCode;
use chrono::{DateTime, Duration, Local, LocalResult, NaiveTime, TimeZone, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

fn error() -> Failure { unavailable("notification-state-unavailable") }
fn now() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64 }
fn posted_order() -> i64 { SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis().min(i64::MAX as u128) as i64 }
fn stamp(at: i64) -> Value { DateTime::<Utc>::from_timestamp(at, 0).map(|v| json!(v.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))).unwrap_or(Value::Null) }

fn init(db: &Connection) -> Result<(), Failure> {
    if !gateway_profile() { return Err(error()); }
    db.execute_batch("CREATE TABLE IF NOT EXISTS notifications (id TEXT PRIMARY KEY, kind TEXT NOT NULL, color TEXT NOT NULL, state TEXT NOT NULL, posted_at INTEGER NOT NULL, expires_at INTEGER, acted_at INTEGER, row TEXT NOT NULL);") .map_err(|_| error())?;
    let old: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='notification_dismissals')", [], |r| r.get(0)).map_err(|_| error())?;
    if old {
        let timestamp = now();
        let date = stamp(timestamp).as_str().unwrap_or("").to_owned();
        db.execute_batch("BEGIN IMMEDIATE;").map_err(|_| error())?;
        let result = (|| {
            db.execute("INSERT OR IGNORE INTO notifications(id,kind,color,state,posted_at,row) SELECT id,'house-link-up','none','dismissed',?1,json_object('id',id,'kind','house-link-up','state','dismissed','title','','posted_at',?2) FROM notification_dismissals", params![timestamp,date]).map_err(|_| error())?;
            db.execute("DELETE FROM notifications WHERE id IN (SELECT id FROM notifications WHERE kind='house-link-up' AND state!='pending' ORDER BY posted_at DESC,id DESC LIMIT -1 OFFSET max(0,50-(SELECT count(*) FROM notifications WHERE kind='house-link-up' AND state='pending')))", []).map_err(|_| error())?;
            db.execute_batch("DROP TABLE notification_dismissals; COMMIT;").map_err(|_| error())?;
            Ok(())
        })();
        if result.is_err() { let _ = db.execute_batch("ROLLBACK;"); }
        result?;
    }
    Ok(())
}

pub(super) fn initialize() -> Result<(), Failure> {
    if !gateway_profile() { return Ok(()); }
    let db = crate::stats::open_db().map_err(|_| error())?.lock().map_err(|_| error())?;
    init(&db)
}

fn expires(ttl: &str, timestamp: i64) -> Option<i64> {
    if ttl == "until-acted" { return None; }
    if ttl == "night" {
        let here = Local.timestamp_opt(timestamp, 0).single()?;
        let today = here.date_naive().and_time(NaiveTime::from_hms_opt(7, 0, 0)?);
        let tomorrow = if here.naive_local() >= today { today.checked_add_signed(Duration::days(1))? } else { today };
        return match Local.from_local_datetime(&tomorrow) { LocalResult::Single(v) => Some(v.timestamp()), LocalResult::Ambiguous(a, _) => Some(a.timestamp()), LocalResult::None => None };
    }
    let (number, scale) = if let Some(n) = ttl.strip_suffix('h') { (n, 3600) } else if let Some(n) = ttl.strip_suffix('d') { (n, 86400) } else { return None };
    let amount = number.parse::<i64>().ok()?.checked_mul(scale)?;
    timestamp.checked_add(amount)
}

pub(super) fn post(mut row: Value, repost: bool) -> Result<Value, Failure> {
    let obj = row.as_object_mut().ok_or((StatusCode::BAD_REQUEST, "notification-row-invalid"))?;
    for field in ["id", "kind", "title"] { if !obj.get(field).and_then(Value::as_str).is_some_and(|v| !v.is_empty()) { return Err((StatusCode::BAD_REQUEST, "notification-row-invalid")); } }
    let color = obj.get("color").and_then(Value::as_str).unwrap_or("none");
    if !["red", "amber", "blue", "none"].contains(&color) { return Err((StatusCode::BAD_REQUEST, "notification-row-invalid")); }
    let id = obj["id"].as_str().unwrap().to_owned();
    let kind = obj["kind"].as_str().unwrap().to_owned();
    let color = color.to_owned();
    let ttl = obj.get("ttl").and_then(Value::as_str).unwrap_or("until-acted").to_owned();
    let limit = obj.get("max_rows").and_then(Value::as_u64).unwrap_or(50).min(i64::MAX as u64) as i64;
    let timestamp = now();
    let expiry = expires(&ttl, timestamp);
    obj.insert("state".into(), json!("pending"));
    obj.insert("color".into(), json!(color));
    obj.insert("ttl".into(), json!(ttl));
    obj.insert("posted_at".into(), stamp(timestamp));
    obj.insert("expires_at".into(), expiry.map(stamp).unwrap_or(Value::Null));
    obj.insert("acted_at".into(), Value::Null);
    if row.to_string().len() >= 1024 { return Err((StatusCode::BAD_REQUEST, "notification-row-invalid")); }
    let mut db = crate::stats::open_db().map_err(|_| error())?.lock().map_err(|_| error())?;
    init(&db)?;
    let tx = db.transaction().map_err(|_| error())?;
    // Expiry is projected on reads; only this posted identity is materialized here.
    tx.execute("UPDATE notifications SET state='expired',acted_at=expires_at,row=json_set(row,'$.state','expired','$.acted_at',strftime('%Y-%m-%dT%H:%M:%SZ',expires_at,'unixepoch')) WHERE id=?1 AND state='pending' AND expires_at IS NOT NULL AND expires_at<=?2", params![id,timestamp]).map_err(|_| error())?;
    let old: Option<String> = tx.query_row("SELECT state FROM notifications WHERE id=?1", [&id], |r| r.get(0)).optional().map_err(|_| error())?;
    if old.as_deref().is_some_and(|s| (s == "dismissed" || s == "expired") && !repost) {
        tx.commit().map_err(|_| error())?;
        return Ok(json!({"schema":super::SCHEMA,"ok":true,"id":id,"state":old.unwrap()}));
    }
    let pending: i64 = tx.query_row("SELECT count(*) FROM notifications WHERE kind=?1 AND id!=?2 AND state='pending' AND (expires_at IS NULL OR expires_at>?3)", params![kind,id,timestamp], |r| r.get(0)).map_err(|_| error())?;
    if pending >= limit { return Err(unavailable("notification-capacity-full")); }
    tx.execute("INSERT INTO notifications(id,kind,color,state,posted_at,expires_at,acted_at,row) VALUES(?1,?2,?3,'pending',?4,?5,NULL,?6) ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,color=excluded.color,state=excluded.state,posted_at=excluded.posted_at,expires_at=excluded.expires_at,acted_at=NULL,row=excluded.row", params![id,kind,color,posted_order(),expiry,row.to_string()]).map_err(|_| error())?;
    tx.execute("DELETE FROM notifications WHERE id IN (SELECT id FROM notifications WHERE kind=?1 AND (state!='pending' OR (expires_at IS NOT NULL AND expires_at<=?3)) ORDER BY posted_at DESC,id DESC LIMIT -1 OFFSET max(0,?2-(SELECT count(*) FROM notifications WHERE kind=?1 AND state='pending' AND (expires_at IS NULL OR expires_at>?3))))", params![kind,limit,timestamp]).map_err(|_| error())?;
    // Bound the whole pinless ingress without evicting another kind's live rows.
    let total: i64 = tx.query_row("SELECT count(*) FROM notifications", [], |r| r.get(0)).map_err(|_| error())?;
    if total > 1000 { return Err(unavailable("notification-capacity-full")); }
    tx.commit().map_err(|_| error())?;
    Ok(json!({"schema":super::SCHEMA,"ok":true,"id":id,"state":"pending"}))
}

pub(super) fn list(all: bool) -> Result<Vec<Value>, Failure> {
    let db = crate::stats::open_db().map_err(|_| error())?.lock().map_err(|_| error())?;
    let timestamp = now();
    let mut query = db.prepare("SELECT CASE WHEN state='pending' AND expires_at IS NOT NULL AND expires_at<=?1 THEN json_set(row,'$.state','expired','$.acted_at',strftime('%Y-%m-%dT%H:%M:%SZ',expires_at,'unixepoch')) ELSE row END FROM notifications WHERE ?2 OR (state='pending' AND (expires_at IS NULL OR expires_at>?1)) ORDER BY posted_at DESC,id DESC").map_err(|_| error())?;
    let rows = query.query_map(params![timestamp,all], |r| r.get::<_, String>(0)).map_err(|_| error())?;
    rows.map(|r| serde_json::from_str(&r.map_err(|_| error())?).map_err(|_| error())).collect()
}

pub(super) fn get(id: &str) -> Result<Value, Failure> {
    let db = crate::stats::open_db().map_err(|_| error())?.lock().map_err(|_| error())?;
    let row: Option<String> = db.query_row("SELECT CASE WHEN state='pending' AND expires_at IS NOT NULL AND expires_at<=?2 THEN json_set(row,'$.state','expired','$.acted_at',strftime('%Y-%m-%dT%H:%M:%SZ',expires_at,'unixepoch')) ELSE row END FROM notifications WHERE id=?1", params![id,now()], |r| r.get(0)).optional().map_err(|_| error())?;
    serde_json::from_str(&row.ok_or((StatusCode::NOT_FOUND,"notification-absent"))?).map_err(|_| error())
}

pub(super) fn change(id: &str, state: &str) -> Result<(), Failure> {
    let db = crate::stats::open_db().map_err(|_| error())?.lock().map_err(|_| error())?;
    init(&db)?;
    let timestamp = now();
    let acted = if state == "pending" { None } else { Some(timestamp) };
    let acted_json = acted.map(stamp).unwrap_or(Value::Null);
    db.execute("UPDATE notifications SET state=?2,acted_at=?3,row=json_set(row,'$.state',?2,'$.acted_at',json(?4)) WHERE id=?1", params![id,state,acted,acted_json.to_string()]).map_err(|_| error())?;
    Ok(())
}
