//! Calendar registrations and bounded fire deeds in the PID-2 database.
use chrono::{Local, LocalResult, NaiveDate, NaiveTime, TimeZone};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::time::Duration;

const SCHEMA: &str = "caduceus.pid2.schedule.v1";

pub(super) fn fire_deed(id:&str,fire:&str,outcome:&str,duration_ms:i64,signal:Option<&str>) {
    let _=crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({"organ":"pid2","kind":"schedule-fire","level":"info","ok":signal.is_none(),"message":"schedule fire","correlation_id":fire,"attributes_redacted":{"who":"caduceus","verb":"schedule-fire","target":id,"outcome":outcome,"duration_ms":duration_ms,"fire_id":fire,"first_missing_signal":signal}}));
}

#[derive(Clone)]
struct Calendar { frequency: String, time: String, weekday: Option<String> }

fn calendar(value: &Value) -> Result<Calendar,String> {
    let frequency=value.get("frequency").and_then(Value::as_str).unwrap_or("");
    if frequency!="daily" && frequency!="weekly" { return Err("pid2-schedule-frequency-unusable".into()); }
    let time=value.get("time").or_else(||value.get("at")).and_then(Value::as_str).unwrap_or("");
    if time.len()!=5 || NaiveTime::parse_from_str(time,"%H:%M").is_err() { return Err("pid2-schedule-time-unusable".into()); }
    let weekday=value.get("weekday").or_else(||value.get("day")).and_then(Value::as_str).map(str::to_owned);
    if frequency=="weekly" && !weekday.as_deref().is_some_and(|v|["Mon","Tue","Wed","Thu","Fri","Sat","Sun"].contains(&v)) { return Err("pid2-schedule-weekday-unusable".into()); }
    Ok(Calendar {frequency:frequency.into(),time:time.into(),weekday:if frequency=="daily" {None} else {weekday}})
}

fn slot_for(day: NaiveDate, cal: &Calendar) -> Option<i64> {
    if cal.frequency=="weekly" && Some(day.format("%a").to_string())!=cal.weekday { return None; }
    let time=NaiveTime::parse_from_str(&cal.time,"%H:%M").ok()?;
    let local=day.and_time(time);
    match Local.from_local_datetime(&local) {
        LocalResult::Single(v)=>Some(v.timestamp()),
        LocalResult::Ambiguous(first,_)=>Some(first.timestamp()),
        LocalResult::None=>None,
    }
}
fn previous_slot(cal: &Calendar, now: i64) -> Option<i64> {
    let today=Local.timestamp_opt(now,0).single()?.date_naive();
    (0..=14).filter_map(|n|today.checked_sub_signed(chrono::Duration::days(n))).filter_map(|d|slot_for(d,cal)).filter(|s|*s<=now).max()
}
pub(super) fn slot_at(frequency:&str,time:&str,weekday:Option<String>,at:i64) -> Option<i64> {
    previous_slot(&Calendar{frequency:frequency.into(),time:time.into(),weekday},at)
}
fn next_slot(cal: &Calendar, now: i64) -> Option<i64> {
    let today=Local.timestamp_opt(now,0).single()?.date_naive();
    (0..=14).filter_map(|n|today.checked_add_signed(chrono::Duration::days(n))).filter_map(|d|slot_for(d,cal)).filter(|s|*s>now).min()
}
fn cal_from_row(frequency:String,time:String,weekday:Option<String>) -> Calendar { Calendar{frequency,time,weekday} }
// A malformed present flag is preserved in the envelope, but must never
// silently arm a schedule. Missing/null retains the primitive behavior.
fn enabled_value(value:Option<&Value>) -> Option<bool> {
    match value {None|Some(Value::Null)=>None,Some(Value::Bool(value))=>Some(*value),Some(_)=>Some(false)}
}
fn fire_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({"fire_id":row.get::<_,String>(0)?,"trigger":row.get::<_,String>(1)?,"state":row.get::<_,String>(2)?,
        "queued_at":row.get::<_,i64>(3)?,"started_at":row.get::<_,Option<i64>>(4)?,"finished_at":row.get::<_,Option<i64>>(5)?,
        "duration_ms":row.get::<_,Option<i64>>(6)?,"first_missing_signal":row.get::<_,Option<String>>(7)?,
        "rsync_exit_code":row.get::<_,Option<i64>>(8)?,"final_file_count":row.get::<_,Option<i64>>(9)?,"final_total_bytes":row.get::<_,Option<i64>>(10)?}))
}

// One abstract datagram address per fire. The waiter binds before queueing;
// the worker signals only after its terminal transaction commits. The kernel
// removes the address when the waiter exits, without touching the fire.
fn fire_address(fire:&str) -> Result<std::os::unix::net::SocketAddr,String> {
    use std::{hash::{Hash,Hasher},os::linux::net::SocketAddrExt};
    let mut hash=std::collections::hash_map::DefaultHasher::new();
    crate::stats::db_path().hash(&mut hash);
    std::os::unix::net::SocketAddr::from_abstract_name(format!("caduceus-fire-{:016x}-{fire}",hash.finish())).map_err(|e|e.to_string())
}
fn fire_row(db:&rusqlite::Connection,id:&str,fire:&str) -> Result<Option<Value>,String> {
    db.query_row("SELECT fire_id,trigger,state,queued_at,started_at,finished_at,duration_ms,first_missing_signal,rsync_exit_code,final_file_count,final_total_bytes FROM pid2_fires WHERE schedule_id=?1 AND fire_id=?2",params![id,fire],fire_json).optional().map_err(|e|e.to_string())
}
fn signal_fire(fire:&str,row:&Value) {
    if let (Ok(address),Ok(socket))=(fire_address(fire),std::os::unix::net::UnixDatagram::unbound()) {
        if let Ok(bytes)=serde_json::to_vec(row) {let _=socket.send_to_addr(&bytes,&address);}
    }
}
fn commit_terminal(tx:rusqlite::Transaction<'_>,id:&str,fire:&str,changed:usize) -> Result<(),String> {
    let row=if changed!=0 {fire_row(&tx,id,fire)?} else {None};
    tx.commit().map_err(|e|e.to_string())?;
    if let Some(row)=row {signal_fire(fire,&row);}
    Ok(())
}
pub(super) fn wake_interrupted() -> Result<(),String> {
    let Some(db)=super::read_db()? else {return Ok(());};
    if !super::table_exists(&db,"pid2_fires")? {return Ok(());}
    let mut q=db.prepare("SELECT fire_id,trigger,state,queued_at,started_at,finished_at,duration_ms,first_missing_signal,rsync_exit_code,final_file_count,final_total_bytes FROM pid2_fires WHERE state='Interrupted'").map_err(|e|e.to_string())?;
    let rows=q.query_map([],fire_json).map_err(|e|e.to_string())?;
    for row in rows {let row=row.map_err(|e|e.to_string())?;if let Some(fire)=row["fire_id"].as_str(){signal_fire(fire,&row);}}
    Ok(())
}

pub fn status(id:&str) -> Result<Value,String> {
    let Some(db)=super::read_db()? else {return Ok(json!({"schedule":null,"next_fire":null,"last_fire":null,"baseline":null}));};
    if !super::table_exists(&db,"pid2_schedules")? {return Ok(json!({"schedule":null,"next_fire":null,"last_fire":null,"baseline":null}));}
    let row:Option<(bool,Vec<u8>,String,String,Option<String>,String,String,i64,i64,i64,Option<i64>)>=db.query_row(
        "SELECT enabled,envelope,frequency,time,weekday,band,action,max_seconds,registered_at,updated_at,last_fired_slot FROM pid2_schedules WHERE schedule_id=?1",[id],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?))).optional().map_err(|e|e.to_string())?;
    let Some((enabled,raw,frequency,time,weekday,band,action,max_seconds,registered_at,updated_at,last_fired_slot))=row else {return Ok(json!({"schedule":null,"next_fire":null,"last_fire":null,"baseline":null}));};
    let envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    let cal=if frequency.is_empty() {None} else {Some(cal_from_row(frequency.clone(),time.clone(),weekday.clone()))};
    let next=if enabled {cal.as_ref().and_then(|cal|next_slot(cal,super::now())).and_then(|v|chrono::DateTime::from_timestamp(v,0)).map(|v|v.with_timezone(&Local).to_rfc3339())} else {None};
    let fire=if super::table_exists(&db,"pid2_fires")? {db.query_row("SELECT fire_id,trigger,state,queued_at,started_at,finished_at,duration_ms,first_missing_signal,rsync_exit_code,final_file_count,final_total_bytes FROM pid2_fires WHERE schedule_id=?1",[id],fire_json).optional().map_err(|e|e.to_string())?} else {None};
    let baseline=if super::table_exists(&db,"pid2_sync_baselines")? {db.query_row("SELECT file_count,total_bytes,updated_at,fire_id FROM pid2_sync_baselines WHERE schedule_id=?1",[id],|r|Ok(json!({"fileCount":r.get::<_,i64>(0)?,"totalBytes":r.get::<_,i64>(1)?,"updated_at":r.get::<_,i64>(2)?,"fire_id":r.get::<_,String>(3)?}))).optional().map_err(|e|e.to_string())?} else {None};
    Ok(json!({"schedule":{"schedule_id":id,"enabled":enabled,"calendar":cal.as_ref().map(|_|json!({"frequency":frequency,"time":time,"weekday":weekday})),"frequency":cal.as_ref().map(|_|frequency),"time":cal.as_ref().map(|_|time),"weekday":weekday,"band":band,"action":action,"max_seconds":max_seconds,"registered_at":registered_at,"updated_at":updated_at,"last_fired_slot":last_fired_slot,"envelope":envelope,"raw_envelope":String::from_utf8(raw).map_err(|e|e.to_string())?},"next_fire":next,"last_fire":fire,"baseline":baseline}))
}
pub fn list() -> Result<Value,String> {
    let Some(db)=super::read_db()? else {return Ok(json!({"schedules":[]}));};
    if !super::table_exists(&db,"pid2_schedules")? {return Ok(json!({"schedules":[]}));}
    let mut q=db.prepare("SELECT schedule_id FROM pid2_schedules ORDER BY schedule_id").map_err(|e|e.to_string())?;
    let ids=q.query_map([],|r|r.get::<_,String>(0)).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    drop(q); drop(db);
    let rows=ids.iter().map(|id|status(id)).collect::<Result<Vec<_>,_>>()?;
    Ok(json!({"schedules":rows}))
}

pub fn register(raw:&[u8]) -> Result<Value,String> {
    let envelope:Value=serde_json::from_slice(raw).map_err(|e|format!("pid2-schedule-json-invalid: {e}"))?;
    if envelope.get("schema").and_then(Value::as_str)!=Some(SCHEMA) {return Err("pid2-schedule-schema-desync".into());}
    let seat=crate::routes::leaf_schema::declaration(SCHEMA).ok_or("pid2-schedule-schema-seat-missing")?;
    for key in seat.get("required").and_then(Value::as_array).ok_or("pid2-schedule-schema-kernel-missing")? {
        let name=key.as_str().ok_or("pid2-schedule-schema-kernel-invalid")?;
        if envelope.get(name).and_then(Value::as_str).filter(|value|!value.is_empty()).is_none() {return Err(format!("pid2-schedule-kernel-unusable: {name}"));}
    }
    let spec=envelope.get("schedule").ok_or("pid2-schedule-unusable")?;
    let id=spec.get("schedule_id").and_then(Value::as_str).filter(|s|!s.is_empty()).ok_or("pid2-schedule-id-unusable")?;
    let enabled=enabled_value(spec.get("enabled"));
    // Empty frequency/time are an internal marker, compatible with existing
    // NOT NULL databases and impossible for a valid calendar.
    let cal=match spec.get("calendar") {None|Some(Value::Null)=>None,Some(value)=>Some(calendar(value)?)};
    let job=spec.get("job").unwrap_or(&Value::Null);
    let band=job.get("band").and_then(Value::as_str).filter(|s|!s.is_empty()).ok_or("pid2-schedule-band-unusable")?;
    let action=job.get("action").and_then(Value::as_str).filter(|s|!s.is_empty()).ok_or("pid2-schedule-action-unusable")?;
    let max=match job.get("max_seconds") {None|Some(Value::Null)=>21600,Some(value)=>value.as_u64().ok_or("pid2-schedule-deadline-unusable")?};
    if !(1..=86400).contains(&max) {return Err("pid2-schedule-deadline-unusable".into());}
    let now=super::now(); let slot=cal.as_ref().and_then(|cal|previous_slot(cal,now));
    let cal=cal.unwrap_or(Calendar{frequency:String::new(),time:String::new(),weekday:None});
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    super::tables(&db)?;
    let changed=db.execute("INSERT INTO pid2_schedules(schedule_id,enabled,envelope,frequency,time,weekday,band,action,max_seconds,registered_at,updated_at,last_fired_slot) VALUES(?1,COALESCE(?11,1),?2,?3,?4,?5,?6,?7,?8,?9,?9,?10) ON CONFLICT(schedule_id) DO UPDATE SET enabled=COALESCE(?11,pid2_schedules.enabled),envelope=excluded.envelope,frequency=excluded.frequency,time=excluded.time,weekday=excluded.weekday,band=excluded.band,action=excluded.action,max_seconds=excluded.max_seconds,updated_at=excluded.updated_at WHERE pid2_schedules.envelope IS NOT excluded.envelope OR pid2_schedules.frequency IS NOT excluded.frequency OR pid2_schedules.time IS NOT excluded.time OR pid2_schedules.weekday IS NOT excluded.weekday OR pid2_schedules.band IS NOT excluded.band OR pid2_schedules.action IS NOT excluded.action OR pid2_schedules.max_seconds IS NOT excluded.max_seconds OR (?11 IS NOT NULL AND pid2_schedules.enabled IS NOT ?11)",params![id,raw,cal.frequency,cal.time,cal.weekday,band,action,max as i64,now,slot,enabled]).map_err(|e|e.to_string())?;
    drop(db); if changed!=0 {super::events::notify_schedule()?;super::solver::deed("schedule-register",id,"success",None);}
    Ok(json!({"ok":true,"readback":status(id)?}))
}

pub fn set_enabled(id:&str,enabled:bool,missing_noop:bool) -> Result<Value,String> {
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?; super::tables(&db)?;
    let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM pid2_schedules WHERE schedule_id=?1)",[id],|r|r.get(0)).map_err(|e|e.to_string())?;
    if !exists && !missing_noop {return Err("pid2-schedule-not-found".into());}
    let changed=db.execute("UPDATE pid2_schedules SET enabled=?2,updated_at=?3 WHERE schedule_id=?1 AND enabled<>?2",params![id,enabled,super::now()]).map_err(|e|e.to_string())?;
    drop(db); if changed!=0 {super::events::notify_schedule()?;super::solver::deed(if enabled {"schedule-enable"} else {"schedule-disable"},id,"success",None);}
    Ok(json!({"ok":true,"changed":changed!=0,"readback":status(id)?}))
}
pub fn update(id:&str,patch:&Value) -> Result<Value,String> {
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?; super::tables(&db)?;
    let tx=db.transaction().map_err(|e|e.to_string())?;
    let row:Option<(Vec<u8>,String,String,Option<String>,bool)>=tx.query_row("SELECT envelope,frequency,time,weekday,enabled FROM pid2_schedules WHERE schedule_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?;
    let (raw,frequency,time,weekday,old_enabled)=row.ok_or("pid2-schedule-not-found")?;
    let mut input=json!({"frequency":frequency,"time":time,"weekday":weekday});
    let calendar_patch=patch.get("calendar").filter(|v|v.is_object()).unwrap_or(patch);
    for key in ["frequency","time","weekday","at","day"] {if let Some(v)=calendar_patch.get(key) {input[key]=v.clone();}}
    if calendar_patch.get("time").is_none() {if let Some(v)=calendar_patch.get("at") {input["time"]=v.clone();}}
    if calendar_patch.get("weekday").is_none() {if let Some(v)=calendar_patch.get("day") {input["weekday"]=v.clone();}}
    let has_calendar_patch=["frequency","time","weekday","at","day"].iter().any(|key|calendar_patch.get(*key).is_some());
    let cal=if frequency.is_empty() && !has_calendar_patch {Calendar{frequency:String::new(),time:String::new(),weekday:None}} else {calendar(&input)?};
    let enabled=enabled_value(patch.get("enabled").or_else(||calendar_patch.get("enabled"))).unwrap_or(old_enabled);
    let mut envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    if !cal.frequency.is_empty() {
        let schedule=envelope.get_mut("schedule").and_then(Value::as_object_mut).ok_or("pid2-schedule-unusable")?;
        let target=schedule.entry("calendar").or_insert_with(||json!({}));
        if target.is_null() {*target=json!({});}
        let target=target.as_object_mut().ok_or("pid2-schedule-calendar-unusable")?;
        target.insert("frequency".into(),json!(cal.frequency));target.insert("time".into(),json!(cal.time));target.insert("weekday".into(),json!(cal.weekday));
    }
    let encoded=serde_json::to_vec(&envelope).map_err(|e|e.to_string())?;
    let first_slot=if frequency.is_empty() && !cal.frequency.is_empty() {previous_slot(&cal,super::now())} else {None};
    let changed=tx.execute("UPDATE pid2_schedules SET envelope=?2,frequency=?3,time=?4,weekday=?5,enabled=?6,updated_at=?7,last_fired_slot=CASE WHEN frequency='' AND ?3<>'' THEN ?8 ELSE last_fired_slot END WHERE schedule_id=?1 AND (frequency IS NOT ?3 OR time IS NOT ?4 OR weekday IS NOT ?5 OR enabled IS NOT ?6)",params![id,encoded,cal.frequency,cal.time,cal.weekday,enabled,super::now(),first_slot]).map_err(|e|e.to_string())?;
    tx.commit().map_err(|e|e.to_string())?;drop(db);
    if changed!=0 {super::events::notify_schedule()?;super::solver::deed("schedule-update",id,"success",None);}
    Ok(json!({"ok":true,"readback":status(id)?}))
}

fn unmet(tx:&rusqlite::Transaction<'_>,raw:&[u8]) -> Result<Option<String>,String> {
    let env:Value=serde_json::from_slice(raw).map_err(|e|e.to_string())?;
    for need in env.pointer("/schedule/needs").and_then(Value::as_array).into_iter().flatten() {
        let routine=need.get("routine_id").and_then(Value::as_str).unwrap_or("");
        let line=need.get("line").and_then(Value::as_str).unwrap_or("");
        if routine.is_empty() || line.is_empty() {return Ok(Some("pid2-schedule-need-unusable".into()));}
        let held:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",[routine],|r|r.get(0)).map_err(|e|e.to_string())?;
        if held {return Ok(Some("pid2-routine-held".into()));}
        let done:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pid2_lines WHERE routine_id=?1 AND line=?2 AND state='Done')",params![routine,line],|r|r.get(0)).map_err(|e|e.to_string())?;
        if !done {return Ok(Some(format!("pid2-schedule-needs-unmet: {routine}/{line}")));}
    }
    Ok(None)
}
fn advance_slot(tx:&rusqlite::Transaction<'_>,id:&str,fire:&str) -> Result<(),String> {
    tx.execute("UPDATE pid2_schedules SET last_fired_slot=CASE WHEN last_fired_slot IS NULL OR last_fired_slot<(SELECT slot FROM pid2_fires WHERE schedule_id=?1 AND fire_id=?2) THEN (SELECT slot FROM pid2_fires WHERE schedule_id=?1 AND fire_id=?2) ELSE last_fired_slot END,retry_slot=CASE WHEN retry_slot=(SELECT slot FROM pid2_fires WHERE schedule_id=?1 AND fire_id=?2) THEN NULL ELSE retry_slot END,retry_queued_at=CASE WHEN retry_slot=(SELECT slot FROM pid2_fires WHERE schedule_id=?1 AND fire_id=?2) THEN NULL ELSE retry_queued_at END,retry_order=CASE WHEN retry_slot=(SELECT slot FROM pid2_fires WHERE schedule_id=?1 AND fire_id=?2) THEN NULL ELSE retry_order END WHERE schedule_id=?1 AND EXISTS(SELECT 1 FROM pid2_fires WHERE schedule_id=?1 AND fire_id=?2 AND slot IS NOT NULL AND (last_fired_slot IS NULL OR slot>last_fired_slot OR slot=retry_slot))",params![id,fire]).map_err(|e|e.to_string())?;
    Ok(())
}
pub fn queue(id:&str,trigger:&str,slot:Option<i64>) -> Result<Value,String> {
    let mut result=queue_with_id(id,trigger,slot,&uuid::Uuid::new_v4().simple().to_string(),false)?;
    if let Some(object)=result.as_object_mut() {object.remove("max_seconds");}
    Ok(result)
}
fn queue_with_id(id:&str,trigger:&str,slot:Option<i64>,fire_id:&str,waiter:bool) -> Result<Value,String> {
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?; super::tables(&db)?;
    let tx=db.transaction().map_err(|e|e.to_string())?;
    let (raw,enabled,max):(Vec<u8>,bool,u64)=tx.query_row("SELECT envelope,enabled,max_seconds FROM pid2_schedules WHERE schedule_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|e|e.to_string())?.ok_or("pid2-schedule-not-found")?;
    if trigger=="round" && !enabled {drop(tx);drop(db);fire_deed(id,&uuid::Uuid::new_v4().simple().to_string(),"Refused",0,Some("pid2-schedule-disabled"));return Err("pid2-schedule-disabled".into());}
    let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pid2_fires WHERE schedule_id=?1 AND state IN ('Queued','Running'))",[id],|r|r.get(0)).map_err(|e|e.to_string())?;
    if active {drop(tx);drop(db);fire_deed(id,&uuid::Uuid::new_v4().simple().to_string(),"Refused",0,Some("pid2-schedule-fire-running"));return Err("pid2-schedule-fire-running".into());}
    let signal=unmet(&tx,&raw)?; let now=super::now();
    let state=if signal.is_some() {"Refused"} else {"Queued"};
    let order:i64=tx.query_row("SELECT COALESCE(MAX(queue_order),0)+1 FROM pid2_fires",[],|r|r.get(0)).map_err(|e|e.to_string())?;
    tx.execute("INSERT INTO pid2_fires(schedule_id,fire_id,trigger,state,queued_at,finished_at,first_missing_signal,slot,queue_order) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(schedule_id) DO UPDATE SET fire_id=excluded.fire_id,trigger=excluded.trigger,state=excluded.state,queued_at=excluded.queued_at,started_at=NULL,finished_at=excluded.finished_at,duration_ms=NULL,first_missing_signal=excluded.first_missing_signal,rsync_exit_code=NULL,final_file_count=NULL,final_total_bytes=NULL,slot=excluded.slot,queue_order=excluded.queue_order",params![id,fire_id,trigger,state,now,if signal.is_some(){Some(now)}else{None},signal,slot,order]).map_err(|e|e.to_string())?;
    if signal.is_some() {advance_slot(&tx,id,&fire_id)?;}
    tx.commit().map_err(|e|e.to_string())?;drop(db);
    if let Some(signal)=signal {fire_deed(id,&fire_id,"Refused",0,Some(&signal));return Err(signal);}
    if let Err(signal)=super::events::notify_schedule() {
        if !waiter {return Err(signal);}
        // The fire is already committed, so the waiting caller must not be
        // told that no fire exists. Keep watching it and surface the failed
        // nudge separately; a later wake may still dispatch the queued fire.
        eprintln!("pid2-schedule-wake-after-queue: {signal}");
    }
    Ok(json!({"ok":true,"fire_id":fire_id,"state":"Queued","max_seconds":max}))
}

/// Return the next clock delay and queue any missed slots. No periodic polling.
pub fn clock(catchup:bool) -> Result<Duration,String> {
    let Some(db)=super::read_db()? else {return Ok(Duration::from_secs(86400*365));};
    if !super::table_exists(&db,"pid2_schedules")? {return Ok(Duration::from_secs(86400*365));}
    let mut q=db.prepare("SELECT schedule_id,frequency,time,weekday,last_fired_slot,retry_slot,interrupted_slot FROM pid2_schedules WHERE enabled=1 ORDER BY retry_queued_at IS NULL,retry_queued_at,retry_order,schedule_id").map_err(|e|e.to_string())?;
    let rows=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<i64>>(4)?,r.get::<_,Option<i64>>(5)?,r.get::<_,Option<i64>>(6)?))).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    drop(q);drop(db);let now=super::now();let mut earliest=None;
    for (id,frequency,time,weekday,last,retry,interrupted) in rows {
        if frequency.is_empty() {continue;}
        let cal=cal_from_row(frequency,time,weekday);
        let current=||previous_slot(&cal,now).filter(|slot|last.is_some_and(|last|*slot>last) && interrupted.is_none_or(|blocked|*slot>blocked));
        if let Some(slot)=retry.filter(|slot|interrupted.is_none_or(|blocked|*slot>blocked)).or_else(current) {
            let already_held={let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;db.query_row("SELECT EXISTS(SELECT 1 FROM pid2_fires WHERE schedule_id=?1 AND (state IN ('Queued','Running') OR (state='Interrupted' AND slot=?2)))",params![id,slot],|r|r.get::<_,bool>(0)).map_err(|e|e.to_string())?};
            if !already_held { let _=queue(&id,if catchup || retry==Some(slot) {"catch-up"} else {"calendar"},Some(slot)); }
        }
        if let Some(next)=next_slot(&cal,now) {earliest=Some(earliest.map_or(next,|old:i64|old.min(next)));}
    }
    Ok(Duration::from_secs(earliest.map(|v|(v-now).max(0) as u64).unwrap_or(86400*365)))
}

pub fn queued() -> Result<Vec<String>,String> {
    let Some(db)=super::read_db()? else {return Ok(vec![]);};
    if !super::table_exists(&db,"pid2_fires")? {return Ok(vec![]);}
    let mut q=db.prepare("SELECT schedule_id FROM pid2_fires WHERE state='Queued' ORDER BY queued_at, queue_order, rowid").map_err(|e|e.to_string())?;
    let rows=q.query_map([],|r|r.get(0)).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    Ok(rows)
}

pub fn execute(id:&str) -> Result<bool,String> {
    // Claim the specific queued fire before the NAS lease or any crossing.
    // Duplicate wakeups may dispatch this worker more than once.
    let (fire,raw,band,action,max) = {
        let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        super::tables(&db)?;
        let tx=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e|e.to_string())?;
        let row:Option<(String,Vec<u8>,String,String,i64)>=tx.query_row("SELECT f.fire_id,s.envelope,s.band,s.action,s.max_seconds FROM pid2_fires f JOIN pid2_schedules s ON s.schedule_id=f.schedule_id WHERE f.schedule_id=?1 AND f.state='Queued'",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?;
        let Some((fire,raw,band,action,max))=row else {return Ok(false);};
        let changed=tx.execute("UPDATE pid2_fires SET state='Running',started_at=?2 WHERE schedule_id=?1 AND fire_id=?3 AND state='Queued' AND NOT EXISTS(SELECT 1 FROM pid2_fires WHERE state='Running') AND schedule_id=(SELECT schedule_id FROM pid2_fires WHERE state='Queued' ORDER BY queued_at,queue_order,rowid LIMIT 1)",params![id,super::now(),fire]).map_err(|e|e.to_string())?;
        if changed!=1 {return Ok(false);}
        tx.commit().map_err(|e|e.to_string())?;
        (fire,raw,band,action,max)
    };
    let result=(|| -> Result<bool,String> {
    // A NAS fire and a NAS role swap must never cross the staff concurrently.
    // The shared nonblocking lease is held until the crossing has ended.
    // Existing registrations keep their parent band and raw envelope.  Resolve
    // that legacy name only at the fire boundary, without rewriting the row.
    let nas_sync=matches!(band.as_str(),"storage/backup/nas-sync"|"storage/backup/nas-sync/sync");
    let _nas_lease=if nas_sync {
        match super::swap_lease() {
            Ok(lease)=>Some(lease),
            Err(signal) if signal=="pid2-swap-busy"=>{
                let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                let tx=db.transaction().map_err(|e|e.to_string())?;
                let changed=tx.execute("UPDATE pid2_fires SET state='Refused',finished_at=?3,first_missing_signal='pid2-routine-held' WHERE schedule_id=?1 AND fire_id=?2 AND state='Running'",params![id,fire,super::now()]).map_err(|e|e.to_string())?;
                if changed!=0 {advance_slot(&tx,id,&fire)?;}
                commit_terminal(tx,id,&fire,changed)?;
                drop(db);
                if changed!=0 {fire_deed(id,&fire,"Refused",0,Some("pid2-routine-held"));}
                return Ok(changed!=0);
            },
            Err(signal)=>return Err(signal),
        }
    } else {None};
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    let tx=db.transaction().map_err(|e|e.to_string())?;
    let signal=unmet(&tx,&raw)?;let now=super::now();
    if let Some(signal)=signal {
        let changed=tx.execute("UPDATE pid2_fires SET state='Refused',finished_at=?3,first_missing_signal=?4 WHERE schedule_id=?1 AND fire_id=?2 AND state='Running'",params![id,fire,now,signal]).map_err(|e|e.to_string())?;
        if changed!=0 {advance_slot(&tx,id,&fire)?;}
        commit_terminal(tx,id,&fire,changed)?;drop(db);if changed!=0 {fire_deed(id,&fire,"Refused",0,Some(&signal));}return Ok(changed!=0);
    }
    let baseline:Option<(i64,i64)>=tx.query_row("SELECT file_count,total_bytes FROM pid2_sync_baselines WHERE schedule_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
    tx.commit().map_err(|e|e.to_string())?;drop(db);
    let started=std::time::Instant::now();
    let baseline=baseline.map(|(f,b)|json!({"fileCount":f,"totalBytes":b}));
    let mut input=if nas_sync {json!({"baseline":baseline,"accept-shrink":false})} else {json!({"action":action,"baseline":baseline,"acceptShrink":false,"dryRun":false})};
    let envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    if let Some(payload)=envelope.pointer("/schedule/job/payload").and_then(Value::as_object) {
        let target=input.as_object_mut().ok_or("pid2-schedule-input-unusable")?;
        for (key,value) in payload { if !matches!(key.as_str(),"action"|"baseline"|"acceptShrink"|"dryRun") && !(nas_sync && key=="accept-shrink") {target.insert(key.clone(),value.clone());} }
    }
    let crossing_band=if nas_sync {"storage/backup/nas-sync/sync"} else {&band};
    let result=crate::gate::snake::schedule_crossing(crossing_band,&input,Duration::from_secs(max as u64));
    let (state,signal,exit,counts)=match result {
        Err(signal)=>("Failed",Some(signal),None,None),
        Ok(result)=>{
            let r=result.get("receiptPayload").unwrap_or(&Value::Null);
            let seat_ok=!nas_sync || (r.get("schema").and_then(Value::as_str)==Some("caduceus.nas.sync.v1") && r.get("action").and_then(Value::as_str)==Some("sync"));
            let outcome_ok=!nas_sync || r.get("outcome").and_then(Value::as_str)==Some("ok");
            let ok=seat_ok && outcome_ok && result.get("ok").and_then(Value::as_bool)==Some(true) && r.get("ok").and_then(Value::as_bool)==Some(true) && r.get("converged").and_then(Value::as_bool)!=Some(false);
            let state=if ok {"Done"} else if r.get("outcome").and_then(Value::as_str)==Some("refused") {"Refused"} else {"Failed"};
            let signal=if ok {None} else if !seat_ok {Some("pid2-schedule-receipt-schema-desync".to_owned())} else {Some(r.get("firstMissingSignal").or_else(||result.get("firstMissingSignal")).and_then(Value::as_str).filter(|s|!s.is_empty() && *s!="none").unwrap_or("pid2-schedule-crossing-failed").to_owned())};
            let counts=match (r.get("finalFileCount").and_then(Value::as_i64),r.get("finalTotalBytes").and_then(Value::as_i64)) {(Some(f),Some(b)) if ok && f>=0 && b>=0=>Some((f,b)),_=>None};
            (state,signal,r.get("rsyncExitCode").and_then(Value::as_i64),counts)
        }
    };
    let elapsed=started.elapsed().as_millis().min(i64::MAX as u128) as i64;
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;let tx=db.transaction().map_err(|e|e.to_string())?;
    let changed=tx.execute("UPDATE pid2_fires SET state=?3,finished_at=?4,duration_ms=?5,first_missing_signal=?6,rsync_exit_code=?7,final_file_count=?8,final_total_bytes=?9 WHERE schedule_id=?1 AND fire_id=?2 AND state='Running'",params![id,fire,state,super::now(),elapsed,signal,exit,counts.map(|v|v.0),counts.map(|v|v.1)]).map_err(|e|e.to_string())?;
    if changed!=0 {advance_slot(&tx,id,&fire)?;}
    if changed!=0 {if let Some((f,b))=counts {tx.execute("INSERT INTO pid2_sync_baselines(schedule_id,file_count,total_bytes,updated_at,fire_id) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(schedule_id) DO UPDATE SET file_count=excluded.file_count,total_bytes=excluded.total_bytes,updated_at=excluded.updated_at,fire_id=excluded.fire_id",params![id,f,b,super::now(),fire]).map_err(|e|e.to_string())?;}}
    commit_terminal(tx,id,&fire,changed)?;drop(db);
    if changed!=0 {fire_deed(id,&fire,state,elapsed,signal.as_deref());}
    Ok(changed!=0)
    })();
    if let Err(signal)=&result {
        // The cached connection or its mutex may itself be the failure.  Use
        // a fresh write connection and touch only the claimed running fire.
        let recovery=(|| -> Result<usize,String> {
            let mut db=rusqlite::Connection::open_with_flags(crate::stats::db_path(),rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE).map_err(|e|e.to_string())?;
            db.busy_timeout(Duration::from_secs(5)).map_err(|e|e.to_string())?;
            let tx=db.transaction().map_err(|e|e.to_string())?;
            let changed=tx.execute("UPDATE pid2_fires SET state='Failed',finished_at=?3,first_missing_signal=?4 WHERE schedule_id=?1 AND fire_id=?2 AND state='Running'",params![id,fire,super::now(),signal]).map_err(|e|e.to_string())?;
            if changed!=0 {advance_slot(&tx,id,&fire)?;}
            commit_terminal(tx,id,&fire,changed)?;
            Ok(changed)
        })();
        match recovery {
            Ok(changed) if changed!=0=>{fire_deed(id,&fire,"Failed",0,Some(signal));return Ok(true);},
            Ok(_)=>{},
            Err(error)=>eprintln!("pid2-fire-failure-record-unavailable: {error}"),
        }
    }
    result
}

fn run_cli(id:&str,options:&[String]) -> i32 {
    let mut round=false; let mut wait=false; let mut deadline=None; let mut n=0;
    while n<options.len() {
        match options[n].as_str() {
            "--round" if !round=>round=true,
            "--wait" if !wait=>wait=true,
            "--deadline-seconds" if deadline.is_none() && n+1<options.len()=>{
                n+=1;
                match options[n].parse::<u64>() {Ok(value) if value>0=>deadline=Some(value),_=>{println!("{}",json!({"ok":false,"signal":"pid2-schedule-arguments-invalid","fire":null}));return 1;}}
            },
            _=>{println!("{}",json!({"ok":false,"signal":"pid2-schedule-arguments-invalid","fire":null}));return 1;}
        }
        n+=1;
    }
    if deadline.is_some() && !wait {println!("{}",json!({"ok":false,"signal":"pid2-schedule-arguments-invalid","fire":null}));return 1;}
    let trigger=if round {"round"} else {"owner"};
    if !wait {
        return match queue(id,trigger,None) {
            Ok(value)=>{println!("{value}");0},
            Err(signal)=>{if round {println!("{}",json!({"ok":false,"signal":signal,"fire":null}));} else {eprintln!("{signal}");}1}
        };
    }
    let mut committed_fire=None;
    let result=(|| -> Result<(Value,i32),String> {
        let begin=std::time::Instant::now();
        if deadline.is_some_and(|seconds|begin.checked_add(Duration::from_secs(seconds)).is_none()) {return Err("pid2-schedule-deadline-unusable".into());}
        let fire=uuid::Uuid::new_v4().simple().to_string();
        let address=fire_address(&fire)?;
        let socket=std::os::unix::net::UnixDatagram::bind_addr(&address).map_err(|e|format!("pid2-schedule-wait-socket: {e}"))?;
        let queued=queue_with_id(id,trigger,None,&fire,true)?;
        committed_fire=Some(fire.clone());
        let max=queued.get("max_seconds").and_then(Value::as_u64).ok_or("pid2-schedule-deadline-unusable")?;
        let seconds=deadline.unwrap_or(max.saturating_add(300));
        let end=begin.checked_add(Duration::from_secs(seconds)).ok_or("pid2-schedule-deadline-unusable")?;
        let mut terminal_notice:Option<Value>=None;
        loop {
            let db=super::read_db()?.ok_or("pid2-schedule-database-unavailable")?;
            let current=fire_row(&db,id,&fire)?;
            drop(db);
            let row=terminal_notice.take().or(current);
            let state=row.as_ref().and_then(|row|row.get("state")).and_then(Value::as_str).unwrap_or("");
            let remaining=end.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {return Ok((json!({"ok":false,"signal":"pid2-schedule-wait-deadline","fire":row}),1));}
            if matches!(state,"Done"|"Refused"|"Failed"|"Interrupted") {
                let ok=state=="Done";
                return Ok((json!({"ok":ok,"fire":row}),if ok {0} else {1}));
            }
            socket.set_read_timeout(Some(remaining)).map_err(|e|e.to_string())?;
            let mut buffer=[0u8;65536];
            match socket.recv(&mut buffer) {
                Ok(count)=>{
                    if let Ok(value)=serde_json::from_slice::<Value>(&buffer[..count]) {
                        if value.get("fire_id").and_then(Value::as_str)==Some(fire.as_str()) && matches!(value.get("state").and_then(Value::as_str),Some("Done"|"Refused"|"Failed"|"Interrupted")) {terminal_notice=Some(value);}
                    }
                },
                Err(error) if matches!(error.kind(),std::io::ErrorKind::WouldBlock|std::io::ErrorKind::TimedOut|std::io::ErrorKind::Interrupted)=>{},
                Err(error)=>return Err(format!("pid2-schedule-wait-socket: {error}")),
            }
        }
    })();
    match result {Ok((value,code))=>{println!("{value}");code},Err(signal)=>{println!("{}",json!({"ok":false,"signal":signal,"fire":committed_fire.map(|fire_id|json!({"fire_id":fire_id}))}));1}}
}

pub fn cli(args:&[String]) -> i32 {
    use std::io::Read;
    let mut raw=Vec::new();
    if let [verb,id,options @ ..]=args {if verb=="run" {return run_cli(id,options);}}
    let result=match args {
        [verb] if verb=="list"=>list(),
        [verb] if verb=="register"=>std::io::stdin().take(1024*1024+1).read_to_end(&mut raw).map_err(|e|e.to_string()).and_then(|_|if raw.len()>1024*1024 {Err("pid2-envelope-too-large".into())} else {register(&raw)}),
        [verb,id] if verb=="status"=>status(id),
        [verb,id] if verb=="enable"=>set_enabled(id,true,false),
        [verb,id] if verb=="disable"=>set_enabled(id,false,false),
        [verb,id] if verb=="update"=>std::io::stdin().take(1024*1024+1).read_to_end(&mut raw).map_err(|e|e.to_string()).and_then(|_|if raw.len()>1024*1024 {Err("pid2-envelope-too-large".into())} else {serde_json::from_slice::<Value>(&raw).map_err(|e|e.to_string()).and_then(|v|update(id,&v))}),
        _=>Err("pid2-schedule-arguments-invalid".into()),
    };
    match result {Ok(value)=>{println!("{value}");0},Err(signal)=>{eprintln!("{signal}");1}}
}

pub fn face(metadata:&Value) -> Result<Value,String> {
    let action=metadata.get("action").and_then(Value::as_str).unwrap_or("");let id="nas-sync";
    match action {
        "sync-now"=>{let fired=queue(id,"owner",None)?;Ok(json!({"schema":"caduceus.nas.sync.v1","ok":true,"action":action,"jobHandle":fired["fire_id"],"status":"queued","progress":0,"firstMissingSignal":null}))},
        "sync-job-status"=>{let handle=metadata.get("jobHandle").or_else(||metadata.get("handle")).and_then(Value::as_str).unwrap_or("");let view=status(id)?;let fire=&view["last_fire"];if fire.get("fire_id").and_then(Value::as_str)!=Some(handle) {return Err("agathodaimon-nas-job-not-found".into());}
            let state=fire["state"].as_str().unwrap_or("Failed");let s=match state {"Queued"=>"queued","Running"=>"running","Done"=>"completed","Refused"=>"refused",_=>"failed"};
            Ok(json!({"schema":"caduceus.nas.sync.v1","ok":true,"action":action,"jobHandle":handle,"status":s,"progress":if ["completed","failed","refused"].contains(&s){100}else{0},"exitCode":fire["rsync_exit_code"],"runOutcome":state,"reason":fire["first_missing_signal"],"runReceipt":null,"firstMissingSignal":null}))},
        "sync-schedule"|"sync-schedule-update"=>{if action=="sync-schedule-update" {update(id,metadata.get("schedule").unwrap_or(&Value::Null))?;}let view=status(id)?;let schedule=&view["schedule"];if schedule.is_null(){return Err("pid2-schedule-not-found".into());}
            Ok(json!({"schema":"caduceus.nas.sync.v1","ok":true,"action":action,"schedule":{"frequency":schedule["frequency"],"time":schedule["time"],"weekday":schedule["weekday"],"enabled":schedule["enabled"]},"timerState":{"enabled":schedule["enabled"],"active":schedule["enabled"],"nextFire":view["next_fire"]},"unitPaths":null,"unitContents":null,"firstMissingSignal":null}))},
        _=>Err("pid2-schedule-action-unknown".into())
    }
}
