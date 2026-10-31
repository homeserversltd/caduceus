//! Calendar registrations and bounded fire deeds in the PID-2 database.
use chrono::{Local, LocalResult, NaiveDate, NaiveTime, TimeZone};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::time::Duration;

const SCHEMA: &str = "caduceus.pid2.schedule.v1";

fn fire_deed(id:&str,fire:&str,outcome:&str,duration_ms:i64,signal:Option<&str>) {
    let _=crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({"organ":"pid2","kind":"schedule-fire","level":"info","ok":signal.is_none(),"message":"schedule fire","attributes_redacted":{"who":"caduceus","verb":"schedule-fire","target":id,"outcome":outcome,"duration_ms":duration_ms,"fire_id":fire,"first_missing_signal":signal}}));
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
fn next_slot(cal: &Calendar, now: i64) -> Option<i64> {
    let today=Local.timestamp_opt(now,0).single()?.date_naive();
    (0..=14).filter_map(|n|today.checked_add_signed(chrono::Duration::days(n))).filter_map(|d|slot_for(d,cal)).filter(|s|*s>now).min()
}
fn cal_from_row(frequency:String,time:String,weekday:Option<String>) -> Calendar { Calendar{frequency,time,weekday} }
fn fire_json(row: &rusqlite::Row<'_>) -> rusqlite::Result<Value> {
    Ok(json!({"fire_id":row.get::<_,String>(0)?,"trigger":row.get::<_,String>(1)?,"state":row.get::<_,String>(2)?,
        "queued_at":row.get::<_,i64>(3)?,"started_at":row.get::<_,Option<i64>>(4)?,"finished_at":row.get::<_,Option<i64>>(5)?,
        "duration_ms":row.get::<_,Option<i64>>(6)?,"first_missing_signal":row.get::<_,Option<String>>(7)?,
        "rsync_exit_code":row.get::<_,Option<i64>>(8)?,"final_file_count":row.get::<_,Option<i64>>(9)?,"final_total_bytes":row.get::<_,Option<i64>>(10)?}))
}

pub fn status(id:&str) -> Result<Value,String> {
    let Some(db)=super::read_db()? else {return Ok(json!({"schedule":null,"next_fire":null,"last_fire":null,"baseline":null}));};
    if !super::table_exists(&db,"pid2_schedules")? {return Ok(json!({"schedule":null,"next_fire":null,"last_fire":null,"baseline":null}));}
    let row:Option<(bool,Vec<u8>,String,String,Option<String>,String,String,i64,i64,i64,Option<i64>)>=db.query_row(
        "SELECT enabled,envelope,frequency,time,weekday,band,action,max_seconds,registered_at,updated_at,last_fired_slot FROM pid2_schedules WHERE schedule_id=?1",[id],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?))).optional().map_err(|e|e.to_string())?;
    let Some((enabled,raw,frequency,time,weekday,band,action,max_seconds,registered_at,updated_at,last_fired_slot))=row else {return Ok(json!({"schedule":null,"next_fire":null,"last_fire":null,"baseline":null}));};
    let envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    let cal=cal_from_row(frequency.clone(),time.clone(),weekday.clone());
    let next=if enabled {next_slot(&cal,super::now()).and_then(|v|chrono::DateTime::from_timestamp(v,0)).map(|v|v.with_timezone(&Local).to_rfc3339())} else {None};
    let fire=if super::table_exists(&db,"pid2_fires")? {db.query_row("SELECT fire_id,trigger,state,queued_at,started_at,finished_at,duration_ms,first_missing_signal,rsync_exit_code,final_file_count,final_total_bytes FROM pid2_fires WHERE schedule_id=?1",[id],fire_json).optional().map_err(|e|e.to_string())?} else {None};
    let baseline=if super::table_exists(&db,"pid2_sync_baselines")? {db.query_row("SELECT file_count,total_bytes,updated_at,fire_id FROM pid2_sync_baselines WHERE schedule_id=?1",[id],|r|Ok(json!({"fileCount":r.get::<_,i64>(0)?,"totalBytes":r.get::<_,i64>(1)?,"updated_at":r.get::<_,i64>(2)?,"fire_id":r.get::<_,String>(3)?}))).optional().map_err(|e|e.to_string())?} else {None};
    Ok(json!({"schedule":{"schedule_id":id,"enabled":enabled,"frequency":frequency,"time":time,"weekday":weekday,"band":band,"action":action,"max_seconds":max_seconds,"registered_at":registered_at,"updated_at":updated_at,"last_fired_slot":last_fired_slot,"envelope":envelope,"raw_envelope":String::from_utf8(raw).map_err(|e|e.to_string())?},"next_fire":next,"last_fire":fire,"baseline":baseline}))
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
    let cal=calendar(spec.get("calendar").unwrap_or(&Value::Null))?;
    let job=spec.get("job").unwrap_or(&Value::Null);
    let band=job.get("band").and_then(Value::as_str).filter(|s|!s.is_empty()).ok_or("pid2-schedule-band-unusable")?;
    let action=job.get("action").and_then(Value::as_str).filter(|s|!s.is_empty()).ok_or("pid2-schedule-action-unusable")?;
    let max=match job.get("max_seconds") {None|Some(Value::Null)=>21600,Some(value)=>value.as_u64().ok_or("pid2-schedule-deadline-unusable")?};
    if !(1..=86400).contains(&max) {return Err("pid2-schedule-deadline-unusable".into());}
    let now=super::now(); let slot=previous_slot(&cal,now);
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    super::tables(&db)?;
    db.execute("INSERT INTO pid2_schedules(schedule_id,enabled,envelope,frequency,time,weekday,band,action,max_seconds,registered_at,updated_at,last_fired_slot) VALUES(?1,1,?2,?3,?4,?5,?6,?7,?8,?9,?9,?10) ON CONFLICT(schedule_id) DO UPDATE SET envelope=excluded.envelope,frequency=excluded.frequency,time=excluded.time,weekday=excluded.weekday,band=excluded.band,action=excluded.action,max_seconds=excluded.max_seconds,updated_at=excluded.updated_at,last_fired_slot=excluded.last_fired_slot",params![id,raw,cal.frequency,cal.time,cal.weekday,band,action,max as i64,now,slot]).map_err(|e|e.to_string())?;
    drop(db); super::solver::deed("schedule-register",id,"success",None); super::events::notify();
    Ok(json!({"ok":true,"readback":status(id)?}))
}

pub fn set_enabled(id:&str,enabled:bool,missing_noop:bool) -> Result<Value,String> {
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?; super::tables(&db)?;
    let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM pid2_schedules WHERE schedule_id=?1)",[id],|r|r.get(0)).map_err(|e|e.to_string())?;
    if !exists && !missing_noop {return Err("pid2-schedule-not-found".into());}
    let changed=db.execute("UPDATE pid2_schedules SET enabled=?2,updated_at=?3 WHERE schedule_id=?1 AND enabled<>?2",params![id,enabled,super::now()]).map_err(|e|e.to_string())?;
    drop(db); if changed!=0 {super::solver::deed(if enabled {"schedule-enable"} else {"schedule-disable"},id,"success",None);super::events::notify();}
    Ok(json!({"ok":true,"changed":changed!=0,"readback":status(id)?}))
}
pub fn update(id:&str,patch:&Value) -> Result<Value,String> {
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?; super::tables(&db)?;
    let tx=db.transaction().map_err(|e|e.to_string())?;
    let row:Option<(Vec<u8>,String,String,Option<String>,bool)>=tx.query_row("SELECT envelope,frequency,time,weekday,enabled FROM pid2_schedules WHERE schedule_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?;
    let (raw,frequency,time,weekday,old_enabled)=row.ok_or("pid2-schedule-not-found")?;
    let mut input=json!({"frequency":frequency,"time":time,"weekday":weekday});
    for key in ["frequency","time","weekday","at","day"] {if let Some(v)=patch.get(key) {input[key]=v.clone();}}
    if patch.get("time").is_none() {if let Some(v)=patch.get("at") {input["time"]=v.clone();}}
    if patch.get("weekday").is_none() {if let Some(v)=patch.get("day") {input["weekday"]=v.clone();}}
    let cal=calendar(&input)?; let enabled=patch.get("enabled").and_then(Value::as_bool).unwrap_or(old_enabled);
    let mut envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    let target=envelope.pointer_mut("/schedule/calendar").and_then(Value::as_object_mut).ok_or("pid2-schedule-calendar-unusable")?;
    target.insert("frequency".into(),json!(cal.frequency));target.insert("time".into(),json!(cal.time));target.insert("weekday".into(),json!(cal.weekday));
    let encoded=serde_json::to_vec(&envelope).map_err(|e|e.to_string())?;
    let changed=tx.execute("UPDATE pid2_schedules SET envelope=?2,frequency=?3,time=?4,weekday=?5,enabled=?6,updated_at=?7,last_fired_slot=?8 WHERE schedule_id=?1",params![id,encoded,cal.frequency,cal.time,cal.weekday,enabled,super::now(),previous_slot(&cal,super::now())]).map_err(|e|e.to_string())?;
    tx.commit().map_err(|e|e.to_string())?;drop(db);
    if changed!=0 {super::solver::deed("schedule-update",id,"success",None);super::events::notify();}
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
pub fn queue(id:&str,trigger:&str,slot:Option<i64>) -> Result<Value,String> {
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?; super::tables(&db)?;
    let tx=db.transaction().map_err(|e|e.to_string())?;
    let raw:Vec<u8>=tx.query_row("SELECT envelope FROM pid2_schedules WHERE schedule_id=?1",[id],|r|r.get(0)).optional().map_err(|e|e.to_string())?.ok_or("pid2-schedule-not-found")?;
    let active:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pid2_fires WHERE schedule_id=?1 AND state IN ('Queued','Running'))",[id],|r|r.get(0)).map_err(|e|e.to_string())?;
    if active {drop(tx);drop(db);fire_deed(id,&uuid::Uuid::new_v4().simple().to_string(),"Refused",0,Some("pid2-schedule-fire-running"));return Err("pid2-schedule-fire-running".into());}
    let signal=unmet(&tx,&raw)?; let fire_id=uuid::Uuid::new_v4().simple().to_string(); let now=super::now();
    let state=if signal.is_some() {"Refused"} else {"Queued"};
    tx.execute("INSERT INTO pid2_fires(schedule_id,fire_id,trigger,state,queued_at,finished_at,first_missing_signal) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(schedule_id) DO UPDATE SET fire_id=excluded.fire_id,trigger=excluded.trigger,state=excluded.state,queued_at=excluded.queued_at,started_at=NULL,finished_at=excluded.finished_at,duration_ms=NULL,first_missing_signal=excluded.first_missing_signal,rsync_exit_code=NULL,final_file_count=NULL,final_total_bytes=NULL",params![id,fire_id,trigger,state,now,if signal.is_some(){Some(now)}else{None},signal]).map_err(|e|e.to_string())?;
    if let Some(slot)=slot {tx.execute("UPDATE pid2_schedules SET last_fired_slot=?2 WHERE schedule_id=?1",params![id,slot]).map_err(|e|e.to_string())?;}
    tx.commit().map_err(|e|e.to_string())?;drop(db);
    if let Some(signal)=signal {fire_deed(id,&fire_id,"Refused",0,Some(&signal));return Err(signal);}
    super::events::notify();Ok(json!({"ok":true,"fire_id":fire_id,"state":"Queued"}))
}

/// Return the next clock delay and queue any missed slots. No periodic polling.
pub fn clock(catchup:bool) -> Result<Duration,String> {
    let Some(db)=super::read_db()? else {return Ok(Duration::from_secs(86400*365));};
    if !super::table_exists(&db,"pid2_schedules")? {return Ok(Duration::from_secs(86400*365));}
    let mut q=db.prepare("SELECT schedule_id,frequency,time,weekday,last_fired_slot FROM pid2_schedules WHERE enabled=1 ORDER BY schedule_id").map_err(|e|e.to_string())?;
    let rows=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,Option<String>>(3)?,r.get::<_,Option<i64>>(4)?))).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    drop(q);drop(db);let now=super::now();let mut earliest=None;
    for (id,frequency,time,weekday,last) in rows {
        let cal=cal_from_row(frequency,time,weekday);
        if let Some(slot)=previous_slot(&cal,now).filter(|slot|last.is_some_and(|last|*slot>last)) {
            if let Err(signal)=queue(&id,if catchup {"catch-up"} else {"calendar"},Some(slot)) {
                if signal=="pid2-schedule-fire-running" {
                    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                    db.execute("UPDATE pid2_schedules SET last_fired_slot=?2 WHERE schedule_id=?1",params![id,slot]).map_err(|e|e.to_string())?;
                }
            }
        }
        if let Some(next)=next_slot(&cal,now) {earliest=Some(earliest.map_or(next,|old:i64|old.min(next)));}
    }
    Ok(Duration::from_secs(earliest.map(|v|(v-now).max(0) as u64).unwrap_or(86400*365)))
}

pub fn queued() -> Result<Vec<String>,String> {
    let Some(db)=super::read_db()? else {return Ok(vec![]);};
    if !super::table_exists(&db,"pid2_fires")? {return Ok(vec![]);}
    let mut q=db.prepare("SELECT schedule_id FROM pid2_fires WHERE state='Queued'").map_err(|e|e.to_string())?;
    let rows=q.query_map([],|r|r.get(0)).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    Ok(rows)
}

pub fn execute(id:&str) -> Result<(),String> {
    // A NAS fire and a NAS role swap must never cross the staff concurrently.
    // The shared nonblocking lease is held until the crossing has ended.
    let nas_job=status(id)?.pointer("/schedule/band").and_then(Value::as_str)==Some("storage/backup/nas-sync");
    let _nas_lease=if nas_job {
        match super::swap_lease() {
            Ok(lease)=>Some(lease),
            Err(signal) if signal=="pid2-swap-busy"=>{
                let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                let fire:Option<String>=db.query_row("SELECT fire_id FROM pid2_fires WHERE schedule_id=?1 AND state='Queued'",[id],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
                if let Some(fire)=fire {
                    let changed=db.execute("UPDATE pid2_fires SET state='Refused',finished_at=?3,first_missing_signal='pid2-routine-held' WHERE schedule_id=?1 AND fire_id=?2 AND state='Queued'",params![id,fire,super::now()]).map_err(|e|e.to_string())?;
                    drop(db);
                    if changed!=0 {fire_deed(id,&fire,"Refused",0,Some("pid2-routine-held"));}
                }
                return Ok(());
            },
            Err(signal)=>return Err(signal),
        }
    } else {None};
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    super::tables(&db)?;
    let tx=db.transaction().map_err(|e|e.to_string())?;
    let row:Option<(String,Vec<u8>,String,String,i64)>=tx.query_row("SELECT f.fire_id,s.envelope,s.band,s.action,s.max_seconds FROM pid2_fires f JOIN pid2_schedules s ON s.schedule_id=f.schedule_id WHERE f.schedule_id=?1 AND f.state='Queued'",[id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?;
    let Some((fire,raw,band,action,max))=row else {return Ok(());};
    let signal=unmet(&tx,&raw)?;let now=super::now();
    if let Some(signal)=signal {
        tx.execute("UPDATE pid2_fires SET state='Refused',finished_at=?2,first_missing_signal=?3 WHERE schedule_id=?1",params![id,now,signal]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e|e.to_string())?;drop(db);fire_deed(id,&fire,"Refused",0,Some(&signal));return Ok(());
    }
    let baseline:Option<(i64,i64)>=tx.query_row("SELECT file_count,total_bytes FROM pid2_sync_baselines WHERE schedule_id=?1",[id],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e|e.to_string())?;
    tx.execute("UPDATE pid2_fires SET state='Running',started_at=?2 WHERE schedule_id=?1 AND fire_id=?3 AND state='Queued'",params![id,now,fire]).map_err(|e|e.to_string())?;
    tx.commit().map_err(|e|e.to_string())?;drop(db);
    let started=std::time::Instant::now();
    let input=json!({"action":action,"baseline":baseline.map(|(f,b)|json!({"fileCount":f,"totalBytes":b})),"acceptShrink":false,"dryRun":false});
    let result=crate::gate::snake::schedule_crossing(&band,&input,Duration::from_secs(max as u64));
    let (state,signal,exit,counts)=match result {
        Err(signal)=>("Failed",Some(signal),None,None),
        Ok(result)=>{
            let r=result.get("receiptPayload").unwrap_or(&Value::Null);
            let seat_ok=band!="storage/backup/nas-sync" || (r.get("schema").and_then(Value::as_str)==Some("caduceus.nas.sync.v1") && r.get("action").and_then(Value::as_str)==Some("sync"));
            let outcome_ok=band!="storage/backup/nas-sync" || r.get("outcome").and_then(Value::as_str)==Some("ok");
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
    if changed!=0 {if let Some((f,b))=counts {tx.execute("INSERT INTO pid2_sync_baselines(schedule_id,file_count,total_bytes,updated_at,fire_id) VALUES(?1,?2,?3,?4,?5) ON CONFLICT(schedule_id) DO UPDATE SET file_count=excluded.file_count,total_bytes=excluded.total_bytes,updated_at=excluded.updated_at,fire_id=excluded.fire_id",params![id,f,b,super::now(),fire]).map_err(|e|e.to_string())?;}}
    tx.commit().map_err(|e|e.to_string())?;drop(db);
    if changed!=0 {fire_deed(id,&fire,state,elapsed,signal.as_deref());}
    super::events::notify();Ok(())
}

pub fn cli(args:&[String]) -> i32 {
    use std::io::Read;
    let mut raw=Vec::new();
    let result=match args {
        [verb] if verb=="list"=>list(),
        [verb] if verb=="register"=>std::io::stdin().take(1024*1024+1).read_to_end(&mut raw).map_err(|e|e.to_string()).and_then(|_|if raw.len()>1024*1024 {Err("pid2-envelope-too-large".into())} else {register(&raw)}),
        [verb,id] if verb=="status"=>status(id),
        [verb,id] if verb=="enable"=>set_enabled(id,true,false),
        [verb,id] if verb=="disable"=>set_enabled(id,false,false),
        [verb,id] if verb=="run"=>queue(id,"owner",None),
        [verb,id] if verb=="update"=>std::io::stdin().take(1024*1024+1).read_to_end(&mut raw).map_err(|e|e.to_string()).and_then(|_|if raw.len()>1024*1024 {Err("pid2-envelope-too-large".into())} else {serde_json::from_slice::<Value>(&raw).map_err(|e|e.to_string()).and_then(|v|update(id,v.get("calendar").unwrap_or(&v)))}),
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
