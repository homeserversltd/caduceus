//! Level-triggered reconciliation: events are hints, current observations are truth.
use super::{now, tables};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::{collections::{BTreeMap,HashMap,HashSet,VecDeque}, path::Path, sync::atomic::{AtomicU64,Ordering}};
static REVISION: AtomicU64 = AtomicU64::new(0);

fn line(routine: &str, name: &str) -> Result<Option<(Option<String>, String)>, String> {
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    db.query_row("SELECT value,state FROM pid2_lines WHERE routine_id=?1 AND line=?2", params![routine,name], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e| e.to_string())
}

fn held(routine: &str) -> Result<bool,String> {
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    db.query_row("SELECT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",[routine],|r|r.get(0)).map_err(|e|e.to_string())
}

fn write_line_changed(routine: &str, name: &str, value: Option<&str>, state: &str, reason: Option<&str>) -> Result<bool, String> {
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    // An observation is a boot-scoped election: no wake may replace it.
    let changed = db.execute("INSERT INTO pid2_lines(routine_id,line,value,state,observed_at,reason) SELECT ?1,?2,?3,?4,?5,?6 WHERE NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1) ON CONFLICT(routine_id,line) DO UPDATE SET value=excluded.value,state=excluded.state,observed_at=excluded.observed_at,reason=excluded.reason WHERE pid2_lines.state <> 'Observed' AND (pid2_lines.value IS NOT excluded.value OR pid2_lines.state IS NOT excluded.state OR pid2_lines.reason IS NOT excluded.reason)",params![routine,name,value,state,now(),reason]).map_err(|e| e.to_string())?;
    drop(db);
    if changed != 0 { REVISION.fetch_add(1,Ordering::Relaxed); deed("line", &format!("{routine}/{name}"), state, reason); }
    Ok(changed != 0)
}

fn write_line(routine: &str, name: &str, value: Option<&str>, state: &str, reason: Option<&str>) -> Result<(), String> {
    write_line_changed(routine, name, value, state, reason).map(|_| ())
}

pub(super) fn deed(verb: &str, target: &str, outcome: &str, signal: Option<&str>) {
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ":"pid2", "kind":verb, "level":"info", "ok":signal.is_none(),
        "message":"pid2 state changed", "attributes_redacted":{"who":"caduceus","verb":verb,"target":target,"outcome":outcome,"signal":signal,"duration_ms":0}
    }));
}

fn unit_entry(unit: &str) -> Result<&'static Value, String> {
    let seat = crate::routes::leaf_schema::declaration(super::SCHEMA).ok_or("pid2-schema-seat-missing")?;
    seat.get("unit_enum").and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.get("unit").and_then(Value::as_str)==Some(unit))).ok_or_else(|| "pid2-unit-not-declared".into())
}
pub(super) fn unit_scope(unit: &str) -> Result<String, String> {
    unit_entry(unit)?.get("scope").and_then(Value::as_str).map(str::to_owned).ok_or_else(||"pid2-unit-scope-missing".into())
}

fn unit_call(action: &str, unit: &str, scope: &str) -> Result<Value, String> {
    unit_call_timeout(action,unit,scope,std::time::Duration::from_secs(300))
}
fn unit_call_timeout(action: &str, unit: &str, scope: &str, timeout: std::time::Duration) -> Result<Value, String> {
    if unit_scope(unit)? != scope { return Err("pid2-unit-scope-mismatch".into()); }
    if action == "status" { return Err("pid2-status-must-use-cache".into()); }
    if unit_entry(unit)?.get("observe_only").and_then(Value::as_bool)==Some(true) { return Err("pid2-unit-observe-only".into()); }
    let result = crate::routes::leaf_pid2::unit_control_with_timeout(&json!({"action":action,"unit":unit,"scope":scope}),timeout);
    deed(action, unit, if result.is_ok() {"attempted"} else {"held"}, result.as_ref().err().map(String::as_str));
    result
}

pub(super) fn unit_status(unit: &str, scope: &str) -> Result<Value, String> {
    if unit_scope(unit)? != scope { return Err("pid2-unit-scope-mismatch".into()); }
    let state=crate::stats::indicators::unit_state::observed(scope,unit).ok_or("pid2-unit-state-unobserved")?;
    Ok(json!({"ok":true,"readback":{"active_state":state.active_state,"sub_state":state.sub_state,"load_state":state.load_state,"unit_file_state":null}}))
}

fn running(unit: &str, scope: &str) -> Result<bool, String> {
    let response = unit_status(unit,scope)?;
    match response.pointer("/readback/active_state").and_then(Value::as_str) {
        Some("active")=>Ok(true), Some("inactive"|"failed")=>Ok(false), Some(_)=>Err("pid2-unit-transitioning".into()), None=>Err("pid2-unit-state-unobserved".into())
    }
}

fn program(routine: &str, unit: &str, scope: &str) -> Result<(String,String,Option<String>),String> {
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    let changed=db.execute("INSERT OR IGNORE INTO pid2_programs(unit,scope,routine_id,desired,life,updated_at) VALUES(?1,?2,?3,'Run','Waiting',?4)",params![unit,scope,routine,now()]).map_err(|e|e.to_string())?;
    let result=db.query_row("SELECT desired,life,last_receipt FROM pid2_programs WHERE unit=?1 AND scope=?2 AND routine_id=?3",params![unit,scope,routine],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|e.to_string())?;
    drop(db);
    if changed!=0 { REVISION.fetch_add(1,Ordering::Relaxed); deed("program",unit,"Waiting",None); }
    Ok(result)
}

fn program_state(routine: &str, unit: &str, scope: &str, life: &str, signal: Option<&str>) -> Result<(),String> {
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    let changed=db.execute("UPDATE pid2_programs SET life=?1,last_receipt=?2,updated_at=?3 WHERE unit=?4 AND scope=?5 AND routine_id=?6 AND (life IS NOT ?1 OR last_receipt IS NOT ?2)",params![life,signal,now(),unit,scope,routine]).map_err(|e|e.to_string())?;
    drop(db);
    if changed != 0 { REVISION.fetch_add(1,Ordering::Relaxed); deed("program",unit,life,signal); }
    Ok(())
}

fn require_current_stage(routine: &str, expected_stage: &Value) -> Result<(),String> {
    let raw:Option<Vec<u8>> = {
        let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        db.query_row("SELECT envelope FROM pid2_registrations WHERE routine_id=?1 AND enabled=1",[routine],|r|r.get(0)).optional().map_err(|e|e.to_string())?
    };
    let raw=raw.ok_or("pid2-routine-disabled")?;
    let current:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    if !current.pointer("/routine/stages").and_then(Value::as_array).is_some_and(|stages|stages.contains(expected_stage)) { return Err("pid2-routine-changed".into()); }
    Ok(())
}
fn needs_token(line: &str, trace: &[Value]) -> String {
    format!("{}\0{:x}",line,md5::compute(serde_json::to_vec(trace).unwrap_or_default()))
}

fn route_stage(routine:&str, name:&str, stage:&Value, steps:&[Value], token:&str, visiting:&mut Visiting) -> Result<(),String> {
    let key=(routine.to_owned(),name.to_owned());
    if visiting.attempted.contains(&key) {return Ok(());}
    let _action=super::ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
    let _process=super::process_action_lock()?;
    if held(routine)? {return Ok(());}
    require_current_stage(routine,stage)?;
    visiting.attempted.insert(key);
    let mut line_signal=None;
    for (index,step) in steps.iter().enumerate() {
        let route=step.get("route").and_then(Value::as_str).ok_or("pid2-route-name-missing")?;
        let mut seen=std::collections::HashSet::new();
        let Some(keep)=step.get("keep").and_then(Value::as_array).filter(|values|!values.is_empty() && values.iter().all(|v|v.as_str().is_some_and(|s|s.len()<=64 && seen.insert(s.to_owned())))) else {
            return write_line(routine,name,None,"Held",Some("pid2-route-keep-invalid"));
        };
        let previous:Option<(String,Option<i64>,Option<bool>,Option<String>)>={
            let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
            db.query_row("SELECT needs_token,deadline,ok,first_missing_signal FROM pid2_route_steps WHERE routine_id=?1 AND line=?2 AND step_index=?3",params![routine,name,index as i64],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional().map_err(|e|e.to_string())?
        };
        let due=previous.as_ref().is_none_or(|(old,deadline,_,_)|old!=token || deadline.is_some_and(|d|d<=now()));
        if !due {
            if let Some((_,_,Some(false),signal))=previous {line_signal=Some(signal.unwrap_or_else(||"pid2-route-refused".into()));break;}
            continue;
        }
        let keep:Vec<String>=keep.iter().filter_map(Value::as_str).map(str::to_owned).collect();
        let seconds=step.get("deadline_seconds").and_then(Value::as_u64).unwrap_or(180);
        let reply=crate::gate::pid2_route::call(route,step.get("payload"),&keep,seconds);
        let recorded=now();
        let (status,ok,signal,kept,deadline)=match reply {
            Ok(value)=>{
                let deadline=value.fresh_until.filter(|v|v.is_finite() && *v > recorded as f64 && *v <= i64::MAX as f64).map(|v|v.ceil() as i64);
                (Some(value.status),value.ok,value.signal,value.kept,deadline)
            },
            Err(signal)=>(None,Some(false),Some(signal),"{}".to_owned(),None),
        };
        {
            let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
            db.execute("INSERT INTO pid2_route_steps(routine_id,line,step_index,route,response_status,ok,first_missing_signal,kept,needs_token,deadline,recorded_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) ON CONFLICT(routine_id,line,step_index) DO UPDATE SET route=excluded.route,response_status=excluded.response_status,ok=excluded.ok,first_missing_signal=excluded.first_missing_signal,kept=excluded.kept,needs_token=excluded.needs_token,deadline=excluded.deadline,recorded_at=excluded.recorded_at",params![routine,name,index as i64,route,status,ok,signal,kept,token,deadline,recorded]).map_err(|e|e.to_string())?;
        }
        deed("route",&format!("{routine}/{name}/{index}"),if ok==Some(false) {"Held"} else {"Done"},signal.as_deref());
        if route=="transmission/status" {let _=crate::stats::poke(crate::stats::IndicatorBlock::Vpn);}
        super::events::notify_schedule()?;
        if ok==Some(false) {line_signal=Some(signal.unwrap_or_else(||"pid2-route-refused".into()));break;}
    }
    match line_signal {Some(signal)=>write_line(routine,name,None,"Held",Some(&signal)),None=>write_line(routine,name,Some("true"),"Done",None)}
}

fn attempt_receipt(kind:&str, mark:&(String,u64)) -> String {
    json!({"kind":kind,"sense":mark.0,"sequence":mark.1}).to_string()
}
fn receipt_mark(receipt:Option<&str>) -> Option<(String,u64)> {
    let value:Value=serde_json::from_str(receipt?).ok()?;
    Some((value.get("sense")?.as_str()?.to_owned(),value.get("sequence")?.as_u64()?))
}
fn failed_receipt(cause: &str, needs: &str, mark:Option<&(String,u64)>) -> String {
    json!({"cause":cause,"needs":needs,"sense":mark.map(|m|&m.0),"sequence":mark.map(|m|m.1)}).to_string()
}

fn failed_cause(receipt: Option<&str>) -> String {
    let Some(receipt)=receipt else { return "pid2-unit-failed".into(); };
    serde_json::from_str::<Value>(receipt).ok().and_then(|v|v.get("cause").and_then(Value::as_str).map(str::to_owned)).unwrap_or_else(||receipt.to_owned())
}

fn rearm_changed_needs(routine: &str, stage: &Value, token: &str) -> Result<(),String> {
    for action in stage.get("actions").and_then(Value::as_array).into_iter().flatten() {
        let Some(unit)=action.get("unit").and_then(Value::as_str) else { continue; };
        let Ok(scope)=unit_scope(unit) else { continue; };
        let (_,life,receipt)=program(routine,unit,&scope)?;
        if life!="Failed" { continue; }
        let old=receipt.as_deref().and_then(|r|serde_json::from_str::<Value>(r).ok());
        if old.as_ref().and_then(|v|v.get("needs")).and_then(Value::as_str).is_some_and(|n|n!=token && n.split('\0').next()==token.split('\0').next()) {
            program_state(routine,unit,&scope,"Waiting",None)?;
        }
    }
    Ok(())
}

fn ensure_running(routine: &str, unit: &str, scope: &str, expected_stage: &Value, needs: &str) -> Result<bool,String> {
    // The caller holds the cross-process walk lock for the entire walk;
    // unit commands and hold/release acquire it before changing intent.
    if held(routine)? { return Err("pid2-routine-held".into()); }
    require_current_stage(routine,expected_stage)?;
    let (desired,mut life,receipt) = program(routine,unit,scope)?;
    if life == "Failed" {
        let cause=failed_cause(receipt.as_deref());
        if cause.starts_with("pid2-stop") || desired!="Run" { return Err(cause); }
        let mark=receipt_mark(receipt.as_deref());
        let current=super::events::transition_mark();
        let (active,inactive)=super::events::unit_transitions(scope,unit);
        let floor=mark.as_ref().filter(|m|m.0==current.0).map(|m|m.1).unwrap_or(0);
        return match running(unit,scope) {
            Ok(true) if mark.is_some() && active>inactive && active>floor && (mark.as_ref().is_some_and(|m|m.0==current.0) || inactive>floor) => {
                let observed=(current.0,inactive);
                program_state(routine,unit,scope,"Running",Some(&attempt_receipt("pid2-started",&observed)))?; Ok(true)
            },
            _ => Err(cause),
        };
    }
    if desired != "Run" { return Err("pid2-program-stopped-by-owner".into()); }
    if life == "Stopping" {
        if receipt.as_deref() != Some("stop-accepted") {
            match unit_call("stop",unit,scope) {
                Ok(reply) if reply.get("ok").and_then(Value::as_bool)==Some(true) => { program_state(routine,unit,scope,"Stopping",Some("stop-accepted"))?; return Ok(false); },
                Ok(_) => { program_state(routine,unit,scope,"Failed",Some(&failed_receipt("pid2-stop-refused",needs,None)))?; return Err("pid2-stop-refused".into()); },
                Err(error) => { let cause=format!("pid2-stop: {error}"); program_state(routine,unit,scope,"Failed",Some(&failed_receipt(&cause,needs,None)))?; return Err(cause); }
            }
        }
        if running(unit,scope)? { return Ok(false); }
        life = "Queued".into();
    }
    match running(unit,scope) {
        Ok(true) => {
            if (life=="Starting" || life=="Running") && receipt_mark(receipt.as_deref()).is_some() {
                let mark=receipt_mark(receipt.as_deref()).expect("checked");
                program_state(routine,unit,scope,"Running",Some(&attempt_receipt("pid2-started",&mark)))?;
            } else { program_state(routine,unit,scope,"Running",Some("active"))?; }
            Ok(true)
        },
        Ok(false) => {
            let mark=receipt_mark(receipt.as_deref());
            let current=super::events::transition_mark();
            let (_,inactive)=super::events::unit_transitions(scope,unit);
            let settled=mark.as_ref().is_some_and(|m| inactive>if m.0==current.0 {m.1} else {0});
            if (life=="Starting" && settled) || life=="Running" {
                let error=if life=="Starting" {"pid2-start-unit-not-active"} else {"pid2-unit-stopped-unexpectedly"};
                let failed_mark=super::events::transition_mark();
                program_state(routine,unit,scope,"Failed",Some(&failed_receipt(error,needs,Some(&failed_mark))))?;
                return Err(error.into());
            }
            if life != "Starting" {
                let mark=super::events::transition_mark();
                program_state(routine,unit,scope,"Starting",Some(&attempt_receipt("start-ordered",&mark)))?;
                match unit_call("start",unit,scope) {
                    Ok(reply) if reply.get("ok").and_then(Value::as_bool)==Some(true) => program_state(routine,unit,scope,"Starting",Some(&attempt_receipt("start-accepted",&mark)))?,
                    Ok(_) => { let failed_mark=super::events::transition_mark(); program_state(routine,unit,scope,"Failed",Some(&failed_receipt("pid2-start-refused",needs,Some(&failed_mark))))?; return Err("pid2-start-refused".into()); },
                    Err(error) => { let failed_mark=super::events::transition_mark(); program_state(routine,unit,scope,"Failed",Some(&failed_receipt(&error,needs,Some(&failed_mark))))?; return Err(error); }
                }
            }
            Ok(false)
        },
        Err(error) if error == "pid2-unit-transitioning" && life == "Starting" => Ok(false),
        Err(error) if life=="Starting" || life=="Running" => Err(error),
        Err(error) => { program_state(routine,unit,scope,"Held",Some(&error))?; Err(error) }
    }
}

fn glob(pattern: &str, value: &str) -> bool {
    // The declared connector pattern uses '*' as the only wildcard.
    let parts: Vec<_> = pattern.split('*').collect();
    if parts.len()==1 { return pattern==value; }
    if !value.starts_with(parts[0]) || !value.ends_with(parts[parts.len()-1]) { return false; }
    let mut remaining = &value[parts[0].len()..];
    for part in &parts[1..parts.len()-1] {
        let Some(pos) = remaining.find(part) else { return false; };
        remaining = &remaining[pos+part.len()..];
    }
    remaining.len() >= parts[parts.len()-1].len()
}

pub fn observe_drm(pattern: &str) -> Result<String, String> {
    let dir = std::fs::read_dir("/sys/class/drm").map_err(|e| format!("pid2-drm-unavailable: {e}"))?;
    let mut enumerated = false;
    let mut unknown = false;
    for entry in dir {
        let entry = entry.map_err(|e| format!("pid2-drm-read-failed: {e}"))?;
        let path = entry.path().join("status");
        if !path.exists() { continue; }
        enumerated = true;
        let name = entry.file_name();
        if !glob(pattern, &name.to_string_lossy()) { continue; }
        let status = std::fs::read_to_string(path).map_err(|e| format!("pid2-drm-status-unavailable: {e}"))?;
        match status.trim() { "connected" => return Ok("present".into()), "disconnected" => {}, _ => unknown = true }
    }
    if !enumerated { return Err("pid2-drm-connectors-not-enumerated".into()); }
    if unknown { return Err("pid2-drm-connector-state-unknown".into()); }
    Ok("absent".into())
}

pub(super) fn watched_mounts() -> Result<HashSet<std::path::PathBuf>,String> {
    let Some(db)=super::read_db()? else { return Ok(HashSet::new()); };
    if !super::table_exists(&db,"pid2_registrations")? { return Ok(HashSet::new()); }
    let mut result=HashSet::new();
    let mut query=db.prepare("SELECT envelope FROM pid2_registrations WHERE enabled=1").map_err(|e|e.to_string())?;
    let mut rows=query.query([]).map_err(|e|e.to_string())?;
    while let Some(row)=rows.next().map_err(|e|e.to_string())? {
        let raw:Vec<u8>=row.get(0).map_err(|e|e.to_string())?;
        let envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        for stage in envelope.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten() {
            for key in ["needs","until"] {
                for need in stage.get(key).and_then(Value::as_array).into_iter().flatten() {
                    if need.get("kind").and_then(Value::as_str)==Some("await-mount") {
                        if let Some(path)=need.get("path").and_then(Value::as_str) { result.insert(std::path::PathBuf::from(path)); }
                    }
                }
            }
        }
    }
    Ok(result)
}

// Install only facts named by enabled routine needs, including until needs.
pub(super) fn watched_kernel() -> Result<super::events::kernel_senses::Watched,String> {
    let Some(db)=super::read_db()? else { return Ok(Default::default()); };
    if !super::table_exists(&db,"pid2_registrations")? { return Ok(Default::default()); }
    let mut watched=super::events::kernel_senses::Watched::default();
    let mut query=db.prepare("SELECT envelope FROM pid2_registrations WHERE enabled=1").map_err(|e|e.to_string())?;
    let mut rows=query.query([]).map_err(|e|e.to_string())?;
    while let Some(row)=rows.next().map_err(|e|e.to_string())? {
        let raw:Vec<u8>=row.get(0).map_err(|e|e.to_string())?;
        let envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        for stage in envelope.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten() {
            for field in ["needs","until"] {
                for need in stage.get(field).and_then(Value::as_array).into_iter().flatten() {
                    match need.get("kind").and_then(Value::as_str) {
                        Some("await-netns") => if let Some(name)=need.get("name").and_then(Value::as_str) { watched.names.insert(name.to_owned()); },
                        Some("observe-link") => if let (Some(ns),Some(link))=(need.get("netns").and_then(Value::as_str),need.get("link").and_then(Value::as_str)) { watched.names.insert(ns.to_owned()); watched.links.insert((ns.to_owned(),link.to_owned())); },
                        Some("observe-file") => if let Some(path)=need.get("path").and_then(Value::as_str) { watched.files.insert(path.into()); },
                        _=>{},
                    }
                }
            }
        }
    }
    Ok(watched)
}

fn mount_point(path: &str) -> Result<bool, String> {
    let content = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| format!("pid2-mountinfo-unavailable: {e}"))?;
    let target = Path::new(path);
    Ok(content.lines().filter_map(|line| line.split_whitespace().nth(4)).any(|mount| {
        let decoded = mount.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\");
        Path::new(&decoded)==target
    }))
}

fn device_facts(path:&Path, name:&str, subsystem:&str, prefix:&str) -> std::collections::BTreeMap<String,String> {
    let mut actual=std::collections::BTreeMap::<String,String>::new();
    actual.insert("SUBSYSTEM".into(),subsystem.into());
    actual.insert("SYSNAME".into(),name.into());
    if let Ok(path)=path.canonicalize() {if let Ok(relative)=path.strip_prefix("/sys") {actual.insert("DEVPATH".into(),format!("/{}",relative.display()));}}
    if let Ok(uevent)=std::fs::read_to_string(path.join("uevent")) {
        for line in uevent.lines() {if let Some((k,v))=line.split_once('=') {actual.insert(k.into(),v.into());}}
    }
    if let Ok(dev)=std::fs::read_to_string(path.join("dev")) {
        if let Ok(data)=std::fs::read_to_string(format!("/run/udev/data/{prefix}{}",dev.trim())) {
            for line in data.lines().filter_map(|line|line.strip_prefix("E:")) {if let Some((k,v))=line.split_once('=') {actual.insert(k.into(),v.into());}}
        }
    }
    actual
}

// Read only the device named by an event.  A missing class entry, a parent
// event or an oversized observation is unknown, never a negative match.
pub(super) fn event_device_facts(subsystem:&str,device:&str)->super::events::DeviceState {
    use super::events::DeviceState;
    let (class,prefix)=match subsystem {"block"=>("/sys/class/block","b"),"drm"=>("/sys/class/drm","c"),_=>return DeviceState::Unknown};
    let Some(name)=Path::new(device).file_name().and_then(|n|n.to_str()) else {return DeviceState::Unknown;};
    let path=Path::new(class).join(name);
    let expected=Path::new("/sys").join(device.trim_start_matches('/'));
    if path.canonicalize().ok().zip(expected.canonicalize().ok()).is_none_or(|(a,b)|a!=b) {return DeviceState::Unknown;}
    let connector=if subsystem=="drm" && path.join("status").exists() {Some(name.to_owned())} else {None};
    let facts:Vec<_>=device_facts(&path,name,subsystem,prefix).into_iter().collect();
    if facts.iter().map(|(k,v)|k.len()+v.len()).sum::<usize>()>16384 {return DeviceState::Unknown;}
    DeviceState::Known{facts,connector}
}

fn device_present(properties: &Value) -> Result<bool, String> {
    let wanted = properties.as_object().filter(|m| !m.is_empty()).ok_or("pid2-device-properties-missing")?;
    let mut observed_directory = false;
    for (class, subsystem, prefix) in [("/sys/class/block", "block", "b"), ("/sys/class/drm", "drm", "c")] {
        if wanted.get("SUBSYSTEM").and_then(Value::as_str).is_some_and(|v| v != subsystem) { continue; }
        let entries = match std::fs::read_dir(class) { Ok(entries)=>entries, Err(e) if e.kind()==std::io::ErrorKind::NotFound => continue, Err(e)=>return Err(format!("pid2-device-observation-failed: {e}")) };
        observed_directory = true;
        for entry in entries {
            let entry = entry.map_err(|e| format!("pid2-device-observation-failed: {e}"))?;
            let path = entry.path();
            if !path.is_dir() { continue; }
            let actual=device_facts(&path,&entry.file_name().to_string_lossy(),subsystem,prefix);
            if wanted.iter().all(|(key,value)| value.as_str().is_some_and(|v| actual.get(key).is_some_and(|observed|observed==v))) { return Ok(true); }
        }
    }
    if !observed_directory { return Err("pid2-device-sense-unavailable".into()); }
    Ok(false)
}

struct Visiting { active: HashSet<(String,String)>, attempted: HashSet<(String,String)>, retry: HashSet<(String,String)> }
fn resolve_line(routine: &str, name: &str, _senses: &super::events::Senses, _visiting: &mut Visiting) -> Result<(),String> {
    let raw: Option<Vec<u8>> = {
        let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        db.query_row("SELECT envelope FROM pid2_registrations WHERE routine_id=?1 AND enabled=1",[routine],|r|r.get(0)).optional().map_err(|e|e.to_string())?
    };
    let raw=raw.ok_or("pid2-required-routine-unavailable")?;
    let value:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    let found=value.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten().find(|stage|stage.get("line").and_then(Value::as_str)==Some(name));
    if found.is_some() && !held(routine)? { Ok(()) } else { Err("pid2-required-line-unavailable".into()) }
}

fn needs(routine: &str, stage_line: &str, need: &Value, senses: &super::events::Senses, visiting: &mut Visiting, separate_election: bool) -> Result<Option<String>, String> {
    let kind = need.get("kind").and_then(Value::as_str).ok_or("pid2-need-kind-missing")?;
    match kind {
        "observe-unit" => {
            let unit=need.get("unit").and_then(Value::as_str).ok_or("pid2-unit-missing")?;
            let scope=need.get("scope").and_then(Value::as_str).unwrap_or("system");
            if !matches!(scope,"system"|"owner") { return Err("pid2-unit-scope-invalid".into()); }
            if !senses.online(scope) { return Err("pid2-systemd-sense-unavailable".into()); }
            if !super::events::unit_watch_ready(scope,unit) { return Err("pid2-systemd-sense-unavailable".into()); }
            let state=crate::stats::indicators::unit_state::observed(scope,unit);
            Ok(Some(state.and_then(|s|s.active_state).ok_or("pid2-systemd-sense-unavailable")?))
        },
        "await-netns" => {
            let name=need.get("name").and_then(Value::as_str).ok_or("pid2-netns-name-missing")?;
            match senses.kernel.netns(name) { Some(true)=>Ok(None), Some(false)=>Err("pid2-await-netns".into()), None=>Err("pid2-netns-sense-unavailable".into()) }
        },
        "observe-link" => {
            let ns=need.get("netns").and_then(Value::as_str).ok_or("pid2-netns-name-missing")?;
            let link=need.get("link").and_then(Value::as_str).ok_or("pid2-link-name-missing")?;
            if !super::events::kernel_senses::valid_link(link) {return Err("pid2-link-name-invalid".into());}
            let value=senses.kernel.link(ns,link).ok_or("pid2-link-sense-unavailable")?;
            if need.get("value").filter(|v|!v.is_null()).is_some_and(|expected|expected.as_str()!=Some(&value)) {return Err("pid2-await-link-value".into());}
            Ok(Some(value))
        },
        "observe-file" => {
            let path=need.get("path").and_then(Value::as_str).ok_or("pid2-file-path-missing")?;
            let value=senses.kernel.file(Path::new(path)).ok_or("pid2-file-sense-unavailable")?;
            if need.get("value").filter(|v|!v.is_null()).is_some_and(|expected|expected.as_str()!=Some(&value)) {return Err("pid2-await-file-value".into());}
            Ok(Some(value))
        },
        "observe" => {
            if separate_election {
                let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                let existing:Option<String>=db.query_row("SELECT value FROM pid2_elections WHERE routine_id=?1 AND line=?2",params![routine,stage_line],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
                if let Some(value)=existing { return Ok(Some(value)); }
            } else if let Some((Some(value), state)) = line(routine, stage_line)? { if state=="Observed" { return Ok(Some(value)); } }
            if !senses.online("udev") { return Err("pid2-udev-sense-unavailable".into()); }
            if need.get("observer").and_then(Value::as_str) != Some("drm-connector") { return Err("pid2-observer-unknown".into()); }
            let pattern = need.get("pattern").and_then(Value::as_str).unwrap_or("*-HDMI-*");
            let value = observe_drm(pattern)?;
            if separate_election {
                let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                db.execute("INSERT OR IGNORE INTO pid2_elections(routine_id,line,value) SELECT ?1,?2,?3 WHERE NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,stage_line,value]).map_err(|e|e.to_string())?;
            } else { write_line(routine,stage_line,Some(&value),"Observed",None)?; }
            Ok(Some(value))
        }
        "await-mount" => {
            let path = need.get("path").and_then(Value::as_str).ok_or("pid2-mount-path-missing")?;
            let cached=senses.mounts.read().map_err(|_|"pid2-mount-cache-lock-poisoned")?;
            let present=match cached.as_ref() { Some(mounts)=>mounts.contains(Path::new(path)), None=>mount_point(path).map_err(|error|format!("pid2-await-mount-unsensed: {error}"))? };
            if present { Ok(None) } else if cached.is_some() { Err("pid2-await-mount".into()) } else { Err("pid2-await-mount-unsensed".into()) }
        }
        "await-line" => {
            let other = need.get("routine_id").and_then(Value::as_str).unwrap_or(routine);
            let name = need.get("line").and_then(Value::as_str).ok_or("pid2-line-name-missing")?;
            let expected = need.get("value").and_then(Value::as_str).unwrap_or("true");
            resolve_line(other,name,senses,visiting)?;
            if line(other,name)?.and_then(|x| x.0).as_deref()==Some(expected) { Ok(None) } else { Err("pid2-await-line".into()) }
        }
        "await-ready" => {
            let unit = need.get("unit").and_then(Value::as_str).ok_or("pid2-unit-missing")?;
            let scope = unit_scope(unit)?;
            if !senses.online(&scope) { return Err("pid2-systemd-sense-unavailable".into()); }
            let status = unit_status(unit,&scope)?;
            if let Some(seat) = need.get("seat").and_then(Value::as_str) {
                if status.pointer("/readback/seat").and_then(Value::as_str) != Some(seat) { return Err("pid2-await-seat-readiness".into()); }
            }
            let active = status.pointer("/readback/active_state").and_then(Value::as_str)==Some("active");
            let rule = need.get("readiness").or_else(|| unit_entry(unit).ok().and_then(|entry|entry.get("readiness"))).and_then(Value::as_str);
            let signal = match rule {
                None | Some("sway-session-target") => active,
                Some("ready") => active && status.pointer("/readback/ready").and_then(Value::as_bool)==Some(true),
                Some(_) => return Err("pid2-readiness-rule-unknown".into()),
            };
            if signal { Ok(None) } else { Err("pid2-await-ready".into()) }
        }
        "await-owner" => {
            let answer_line = need.get("line").and_then(Value::as_str).unwrap_or(stage_line);
            let expected = need.get("value").and_then(Value::as_str).unwrap_or("true");
            if line(routine,answer_line)?.and_then(|x|x.0).as_deref()==Some(expected) { Ok(None) } else { Err("pid2-await-owner".into()) }
        },
        "await-device" => {
            if !senses.online("udev") { return Err("pid2-udev-sense-unavailable".into()); }
            let properties = need.get("properties").unwrap_or(&Value::Null);
            if device_present(properties)? { Ok(None) } else { Err("pid2-await-device".into()) }
        },
        _ => Err("pid2-need-kind-unknown".into()),
    }
}

fn stage(routine: &str, stage: &Value, senses: &super::events::Senses, visiting: &mut Visiting) -> Result<(), String> {
    if held(routine)? { return Ok(()); }
    let name=stage.get("line").and_then(Value::as_str).ok_or("pid2-line-name-missing")?;
    if visiting.active.len()>=128 { return Err("pid2-dependency-depth-exceeded".into()); }
    let key=(routine.to_owned(),name.to_owned());
    if !visiting.active.insert(key.clone()) { return Err("pid2-dependency-cycle".into()); }
    let result=stage_inner(routine,stage,senses,visiting);
    visiting.active.remove(&key);
    result
}
fn stage_inner(routine: &str, stage: &Value, senses: &super::events::Senses, visiting: &mut Visiting) -> Result<(), String> {
    let name = stage.get("line").and_then(Value::as_str).ok_or("pid2-line-name-missing")?;
    if stage.get("do").is_some_and(|value| !value.is_null() && !value.is_array()) { return Err("pid2-do-not-array".into()); }
    if stage.get("until").is_some_and(|value| !value.is_null() && !value.is_array()) { return Err("pid2-until-not-array".into()); }
    let crossings=stage.get("do").and_then(Value::as_array);
    let until=stage.get("until").and_then(Value::as_array);
    let dynamic=["needs","until"].into_iter().flat_map(|key|stage.get(key).and_then(Value::as_array).into_iter().flatten()).any(|n|matches!(n.get("kind").and_then(Value::as_str),Some("await-netns"|"observe-link"|"observe-file"|"observe-unit")));
    // Migrate a retained boot election before replacing its old line row;
    // a repurposed line without an election must not keep the old value.
    if dynamic {
        let election=stage.get("select").is_some_and(|v|!v.is_null()) || ["needs","until"].into_iter().flat_map(|key|stage.get(key).and_then(Value::as_array).into_iter().flatten()).any(|n|n.get("kind").and_then(Value::as_str)==Some("observe"));
        let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        let tx=db.transaction().map_err(|e|e.to_string())?;
        if election {
            tx.execute("INSERT OR IGNORE INTO pid2_elections(routine_id,line,value) SELECT routine_id,line,value FROM pid2_lines WHERE routine_id=?1 AND line=?2 AND state='Observed' AND value IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,name]).map_err(|e|e.to_string())?;
        }
        let removed=tx.execute("DELETE FROM pid2_lines WHERE routine_id=?1 AND line=?2 AND state='Observed' AND NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,name]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e|e.to_string())?;
        drop(db);
        if removed!=0 {REVISION.fetch_add(1,Ordering::Relaxed);deed("line",&format!("{routine}/{name}"),"Reevaluate",None);}
    }
    let separate_election=dynamic || crossings.is_some() || until.is_some() || stage.get("actions").and_then(Value::as_array).is_some_and(|a|!a.is_empty());
    let check_until = |visiting: &mut Visiting| -> Result<(),String> {
        if let Some(conditions)=until {
            for condition in conditions { needs(routine,name,condition,senses,visiting,separate_election)?; }
        }
        Ok(())
    };
    if !crossings.is_some_and(|steps|steps.iter().any(|step|step.get("route").is_some())) && until.is_some() && check_until(visiting).is_ok() {
        let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        let tx=db.transaction().map_err(|e|e.to_string())?;
        tx.execute("INSERT OR IGNORE INTO pid2_completed(routine_id,line) SELECT ?1,?2 WHERE NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,name]).map_err(|e|e.to_string())?;
        tx.execute("DELETE FROM pid2_crossings WHERE routine_id=?1 AND line=?2",params![routine,name]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e|e.to_string())?;
        drop(db);
        return write_line(routine,name,Some("true"),"Done",None);
    }
    let mut value = None;
    let mut need_trace=Vec::new();
    for need in stage.get("needs").and_then(Value::as_array).into_iter().flatten() {
        if let Some(branch)=need.get("when_line").and_then(Value::as_str) {
            resolve_line(routine,branch,senses,visiting)?;
            let selected=line(routine,branch)?.and_then(|x|x.0).ok_or("pid2-need-branch-unobserved")?;
            let expected=need.get("when_value").and_then(Value::as_str).unwrap_or("true");
            need_trace.push(json!({"branch":branch,"selected":selected,"expected":expected}));
            if selected != expected { continue; }
        }
        let observed=needs(routine,name,need,senses,visiting,separate_election);
        let mut declared=serde_json::Map::new();
        for key in ["kind","properties","path","name","netns","link","routine_id","line","value","unit","scope","observer","pattern","seat","readiness"] {
            if let Some(v)=need.get(key) { declared.insert(key.into(),v.clone()); }
        }
        need_trace.push(json!({"need":declared,"observation":match &observed { Ok(value)=>json!({"value":value}),Err(reason)=>json!({"reason":reason}) }}));
        match observed {
            Ok(Some(v)) => value=Some(v),
            Ok(None) => {},
            Err(reason) => { rearm_changed_needs(routine,stage,&needs_token(name,&need_trace))?; write_line(routine,name,None,"Waiting",Some(&reason))?; return Ok(()); }
        }
    }
    let needs_fingerprint=needs_token(name,&need_trace);
    rearm_changed_needs(routine,stage,&needs_fingerprint)?;
    if let Some(steps)=crossings {
        if steps.iter().any(|step|step.get("route").is_some()) {
            if !steps.iter().all(|step|step.get("route").and_then(Value::as_str).is_some() && step.get("staff").is_none()) {return Err("pid2-route-mixed-steps".into());}
            return route_stage(routine,name,stage,steps,&needs_fingerprint,visiting);
        }
    }
    if crossings.is_some() || until.is_some() {
        let done: bool = {
            let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
            db.query_row("SELECT EXISTS(SELECT 1 FROM pid2_completed WHERE routine_id=?1 AND line=?2)",params![routine,name],|r|r.get(0)).map_err(|e|e.to_string())?
        };

        if done {
            if until.is_none() { return write_line(routine,name,Some("true"),"Done",None); }
            let reason=check_until(visiting).err().unwrap_or_else(||"pid2-await-until".into());
            return write_line(routine,name,None,"Waiting",Some(&reason));
        }
        if let Some(steps)=crossings {
            let key=(routine.to_owned(),name.to_owned());
            let previous: Option<i64> = {
                let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                db.query_row("SELECT attempted_at FROM pid2_attempts WHERE routine_id=?1 AND line=?2",params![routine,name],|r|r.get(0)).optional().map_err(|e|e.to_string())?
            };
            if visiting.attempted.contains(&key) || (previous.is_some() && !visiting.retry.contains(&key)) { return Ok(()); }
            let _action=super::ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
            let _process=super::process_action_lock()?;
            if held(routine)? { return Ok(()); }
            require_current_stage(routine,stage)?;
            visiting.attempted.insert(key);
            {
                let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                db.execute("INSERT INTO pid2_attempts(routine_id,line,attempted_at) VALUES(?1,?2,?3) ON CONFLICT(routine_id,line) DO UPDATE SET attempted_at=excluded.attempted_at",params![routine,name,now()]).map_err(|e|e.to_string())?;
            }
            for (index,step) in steps.iter().enumerate() {
                let completed:bool={
                    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                    db.query_row("SELECT EXISTS(SELECT 1 FROM pid2_crossings WHERE routine_id=?1 AND line=?2 AND step_index=?3)",params![routine,name,index as i64],|r|r.get(0)).map_err(|e|e.to_string())?
                };
                if completed { continue; }
                let band=step.get("staff").and_then(Value::as_str).ok_or("pid2-staff-path-missing")?;
                let payload=step.get("payload").filter(|v|v.is_object()).ok_or("pid2-staff-payload-invalid")?;
                // The generic crossing is also an entry to unit/control;
                // enforce the same enum wall as the action and status paths.
                let mut status_read=None;
                if crate::gate::snake::safe_band_path(band)? == "unit/control" {
                    let unit=payload.get("unit").and_then(Value::as_str).ok_or("pid2-action-unit-missing")?;
                    let scope=unit_scope(unit)?;
                    if payload.get("scope").and_then(Value::as_str)!=Some(scope.as_str()) { return Err("pid2-unit-scope-mismatch".into()); }
                    if payload.get("action").and_then(Value::as_str)==Some("status") { status_read=Some(unit_status(unit,&scope)); }
                    else if unit_entry(unit)?.get("observe_only").and_then(Value::as_bool)==Some(true) { return Err("pid2-unit-observe-only".into()); }
                }
                let seconds=step.get("deadline_seconds").and_then(Value::as_u64).unwrap_or(180);
                if !(1..=600).contains(&seconds) { return Err("pid2-staff-deadline-out-of-range".into()); }
                let result=if let Some(status)=status_read { status.map(|receipt|json!({"ok":true,"converged":true,"receiptPayload":receipt})) }
                    else { crate::gate::snake::crossing_path_with_timeout(band,payload,std::time::Duration::from_secs(seconds)) };
                let signal=match result {
                    Err(signal)=>Some(signal),
                    Ok(reply)=>{
                        let receipt=reply.get("receiptPayload").unwrap_or(&Value::Null);
                        if reply.get("ok").and_then(Value::as_bool)==Some(true) && receipt.get("ok").and_then(Value::as_bool)==Some(true) && reply.get("converged").and_then(Value::as_bool)!=Some(false) && receipt.get("converged").and_then(Value::as_bool)!=Some(false) { None }
                        else { Some(receipt.get("first_missing_signal").or_else(||receipt.get("firstMissingSignal")).or_else(||reply.get("first_missing_signal")).or_else(||reply.get("firstMissingSignal")).and_then(Value::as_str).unwrap_or("pid2-staff-refused").to_owned()) }
                    }
                };
                if let Some(reason)=signal {
                    write_line(routine,name,None,"Held",Some(&reason))?;
                    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                    db.execute("UPDATE pid2_lines SET observed_at=?3 WHERE routine_id=?1 AND line=?2",params![routine,name,now()]).map_err(|e|e.to_string())?;
                    db.execute("UPDATE pid2_attempts SET attempted_at=?3 WHERE routine_id=?1 AND line=?2",params![routine,name,now()]).map_err(|e|e.to_string())?;
                    return Ok(());
                }
                let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                db.execute("INSERT OR IGNORE INTO pid2_crossings(routine_id,line,step_index) SELECT ?1,?2,?3 WHERE NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,name,index as i64]).map_err(|e|e.to_string())?;
            }
            {
                let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                db.execute("UPDATE pid2_attempts SET attempted_at=?3 WHERE routine_id=?1 AND line=?2",params![routine,name,now()]).map_err(|e|e.to_string())?;
            }
            drop(_process); drop(_action);
        }
        if let Err(reason)=check_until(visiting) { return write_line(routine,name,None,"Waiting",Some(&reason)); }
        let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        let tx=db.transaction().map_err(|e|e.to_string())?;
        tx.execute("INSERT OR IGNORE INTO pid2_completed(routine_id,line) SELECT ?1,?2 WHERE NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,name]).map_err(|e|e.to_string())?;
        tx.execute("DELETE FROM pid2_crossings WHERE routine_id=?1 AND line=?2",params![routine,name]).map_err(|e|e.to_string())?;
        tx.commit().map_err(|e|e.to_string())?;
        drop(db);
        return write_line(routine,name,Some("true"),"Done",None);
    }
    if let Some(select) = stage.get("select").filter(|v| !v.is_null()) {
        if separate_election {
            let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
            let tx=db.transaction().map_err(|e|e.to_string())?;
            tx.execute("INSERT OR IGNORE INTO pid2_elections(routine_id,line,value) SELECT routine_id,line,value FROM pid2_lines WHERE routine_id=?1 AND line=?2 AND state='Observed' AND value IS NOT NULL AND NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,name]).map_err(|e|e.to_string())?;
            let changed=tx.execute("UPDATE pid2_lines SET state='Done' WHERE routine_id=?1 AND line=?2 AND state='Observed' AND EXISTS(SELECT 1 FROM pid2_elections WHERE routine_id=?1 AND line=?2) AND NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,name]).map_err(|e|e.to_string())?;
            tx.commit().map_err(|e|e.to_string())?;
            value=db.query_row("SELECT value FROM pid2_elections WHERE routine_id=?1 AND line=?2",params![routine,name],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
            drop(db);
            if changed!=0 { REVISION.fetch_add(1,Ordering::Relaxed); }
        } else if let Some((Some(existing),state)) = line(routine,name)? {
            if state == "Observed" { value=Some(existing); }
        }
        if value.is_none() {
            let source = select.get("line").and_then(Value::as_str).ok_or("pid2-select-line-missing")?;
            resolve_line(routine,source,senses,visiting)?;
            let source_value = line(routine,source)?.and_then(|v|v.0).ok_or("pid2-select-source-not-observed")?;
            let chosen = select.get("map").and_then(|m|m.get(&source_value)).and_then(Value::as_str).ok_or("pid2-select-value-undefined")?;
            if separate_election {
                let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
                db.execute("INSERT OR IGNORE INTO pid2_elections(routine_id,line,value) SELECT ?1,?2,?3 WHERE NOT EXISTS(SELECT 1 FROM pid2_holds WHERE routine_id=?1)",params![routine,name,chosen]).map_err(|e|e.to_string())?;
                value=db.query_row("SELECT value FROM pid2_elections WHERE routine_id=?1 AND line=?2",params![routine,name],|r|r.get(0)).optional().map_err(|e|e.to_string())?;
            } else {
                write_line(routine,name,Some(chosen),"Observed",None)?;
                value=Some(chosen.to_owned());
            }
        }
    }
    let mut ordered: Vec<Result<usize,(String,String)>> = Vec::new();
    let mut units: Vec<(String,String)> = Vec::new();
    for action in stage.get("actions").and_then(Value::as_array).into_iter().flatten() {
        if let Some(branch) = action.get("when_line").and_then(Value::as_str) {
            let expected = action.get("when_value").and_then(Value::as_str).unwrap_or("true");
            if let Err(reason)=resolve_line(routine,branch,senses,visiting) { ordered.push(Err(("Held".into(),reason))); continue; }
            let Some(branch_value)=line(routine,branch)?.and_then(|x|x.0) else { ordered.push(Err(("Held".into(),"pid2-action-branch-unobserved".into()))); continue; };
            if branch_value != expected { continue; }
        }
        let Some(unit) = action.get("unit").and_then(Value::as_str) else { ordered.push(Err(("Held".into(),"pid2-action-unit-missing".into()))); continue; };
        let scope = match unit_scope(unit) { Ok(scope)=>scope, Err(reason)=>{ ordered.push(Err(("Held".into(),format!("{unit}: {reason}")))); continue; } };
        if !senses.online(&scope) { ordered.push(Err(("Held".into(),format!("{unit}: pid2-systemd-sense-unavailable")))); continue; }
        if action.get("scope").and_then(Value::as_str).is_some_and(|declared|declared!=scope) { ordered.push(Err(("Held".into(),format!("{unit}: pid2-unit-scope-mismatch")))); continue; }
        // A repeated unit shares one attempt. The schema seat bounds the
        // number of distinct units, so one slow unit cannot create an
        // unbounded worker fan or delay another declared unit's attempt.
        let index=units.iter().position(|(name,existing_scope)|name==unit && existing_scope==&scope).unwrap_or_else(|| {units.push((unit.to_owned(),scope)); units.len()-1});
        ordered.push(Ok(index));
    }
    let outcomes: Vec<Result<bool,String>> = std::thread::scope(|threads| {
        let needs_fingerprint=&needs_fingerprint;
        let jobs: Vec<_>=units.iter().map(|(unit,scope)| threads.spawn(move || ensure_running(routine,unit,scope,stage,needs_fingerprint))).collect();
        jobs.into_iter().map(|job|job.join().unwrap_or_else(|_|Err("pid2-unit-attempt-panicked".into()))).collect()
    });
    for result in ordered {
        let problem=match result {
            Err(problem)=>Some(problem),
            Ok(index)=>match &outcomes[index] {
                Ok(true)=>None,
                Ok(false)=>Some(("Waiting".into(),format!("{}: pid2-await-ready",units[index].0))),
                Err(reason)=>Some(("Held".into(),format!("{}: {reason}",units[index].0))),
            }
        };
        if let Some((state,reason))=problem { return write_line(routine,name,None,&state,Some(&reason)); }
    }
    write_line(routine,name,Some(value.as_deref().unwrap_or("true")),if value.is_some() && !separate_election && !dynamic {"Observed"}else{"Done"},None)
}

pub fn owner_answer(routine: &str, name: &str, answer: &str) -> Result<Value, String> {
    if routine.is_empty() || name.is_empty() || !["true","false","yes","no"].contains(&answer) { return Err("pid2-owner-answer-invalid".into()); }
    let _walk=super::walk_lock()?;
    if held(routine)? { return Err("pid2-routine-held".into()); }
    if write_line_changed(routine,name,Some(answer),"Answered",None)? { super::events::notify_line(routine,name)?; }
    Ok(json!({"ok":true,"routine_id":routine,"line":name,"value":answer}))
}

/// The swap must not advance merely because Stop intent was queued.
pub fn quiesce_held(routine: &str, deadline: std::time::Instant) -> Result<(),String> {
    let _walk=super::walk_lock()?;
    let _guard=super::ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
    let _process=super::process_action_lock()?;
    if !held(routine)? { return Ok(()); }
    let rows: Vec<(String,String)> = {
        let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        let mut query=db.prepare("SELECT unit,scope FROM pid2_programs WHERE routine_id=?1 ORDER BY unit,scope").map_err(|e|e.to_string())?;
        let result=query.query_map([routine],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
        result
    };
    let remaining = || -> Result<std::time::Duration,String> {
        let left=deadline.saturating_duration_since(std::time::Instant::now());
        if left.is_zero() {Err("pid2-native-stage-timeout".into())} else {Ok(left.min(std::time::Duration::from_secs(300)))}
    };
    let active = |unit: &str, scope: &str| -> Result<bool,String> {
        remaining()?;
        let response=unit_status(unit,scope)?;
        if response.get("ok").and_then(Value::as_bool)!=Some(true) { return Err("pid2-unit-status-refused".into()); }
        match response.pointer("/readback/active_state").and_then(Value::as_str) {
            Some("inactive"|"failed")=>Ok(false), Some(_)=>Ok(true), None=>Err("pid2-unit-state-unobserved".into())
        }
    };
    for (unit,scope) in rows {
        if active(&unit,&scope)? {
            let result=unit_call_timeout("stop",&unit,&scope,remaining()?)?;
            if result.get("ok").and_then(Value::as_bool)!=Some(true) { return Err(format!("pid2-stop-refused: {unit}")); }
            program_state(routine,&unit,&scope,"Stopping",Some("stop-accepted"))?;
            if active(&unit,&scope)? { return Err(format!("pid2-stop-not-yet-inactive: {unit}")); }
        }
        program_state(routine,&unit,&scope,"Held",Some("stopped"))?;
    }
    Ok(())
}

fn reconcile_stops(senses: &super::events::Senses, keys:&[super::events::DirtyKey]) -> Result<(),String> {
    use super::events::DirtyKey;
    let mut previous=(String::new(),String::new(),String::new());
    loop {
        let item: Option<(String,String,String,String,Option<String>)> = {
            let db=crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
            db.query_row("SELECT unit,scope,routine_id,life,last_receipt FROM pid2_programs WHERE desired='Stop' AND (unit,scope,routine_id)>(?1,?2,?3) ORDER BY unit,scope,routine_id LIMIT 1",params![previous.0,previous.1,previous.2],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?
        };
        let Some((unit,scope,routine,_,_))=item else { break; };
        previous=(unit.clone(),scope.clone(),routine.clone());
        if !keys.iter().any(|key|match key { DirtyKey::All|DirtyKey::Startup=>true, DirtyKey::Routine(id)=>id==&routine, DirtyKey::Unit(s,u)|DirtyKey::Job(s,u)=>s==&scope && u==&unit, DirtyKey::Sense(s)|DirtyKey::Unavailable(s)=>s==&scope, _=>false }) { continue; }
        let _guard=super::ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
    let _process_guard=super::process_action_lock()?;
        let (desired,life,receipt)=program(&routine,&unit,&scope)?;
        if desired!="Stop" || life=="Failed" { continue; }
        if !senses.online(&scope) { if life!="Stopping" { program_state(&routine,&unit,&scope,"Held",Some("pid2-systemd-sense-unavailable"))?; } continue; }
        match unit_status(&unit,&scope) {
            Ok(status) => match status.pointer("/readback/active_state").and_then(Value::as_str) {
                Some("inactive" | "failed") => program_state(&routine,&unit,&scope,"Held",Some("stopped"))?,
                Some(_) if life=="Stopping" && receipt.as_deref()==Some("stop-accepted") => {},
                Some(_) => match unit_call("stop",&unit,&scope) {
                    Ok(reply) if reply.get("ok").and_then(Value::as_bool)==Some(true) => program_state(&routine,&unit,&scope,"Stopping",Some("stop-accepted"))?,
                    Ok(_) => program_state(&routine,&unit,&scope,"Failed",Some("pid2-stop-refused"))?,
                    Err(error) => program_state(&routine,&unit,&scope,"Failed",Some(&error))?,
                },
                None if life=="Stopping" => {},
                None => program_state(&routine,&unit,&scope,"Held",Some("pid2-unit-state-unobserved"))?,
            },
            Err(_) if life=="Stopping" => {},
            Err(error) => program_state(&routine,&unit,&scope,"Held",Some(&error))?,
        }
    }
    Ok(())
}

type LineKey=(String,String);

fn stage_dependencies(routine:&str,stage:&Value)->HashSet<LineKey> {
    let mut out=HashSet::new();
    for key in ["needs","until"] {
        for need in stage.get(key).and_then(Value::as_array).into_iter().flatten() {
            if let Some(line)=need.get("when_line").and_then(Value::as_str) {out.insert((routine.to_owned(),line.to_owned()));}
            if need.get("kind").and_then(Value::as_str)==Some("await-line") {
                if let Some(line)=need.get("line").and_then(Value::as_str) {out.insert((need.get("routine_id").and_then(Value::as_str).unwrap_or(routine).to_owned(),line.to_owned()));}
            }
            if need.get("kind").and_then(Value::as_str)==Some("await-owner") {
                if let Some(line)=need.get("line").and_then(Value::as_str) {
                    // An answer stored on this same line is an external input,
                    // not a recursive producer dependency.
                    if stage.get("line").and_then(Value::as_str)!=Some(line) {out.insert((routine.to_owned(),line.to_owned()));}
                }
            }
        }
    }
    if let Some(line)=stage.pointer("/select/line").and_then(Value::as_str) {out.insert((routine.to_owned(),line.to_owned()));}
    for action in stage.get("actions").and_then(Value::as_array).into_iter().flatten() {
        if let Some(line)=action.get("when_line").and_then(Value::as_str) {out.insert((routine.to_owned(),line.to_owned()));}
    }
    out
}

fn device_side_may_match(need:&Value,side:&super::events::DeviceState)->bool {
    use super::events::DeviceState;
    match side {
        DeviceState::Unknown=>true,
        DeviceState::Absent=>false,
        DeviceState::Known{facts,connector}=>{
            if need.get("kind").and_then(Value::as_str)==Some("observe") {
                let pattern=need.get("pattern").and_then(Value::as_str).unwrap_or("*-HDMI-*");
                return connector.as_ref().is_none_or(|name|glob(pattern,name));
            }
            need.get("properties").and_then(Value::as_object).is_none_or(|wanted|wanted.iter().all(|(key,value)| {
                match (facts.iter().find(|(name,_)|name==key),value.as_str()) {
                    (Some((_,actual)),Some(expected))=>actual==expected,
                    _=>true,
                }
            }))
        },
    }
}

fn stage_matches(routine:&str,stage:&Value,key:&super::events::DirtyKey)->bool {
    use super::events::DirtyKey;
    match key {
        DirtyKey::All|DirtyKey::Startup=>return true,
        DirtyKey::Routine(id)=>return id==routine || stage_dependencies(routine,stage).iter().any(|(r,_)|r==id),
        DirtyKey::Line(id,line)=>return (id==routine && stage.get("line").and_then(Value::as_str)==Some(line)) || stage_dependencies(routine,stage).contains(&(id.clone(),line.clone())),
        DirtyKey::Schedule=>return false,
        _=>{},
    }
    let conditions=["needs","until"].into_iter().flat_map(|name|stage.get(name).and_then(Value::as_array).into_iter().flatten());
    for need in conditions {
        let kind=need.get("kind").and_then(Value::as_str).unwrap_or("");
        let matches=match key {
            DirtyKey::Netns(name)=>kind=="await-netns" && need.get("name").and_then(Value::as_str)==Some(name),
            DirtyKey::Link(ns,link)=>kind=="observe-link" && need.get("netns").and_then(Value::as_str)==Some(ns) && need.get("link").and_then(Value::as_str)==Some(link),
            DirtyKey::File(path)=>kind=="observe-file" && need.get("path").and_then(Value::as_str).is_some_and(|p|Path::new(p)==path),
            DirtyKey::Mount(path)=>kind=="await-mount" && need.get("path").and_then(Value::as_str).is_some_and(|p|Path::new(p)==path),
            DirtyKey::Device(subsystem,device,before,after)=>{
                if kind=="observe" {subsystem=="drm" && (device_side_may_match(need,before) || device_side_may_match(need,after))} else if kind=="await-device" {
                    let properties=need.get("properties");
                    let same=properties.and_then(|p|p.get("SUBSYSTEM")).and_then(Value::as_str).is_none_or(|v|v==subsystem);
                    let path=properties.and_then(|p|p.get("DEVPATH")).and_then(Value::as_str);
                    same && (device.is_empty() || path.is_none_or(|v|Path::new(v).starts_with(device) || Path::new(device).starts_with(v))) && (device_side_may_match(need,before) || device_side_may_match(need,after))
                } else {false}
            },
            DirtyKey::Unit(scope,unit)=>need.get("unit").and_then(Value::as_str)==Some(unit) && ((kind=="await-ready" && unit_scope(unit).is_ok_and(|s|s==*scope)) || (kind=="observe-unit" && need.get("scope").and_then(Value::as_str).unwrap_or("system")==scope)),
            DirtyKey::Sense(scope)|DirtyKey::Offline(scope)|DirtyKey::Unavailable(scope)=>match scope.as_str() {
                "mount"=>kind=="await-mount", "udev"=>kind=="await-device" || kind=="observe",
                "netns"=>kind=="await-netns", "link"=>kind=="observe-link", "file"=>kind=="observe-file",
                "system"|"owner"=>(kind=="await-ready" && need.get("unit").and_then(Value::as_str).is_some_and(|u|unit_scope(u).is_ok_and(|s|s==*scope))) || (kind=="observe-unit" && need.get("scope").and_then(Value::as_str).unwrap_or("system")==scope), _=>false,
            },
            _=>false,
        };
        if matches {return true;}
    }
    for action in stage.get("actions").and_then(Value::as_array).into_iter().flatten() {
        if let Some(name)=action.get("unit").and_then(Value::as_str) {
            if match key {DirtyKey::Unit(scope,unit)|DirtyKey::Job(scope,unit)=>unit==name && unit_scope(name).is_ok_and(|s|s==*scope),DirtyKey::Sense(scope)|DirtyKey::Unavailable(scope)=>unit_scope(name).is_ok_and(|s|s==*scope),_=>false} {return true;}
        }
    }
    false
}

fn line_snapshot(routine:&str,name:&str)->Result<Option<(Option<String>,String,Option<String>)>,String> {
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    db.query_row("SELECT value,state,reason FROM pid2_lines WHERE routine_id=?1 AND line=?2",params![routine,name],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(|e|e.to_string())
}

pub(super) fn reconcile(senses:&super::events::Senses,keys:Vec<super::events::DirtyKey>)->Result<(),String> {
    use super::events::DirtyKey;
    let _walk=super::walk_lock()?;
    reconcile_stops(senses,&keys)?;
    let registrations:Vec<(String,Vec<u8>)>={
        let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        tables(&db)?;
        let mut q=db.prepare("SELECT routine_id,envelope FROM pid2_registrations WHERE enabled=1 ORDER BY routine_id").map_err(|e|e.to_string())?;
        let rows=q.query_map([],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
        rows
    };
    let mut stages=BTreeMap::<LineKey,Value>::new();
    let mut reverse=HashMap::<LineKey,HashSet<LineKey>>::new();
    for (routine,raw) in registrations {
        let envelope:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        for stage in envelope.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten() {
            let Some(name)=stage.get("line").and_then(Value::as_str) else {continue;};
            let line=(routine.clone(),name.to_owned());
            for dependency in stage_dependencies(&routine,stage) {reverse.entry(dependency).or_default().insert(line.clone());}
            stages.insert(line,stage.clone());
        }
    }
    let mut queued=HashSet::new(); let mut retry=HashSet::new();
    for (line,stage) in &stages {
        for key in &keys {
            if stage_matches(&line.0,stage,key) {
                queued.insert(line.clone());
                if !matches!(key,DirtyKey::Startup|DirtyKey::Offline(_)|DirtyKey::Unavailable(_)|DirtyKey::Job(_,_)|DirtyKey::Schedule) {retry.insert(line.clone());}
            }
        }
    }
    // Refresh selected producers before selected consumers. Persisted line
    // values can predate this wake, particularly on the startup full walk.
    // Fail closed on a cycle rather than act on those stale values.
    let mut pending=queued.clone();
    let mut queue=VecDeque::new();
    while !pending.is_empty() {
        let next=stages.iter().find_map(|(line,stage)| {
            if !pending.contains(line) {return None;}
            if stage_dependencies(&line.0,stage).iter().any(|parent|pending.contains(parent)) {None} else {Some(line.clone())}
        }).ok_or("pid2-dependency-cycle")?;
        pending.remove(&next);
        queue.push_back(next);
    }
    let mut visiting=Visiting{active:HashSet::new(),attempted:HashSet::new(),retry};
    let mut remaining=stages.len().saturating_mul(64).max(1);
    while let Some(line)=queue.pop_front() {
        queued.remove(&line);
        if remaining==0 {return Err("pid2-reconcile-iteration-limit".into());} remaining-=1;
        let Some(item)=stages.get(&line) else {continue;};
        let before=line_snapshot(&line.0,&line.1)?;
        if let Err(error)=stage(&line.0,item,senses,&mut visiting) {write_line(&line.0,&line.1,None,"Held",Some(&error))?;}
        let after=line_snapshot(&line.0,&line.1)?;
        if before!=after {
            // A changed result dirties its consumers, not its own input.  A
            // second visit to this line requires a new key that it names.
            if let Some(children)=reverse.get(&line) {let mut children:Vec<_>=children.iter().collect(); children.sort(); for child in children {if visiting.retry.contains(&line) {visiting.retry.insert(child.clone());} if queued.insert(child.clone()) {queue.push_back(child.clone());}}}
        }
    }
    Ok(())
}
