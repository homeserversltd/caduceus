//! Level-triggered reconciliation: events are hints, current observations are truth.
use super::{now, tables};
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};
use std::{collections::HashSet, path::Path, sync::atomic::{AtomicU64,Ordering}};
static REVISION: AtomicU64 = AtomicU64::new(0);

fn line(routine: &str, name: &str) -> Result<Option<(Option<String>, String)>, String> {
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    db.query_row("SELECT value,state FROM pid2_lines WHERE routine_id=?1 AND line=?2", params![routine,name], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e| e.to_string())
}

fn write_line(routine: &str, name: &str, value: Option<&str>, state: &str, reason: Option<&str>) -> Result<(), String> {
    let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
    // An observation is a boot-scoped election: no wake may replace it.
    let changed = db.execute("INSERT INTO pid2_lines(routine_id,line,value,state,observed_at,reason) VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(routine_id,line) DO UPDATE SET value=excluded.value,state=excluded.state,observed_at=excluded.observed_at,reason=excluded.reason WHERE pid2_lines.state <> 'Observed' AND (pid2_lines.value IS NOT excluded.value OR pid2_lines.state IS NOT excluded.state OR pid2_lines.reason IS NOT excluded.reason)",params![routine,name,value,state,now(),reason]).map_err(|e| e.to_string())?;
    drop(db);
    if changed != 0 { REVISION.fetch_add(1,Ordering::Relaxed); deed("line", &format!("{routine}/{name}"), state, reason); }
    Ok(())
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
fn unit_scope(unit: &str) -> Result<String, String> {
    unit_entry(unit)?.get("scope").and_then(Value::as_str).map(str::to_owned).ok_or_else(||"pid2-unit-scope-missing".into())
}

fn unit_call(action: &str, unit: &str, scope: &str) -> Result<Value, String> {
    if unit_scope(unit)? != scope { return Err("pid2-unit-scope-mismatch".into()); }
    if action != "status" && unit_entry(unit)?.get("observe_only").and_then(Value::as_bool)==Some(true) { return Err("pid2-unit-observe-only".into()); }
    let result = crate::routes::leaf_pid2::unit_control(&json!({"action":action,"unit":unit,"scope":scope}));
    if action != "status" { deed(action, unit, if result.is_ok() {"attempted"} else {"held"}, result.as_ref().err().map(String::as_str)); }
    result
}

pub(super) fn unit_status(unit: &str, scope: &str) -> Result<Value, String> {
    let response = unit_call("status",unit,scope)?;
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(response.get("first_missing_signal").and_then(Value::as_str).unwrap_or("pid2-unit-status-refused").to_owned());
    }
    Ok(response)
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

fn ensure_running(routine: &str, unit: &str, scope: &str, expected_stage: &Value) -> Result<bool,String> {
    let _guard=super::ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
    let raw:Option<Vec<u8>> = {
        let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        db.query_row("SELECT envelope FROM pid2_registrations WHERE routine_id=?1 AND enabled=1",[routine],|r|r.get(0)).optional().map_err(|e|e.to_string())?
    };
    let raw=raw.ok_or("pid2-routine-disabled")?;
    let current:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    if !current.pointer("/routine/stages").and_then(Value::as_array).is_some_and(|stages|stages.contains(expected_stage)) { return Err("pid2-routine-changed".into()); }
    let (desired,mut life,receipt) = program(routine,unit,scope)?;
    if desired != "Run" { return Err("pid2-program-stopped-by-owner".into()); }
    if life == "Stopping" {
        if receipt.as_deref() != Some("stop-accepted") {
            match unit_call("stop",unit,scope) {
                Ok(reply) if reply.get("ok").and_then(Value::as_bool)==Some(true) => { program_state(routine,unit,scope,"Stopping",Some("stop-accepted"))?; return Ok(false); },
                Ok(_) => { program_state(routine,unit,scope,"Stopping",Some("pid2-stop-refused"))?; return Err("pid2-stop-refused".into()); },
                Err(error) => { program_state(routine,unit,scope,"Stopping",Some(&error))?; return Err(error); }
            }
        }
        if running(unit,scope)? { return Ok(false); }
        life = "Queued".into();
    }
    match running(unit,scope) {
        Ok(true) => { program_state(routine,unit,scope,"Running",Some("active"))?; Ok(true) },
        Ok(false) => {
            if life != "Starting" {
                match unit_call("start",unit,scope) {
                    Ok(reply) if reply.get("ok").and_then(Value::as_bool)==Some(true) => program_state(routine,unit,scope,"Starting",Some("start-accepted"))?,
                    Ok(_) => { program_state(routine,unit,scope,"Held",Some("pid2-start-refused"))?; return Err("pid2-start-refused".into()); },
                    Err(error) => { program_state(routine,unit,scope,"Held",Some(&error))?; return Err(error); }
                }
            }
            Ok(false)
        },
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

fn mount_point(path: &str) -> Result<bool, String> {
    let content = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| format!("pid2-mountinfo-unavailable: {e}"))?;
    let target = Path::new(path);
    Ok(content.lines().filter_map(|line| line.split_whitespace().nth(4)).any(|mount| {
        let decoded = mount.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\");
        Path::new(&decoded)==target
    }))
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
            let mut actual = std::collections::BTreeMap::<String,String>::new();
            actual.insert("SUBSYSTEM".into(), subsystem.into());
            actual.insert("SYSNAME".into(), entry.file_name().to_string_lossy().into_owned());
            if let Ok(path) = path.canonicalize() { if let Ok(relative) = path.strip_prefix("/sys") { actual.insert("DEVPATH".into(), format!("/{}",relative.display())); } }
            if let Ok(uevent) = std::fs::read_to_string(path.join("uevent")) {
                for line in uevent.lines() { if let Some((k,v))=line.split_once('=') { actual.insert(k.into(),v.into()); } }
            }
            if let Ok(dev) = std::fs::read_to_string(path.join("dev")) {
                let udev_path = format!("/run/udev/data/{prefix}{}", dev.trim());
                if let Ok(data) = std::fs::read_to_string(udev_path) {
                    for line in data.lines().filter_map(|line| line.strip_prefix("E:")) { if let Some((k,v))=line.split_once('=') { actual.insert(k.into(),v.into()); } }
                }
            }
            if wanted.iter().all(|(key,value)| value.as_str().is_some_and(|v| actual.get(key).is_some_and(|observed|observed==v))) { return Ok(true); }
        }
    }
    if !observed_directory { return Err("pid2-device-sense-unavailable".into()); }
    Ok(false)
}

type Visiting = HashSet<(String,String)>;
fn resolve_line(routine: &str, name: &str, senses: &super::events::Senses, visiting: &mut Visiting) -> Result<(),String> {
    let raw: Option<Vec<u8>> = {
        let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
        db.query_row("SELECT envelope FROM pid2_registrations WHERE routine_id=?1 AND enabled=1",[routine],|r|r.get(0)).optional().map_err(|e|e.to_string())?
    };
    let raw=raw.ok_or("pid2-required-routine-unavailable")?;
    let value:Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
    let found=value.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten().find(|stage|stage.get("line").and_then(Value::as_str)==Some(name));
    if let Some(item)=found { stage(routine,item,senses,visiting)?; }
    Ok(())
}

fn needs(routine: &str, stage_line: &str, need: &Value, senses: &super::events::Senses, visiting: &mut Visiting) -> Result<Option<String>, String> {
    let kind = need.get("kind").and_then(Value::as_str).ok_or("pid2-need-kind-missing")?;
    match kind {
        "observe" => {
            if let Some((Some(value), state)) = line(routine, stage_line)? { if state=="Observed" { return Ok(Some(value)); } }
            if !senses.online("udev") { return Err("pid2-udev-sense-unavailable".into()); }
            if need.get("observer").and_then(Value::as_str) != Some("drm-connector") { return Err("pid2-observer-unknown".into()); }
            let pattern = need.get("pattern").and_then(Value::as_str).unwrap_or("*-HDMI-*");
            let value = observe_drm(pattern)?;
            write_line(routine,stage_line,Some(&value),"Observed",None)?;
            Ok(Some(value))
        }
        "await-mount" => {
            let path = need.get("path").and_then(Value::as_str).ok_or("pid2-mount-path-missing")?;
            if mount_point(path)? { Ok(None) } else { Err("pid2-await-mount".into()) }
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
    let name=stage.get("line").and_then(Value::as_str).ok_or("pid2-line-name-missing")?;
    if visiting.len()>=128 { return Err("pid2-dependency-depth-exceeded".into()); }
    let key=(routine.to_owned(),name.to_owned());
    if !visiting.insert(key.clone()) { return Err("pid2-dependency-cycle".into()); }
    let result=stage_inner(routine,stage,senses,visiting);
    visiting.remove(&key);
    result
}
fn stage_inner(routine: &str, stage: &Value, senses: &super::events::Senses, visiting: &mut Visiting) -> Result<(), String> {
    let name = stage.get("line").and_then(Value::as_str).ok_or("pid2-line-name-missing")?;
    let mut value = None;
    for need in stage.get("needs").and_then(Value::as_array).into_iter().flatten() {
        if let Some(branch)=need.get("when_line").and_then(Value::as_str) {
            resolve_line(routine,branch,senses,visiting)?;
            let selected=line(routine,branch)?.and_then(|x|x.0).ok_or("pid2-need-branch-unobserved")?;
            let expected=need.get("when_value").and_then(Value::as_str).unwrap_or("true");
            if selected != expected { continue; }
        }
        match needs(routine,name,need,senses,visiting) {
            Ok(Some(v)) => value=Some(v),
            Ok(None) => {},
            Err(reason) => { write_line(routine,name,None,"Waiting",Some(&reason))?; return Ok(()); }
        }
    }
    if let Some(select) = stage.get("select").filter(|v| !v.is_null()) {
        if let Some((Some(existing),state)) = line(routine,name)? {
            if state == "Observed" { value=Some(existing); }
        }
        if value.is_none() {
            let source = select.get("line").and_then(Value::as_str).ok_or("pid2-select-line-missing")?;
            resolve_line(routine,source,senses,visiting)?;
            let source_value = line(routine,source)?.and_then(|v|v.0).ok_or("pid2-select-source-not-observed")?;
            let chosen = select.get("map").and_then(|m|m.get(&source_value)).and_then(Value::as_str).ok_or("pid2-select-value-undefined")?;
            write_line(routine,name,Some(chosen),"Observed",None)?;
            value=Some(chosen.to_owned());
        }
    }
    for action in stage.get("actions").and_then(Value::as_array).into_iter().flatten() {
        if let Some(branch) = action.get("when_line").and_then(Value::as_str) {
            let expected = action.get("when_value").and_then(Value::as_str).unwrap_or("true");
            resolve_line(routine,branch,senses,visiting)?;
            let branch_value = line(routine,branch)?.and_then(|x|x.0).ok_or("pid2-action-branch-unobserved")?;
            if branch_value != expected { continue; }
        }
        let unit = action.get("unit").and_then(Value::as_str).ok_or("pid2-action-unit-missing")?;
        let scope = unit_scope(unit)?;
        if !senses.online(&scope) { write_line(routine,name,None,"Held",Some("pid2-systemd-sense-unavailable"))?; return Ok(()); }
        if let Some(declared) = action.get("scope").and_then(Value::as_str) { if declared != scope { return Err("pid2-unit-scope-mismatch".into()); } }
        match ensure_running(routine,unit,&scope,stage) {
            Ok(true) => {},
            Ok(false) => { write_line(routine,name,None,"Waiting",Some("pid2-await-ready"))?; return Ok(()); },
            Err(reason) => { write_line(routine,name,None,"Held",Some(&reason))?; return Ok(()); }
        }
    }
    write_line(routine,name,Some(value.as_deref().unwrap_or("true")),if value.is_some(){"Observed"}else{"Done"},None)
}

pub fn owner_answer(routine: &str, name: &str, answer: &str) -> Result<Value, String> {
    if routine.is_empty() || name.is_empty() || !["true","false","yes","no"].contains(&answer) { return Err("pid2-owner-answer-invalid".into()); }
    write_line(routine,name,Some(answer),"Answered",None)?;
    super::events::notify();
    Ok(json!({"ok":true,"routine_id":routine,"line":name,"value":answer}))
}

fn reconcile_stops(senses: &super::events::Senses) -> Result<(),String> {
    let mut previous=(String::new(),String::new(),String::new());
    loop {
        let item: Option<(String,String,String,String,Option<String>)> = {
            let db=crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
            db.query_row("SELECT unit,scope,routine_id,life,last_receipt FROM pid2_programs WHERE desired='Stop' AND (unit,scope,routine_id)>(?1,?2,?3) ORDER BY unit,scope,routine_id LIMIT 1",params![previous.0,previous.1,previous.2],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(|e|e.to_string())?
        };
        let Some((unit,scope,routine,_,_))=item else { break; };
        previous=(unit.clone(),scope.clone(),routine.clone());
        let _guard=super::ACTION_LOCK.lock().map_err(|_|"pid2-action-lock-poisoned")?;
        let (desired,life,receipt)=program(&routine,&unit,&scope)?;
        if desired!="Stop" { continue; }
        if !senses.online(&scope) { program_state(&routine,&unit,&scope,"Held",Some("pid2-systemd-sense-unavailable"))?; continue; }
        match unit_status(&unit,&scope) {
            Ok(status) => match status.pointer("/readback/active_state").and_then(Value::as_str) {
                Some("inactive" | "failed") => program_state(&routine,&unit,&scope,"Held",Some("stopped"))?,
                Some(_) if life=="Stopping" && receipt.as_deref()==Some("stop-accepted") => {},
                Some(_) => match unit_call("stop",&unit,&scope) {
                    Ok(reply) if reply.get("ok").and_then(Value::as_bool)==Some(true) => program_state(&routine,&unit,&scope,"Stopping",Some("stop-accepted"))?,
                    Ok(_) => program_state(&routine,&unit,&scope,"Held",Some("pid2-stop-refused"))?,
                    Err(error) => program_state(&routine,&unit,&scope,"Held",Some(&error))?,
                },
                None => program_state(&routine,&unit,&scope,"Held",Some("pid2-unit-state-unobserved"))?,
            },
            Err(error) => program_state(&routine,&unit,&scope,"Held",Some(&error))?,
        }
    }
    Ok(())
}

pub fn reconcile(senses: &super::events::Senses) -> Result<(), String> {
    for _ in 0..64 {
        let before=REVISION.load(Ordering::Relaxed);
        reconcile_stops(senses)?;
        reconcile_routines(senses)?;
        let after=REVISION.load(Ordering::Relaxed);
        if after==before { return Ok(()); }
    }
    super::events::notify();
    Ok(())
}

fn reconcile_routines(senses: &super::events::Senses) -> Result<(), String> {
    let mut after = String::new();
    loop {
        let next: Option<(String,Vec<u8>)> = {
            let db = crate::stats::open_db()?.lock().map_err(|_| "pid2-database-lock-poisoned")?;
            tables(&db)?;
            db.query_row("SELECT routine_id,envelope FROM pid2_registrations WHERE enabled=1 AND routine_id>?1 ORDER BY routine_id LIMIT 1", [&after], |r| Ok((r.get(0)?,r.get(1)?))).optional().map_err(|e| e.to_string())?
        };
        let Some((id,raw)) = next else { break; };
        after = id.clone();
        let envelope: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        for item in envelope.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten() {
            for action in item.get("actions").and_then(Value::as_array).into_iter().flatten() {
                if let Some(unit)=action.get("unit").and_then(Value::as_str) {
                    if let Ok(scope)=unit_scope(unit) { let _=program(&id,unit,&scope)?; }
                }
            }
        }
        for item in envelope.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten() {
            if let Err(error) = stage(&id,item,senses,&mut Visiting::new()) {
                if let Some(name)=item.get("line").and_then(Value::as_str) { write_line(&id,name,None,"Held",Some(&error))?; }
            }
        }
    }
    Ok(())
}
