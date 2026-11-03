//! Coalesced event wakes; observations are always re-read by the solver.
use futures_util::{FutureExt, StreamExt};
use serde_json::Value;
use std::{collections::{HashMap, HashSet, VecDeque}, ffi::CString, io::{Read, Seek, SeekFrom, Write}, os::fd::{AsRawFd, FromRawFd, OwnedFd}, path::PathBuf, sync::{Arc, Mutex, OnceLock, RwLock, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::{io::{unix::AsyncFd, AsyncBufReadExt, AsyncReadExt, BufReader, Interest}, sync::mpsc};
use zbus::{Connection, Message, MatchRule, MessageStream, Proxy, message::Type, zvariant::{OwnedObjectPath, OwnedValue}};

#[path="kernel_senses.rs"]
pub(super) mod kernel_senses;

#[derive(Clone,Debug,Eq,Hash,PartialEq,serde::Serialize,serde::Deserialize)]
pub(super) enum DeviceState {
    Unknown,
    Absent,
    Known { facts:Vec<(String,String)>, connector:Option<String> },
}
#[derive(Clone,Debug,Eq,Hash,PartialEq,serde::Serialize,serde::Deserialize)]
pub(super) enum DirtyKey {
    All, Startup, Unit(String,String), Job(String,String), Sense(String), Mount(PathBuf), Device(String,String,DeviceState,DeviceState),
    Netns(String), Link(String,String), File(PathBuf), Routine(String), Line(String,String), Schedule, Offline(String), Unavailable(String),
}
#[derive(Default)]
struct Pending { keys:HashSet<DirtyKey>, full:bool }
#[derive(Clone)]
struct Wake { tx:mpsc::Sender<()>, pending:Arc<Mutex<Pending>>, offline:Arc<std::sync::atomic::AtomicU8>, reconfigure:tokio::sync::watch::Sender<()>, mount_event:tokio::sync::watch::Sender<()> }
impl Wake {
    // Preserve a failed walk's inputs without generating a self-wake.  They
    // join the next real event; overflow remains one bounded full walk.
    fn retain(&self,keys:Vec<DirtyKey>) {
        if let Ok(mut pending)=self.pending.lock() {
            for key in keys {
                if pending.full {break;}
                if key==DirtyKey::All {pending.full=true; pending.keys.clear();}
                else if pending.keys.len()>=512 && !pending.keys.contains(&key) {
                    pending.full=true; pending.keys.clear(); super::solver::deed("dirty-overflow","pid2","full-walk",None);
                } else {pending.keys.insert(key);}
            }
        }
    }
    fn push(&self,key:DirtyKey) {
        if matches!(key,DirtyKey::Routine(_)|DirtyKey::All|DirtyKey::Startup) { self.reconfigure.send_replace(()); }
        if let Ok(mut pending)=self.pending.lock() {
            if !pending.full {
                if key==DirtyKey::All { pending.full=true; pending.keys.clear(); }
                else if pending.keys.len()>=512 && !pending.keys.contains(&key) { pending.full=true; pending.keys.clear(); super::solver::deed("dirty-overflow","pid2","full-walk",None); }
                else { pending.keys.insert(key); }
            }
        }
        let _=self.tx.try_send(());
    }
    fn offline(&self,scope:&str) {
        let bit=match scope {"system"=>1,"owner"=>2,"udev"=>4,"mount"=>8,"netns"=>16,"link"=>32,"file"=>64,_=>0};
        if let Ok(mut pending)=self.pending.lock() {
            self.offline.fetch_or(bit,Ordering::AcqRel);
            if !pending.full {
                let key=DirtyKey::Unavailable(scope.to_owned());
                if pending.keys.len()>=512 && !pending.keys.contains(&key) { pending.full=true; pending.keys.clear(); super::solver::deed("dirty-overflow","pid2","full-walk",None); }
                else { pending.keys.insert(key); }
            }
        }
        let _=self.tx.try_send(());
    }
    fn closed(&self)->bool { self.tx.is_closed() }
}
fn wake(tx: &Wake) { tx.push(DirtyKey::All); }
fn sense(tx:&Wake,scope:&str) { tx.push(DirtyKey::Sense(scope.to_owned())); }
fn unit_wake(tx:&Wake,scope:&str,name:&str) { tx.push(DirtyKey::Unit(scope.to_owned(),name.to_owned())); }
fn job_wake(tx:&Wake,scope:&str,name:&str) { tx.push(DirtyKey::Job(scope.to_owned(),name.to_owned())); }

// Only the latest active/non-active observations are retained for each declared
// unit. A failure stores a sequence fence so an earlier active observation cannot
// be mistaken for a later recovery; reconnects require a new non-active baseline.
struct UnitTransitions { session:String, sequence:u64, rows:HashMap<(String,String),(u64,u64)> }
impl Default for UnitTransitions {
    fn default()->Self { Self{session:uuid::Uuid::new_v4().to_string(),sequence:0,rows:HashMap::new()} }
}
fn transitions() -> &'static Mutex<UnitTransitions> {
    static TRANSITIONS:OnceLock<Mutex<UnitTransitions>>=OnceLock::new();
    TRANSITIONS.get_or_init(||Mutex::new(UnitTransitions::default()))
}
fn record_transition(scope:&str,unit:&str) {
    let Some(state)=crate::stats::indicators::unit_state::get(scope,unit) else { return; };
    let Some(active)=state.active_state.as_deref() else { return; };
    if !matches!(active,"active"|"inactive"|"failed") { return; }
    if let Ok(mut events)=transitions().lock() {
        events.sequence=events.sequence.saturating_add(1);
        let sequence=events.sequence;
        let row=events.rows.entry((scope.to_owned(),unit.to_owned())).or_default();
        if active=="active" { row.0=sequence; } else { row.1=sequence; }
    }
}
pub(super) fn transition_mark() -> (String,u64) {
    transitions().lock().map(|e|(e.session.clone(),e.sequence)).unwrap_or((String::new(),u64::MAX))
}
pub(super) fn unit_transitions(scope:&str,unit:&str) -> (u64,u64) {
    transitions().lock().ok().and_then(|e|e.rows.get(&(scope.to_owned(),unit.to_owned())).copied()).unwrap_or_default()
}

// systemd's bus label escaping: every byte outside [A-Za-z0-9] becomes _xx.
fn unit_path(unit: &str) -> String {
    let label: String = unit.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("_{b:02x}") }).collect();
    format!("/org/freedesktop/systemd1/unit/{label}")
}
// The action enum is fixed; observe-unit adds enabled routine names dynamically.
fn unit_sets()->&'static RwLock<HashMap<String,HashSet<String>>> {
    static SETS:OnceLock<RwLock<HashMap<String,HashSet<String>>>>=OnceLock::new();
    SETS.get_or_init(||RwLock::new(enum_units()))
}
fn enum_units()->HashMap<String,HashSet<String>> {
    let mut sets=HashMap::<String,HashSet<String>>::new();
    if let Some(units)=crate::routes::leaf_schema::declaration(super::SCHEMA).and_then(|seat|seat.get("unit_enum")).and_then(Value::as_array) {
        for unit in units {
            if let (Some(scope),Some(name))=(unit.get("scope").and_then(Value::as_str),unit.get("unit").and_then(Value::as_str)) {sets.entry(scope.to_owned()).or_default().insert(name.to_owned());}
        }
    }
    sets
}
fn refresh_units()->Result<(),String> {
    static REFRESH:Mutex<()>=Mutex::new(());
    let _refresh=REFRESH.lock().map_err(|_|"pid2-unit-refresh-lock-poisoned")?;
    let mut sets=enum_units();
    if let Some(db)=super::read_db()? {
        if super::table_exists(&db,"pid2_registrations")? {
            let mut q=db.prepare("SELECT routine_id,envelope FROM pid2_registrations WHERE enabled=1").map_err(|e|e.to_string())?;
            let rows=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?))).map_err(|e|e.to_string())?;
            for row in rows {
                let (routine,raw)=row.map_err(|e|e.to_string())?;
                let envelope:Value=match serde_json::from_slice(&raw) {Ok(value)=>value,Err(_)=>{let name:String=routine.chars().take(48).collect();eprintln!("pid2-unit-config-invalid routine_prefix={name:?} routine_bytes={} routine_md5={:x}",routine.len(),md5::compute(routine.as_bytes()));continue;}};
                for need in envelope.pointer("/routine/stages").and_then(Value::as_array).into_iter().flatten().flat_map(|s|["needs","until"].into_iter().flat_map(move |key|s.get(key).and_then(Value::as_array).into_iter().flatten())) {
                    if need.get("kind").and_then(Value::as_str)==Some("observe-unit") {
                        if let Some(name)=need.get("unit").and_then(Value::as_str) {
                            let scope=need.get("scope").and_then(Value::as_str).unwrap_or("system");
                            if matches!(scope,"system"|"owner") {sets.entry(scope.to_owned()).or_default().insert(name.to_owned());}
                        }
                    }
                }
            }
        } else {return Err("pid2-unit-watch-table-absent".into());}
    } else {return Err("pid2-unit-watch-db-absent".into());}
    *unit_sets().write().map_err(|_|"pid2-unit-watch-lock-poisoned")?=sets;
    Ok(())
}
fn scoped_units(scope:&str)->HashSet<String> {
    unit_sets().read().ok().and_then(|sets|sets.get(scope).cloned()).unwrap_or_default()
}
fn installed_units()->&'static RwLock<HashMap<String,HashSet<String>>> {
    static SETS:OnceLock<RwLock<HashMap<String,HashSet<String>>>>=OnceLock::new();
    SETS.get_or_init(||RwLock::new(HashMap::new()))
}
pub(super) fn unit_watch_ready(scope:&str,unit:&str)->bool {
    installed_units().read().is_ok_and(|sets|sets.get(scope).is_some_and(|names|names.contains(unit)))
}
fn set_installed(scope:&str,units:HashSet<String>) {
    crate::stats::indicators::unit_state::retain_scope(scope,&units);
    if let Ok(mut events)=transitions().lock() {events.rows.retain(|(row_scope,unit),_|row_scope!=scope || units.contains(unit));}
    if let Ok(mut sets)=installed_units().write() {sets.insert(scope.to_owned(),units);}
}
fn clear_installed(scope:&str) {
    if let Ok(mut events)=transitions().lock() {events.rows.retain(|(row_scope,_),_|row_scope!=scope);}
    if let Ok(mut sets)=installed_units().write() {sets.remove(scope);}
}
fn declared(scope:&str)->(HashSet<String>,HashSet<String>) {
    let names=scoped_units(scope);
    let paths=names.iter().map(|unit|unit_path(unit)).collect();
    (names,paths)
}
async fn snapshot_scope(conn: &Connection, scope: &str, events: &mut MessageStream, manager_owner: &str, pending: &mut VecDeque<Message>) -> Result<(bool,zbus::message::Sequence), String> {
    // Drain the bus while ListUnits is in flight. Reload can announce many
    // unrelated units; letting their bounded queue fill would block its reply.
    let call=conn.call_method(Some("org.freedesktop.systemd1"),"/org/freedesktop/systemd1",Some("org.freedesktop.systemd1.Manager"),"ListUnits",&());
    tokio::pin!(call);
    let reply=loop {
        tokio::select! {
            biased;
            result=&mut call => break result.map_err(|e|e.to_string())?,
            item=events.next() => match item {
                Some(Ok(message)) if manager_owner_changed(&message) => return Err("pid2-systemd-owner-changed".into()),
                Some(Ok(message)) if message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(scope,&message) => {
                    if pending.len()>=256 { return Err("pid2-snapshot-signal-overflow".into()); }
                    pending.push_back(message);
                },
                Some(Ok(_)) => {},
                Some(Err(error)) => return Err(error.to_string()),
                None => return Err("pid2-systemd-stream-closed".into()),
            }
        }
    };
    let rows: Vec<crate::stats::indicators::unit_state::UnitRow> = reply.body().deserialize().map_err(|e|e.to_string())?;
    let watched=scoped_units(scope);
    let settled:HashSet<String>=watched.iter().filter(|unit|rows.iter().find(|row|&row.0==*unit).is_none_or(|row|row.7==0)).cloned().collect();
    let before:HashMap<String,Option<String>>=watched.iter().map(|unit|(unit.clone(),crate::stats::indicators::unit_state::get(scope,unit).and_then(|s|s.active_state))).collect();
    pending.retain(|message|message.recv_position()>reply.recv_position());
    let changed=crate::stats::indicators::unit_state::snapshot(scope, &watched, rows);
    for unit in settled {
        let active=crate::stats::indicators::unit_state::get(scope,&unit).and_then(|s|s.active_state);
        if active.as_deref().is_some_and(|a|matches!(a,"inactive"|"failed")) || before.get(&unit)!=Some(&active) { record_transition(scope,&unit); }
    }
    Ok((!changed.is_empty(),reply.recv_position()))
}
fn message_unit(scope:&str,message:&Message)->Option<String> {
    let header=message.header();
    match header.member().map(|m|m.as_str()) {
        Some("PropertiesChanged") => header.path().and_then(|p|scoped_units(scope).into_iter().find(|u|unit_path(u)==p.as_str())),
        Some("UnitNew"|"UnitRemoved") => message.body().deserialize::<(String,OwnedObjectPath)>().ok().map(|v|v.0),
        Some("JobRemoved") => message.body().deserialize::<(u32,OwnedObjectPath,String,String)>().ok().map(|v|v.2),
        _=>None,
    }
}
fn update_scope(scope: &str, message: &Message) -> Result<bool, String> {
    use crate::stats::indicators::unit_state;
    let header = message.header();
    match header.member().map(|m| m.as_str()) {
        Some("PropertiesChanged") => {
            let path = header.path().ok_or("pid2-unit-path-missing")?;
            let unit = scoped_units(scope).into_iter().find(|u| unit_path(u) == path.as_str()).ok_or("pid2-unit-not-watched")?;
            let (interface, mut changed, invalidated): (String, HashMap<String, OwnedValue>, Vec<String>) = message.body().deserialize().map_err(|e| format!("pid2-unit-signal-invalid: {e}"))?;
            if interface != "org.freedesktop.systemd1.Unit" { return Ok(false); }
            if invalidated.iter().any(|v| v == "ActiveState" || v == "SubState") { return Err("pid2-unit-state-invalidated".into()); }
            let active = changed.remove("ActiveState").map(|v| String::try_from(v).map(Some).map_err(|e| e.to_string())).transpose()?;
            let sub = changed.remove("SubState").map(|v| String::try_from(v).map(Some).map_err(|e| e.to_string())).transpose()?;
            let before=unit_state::get(scope,&unit).and_then(|v|v.active_state);
            let updated=unit_state::update(scope, &unit, active, sub, None);
            if updated && before!=unit_state::get(scope,&unit).and_then(|v|v.active_state) { record_transition(scope,&unit); }
            Ok(updated)
        },
        Some("UnitRemoved") => {
            let (unit, _): (String, OwnedObjectPath) = message.body().deserialize().map_err(|e| e.to_string())?;
            let before=unit_state::get(scope,&unit).and_then(|v|v.active_state);
            let updated=unit_state::update(scope, &unit, Some(Some("inactive".into())), Some(Some("dead".into())), Some(Some("unloaded".into())));
            if updated && before.as_deref()!=Some("inactive") { record_transition(scope,&unit); }
            Ok(updated)
        },
        Some("UnitNew") => {
            let (unit, _): (String, OwnedObjectPath) = message.body().deserialize().map_err(|e| e.to_string())?;
            Ok(unit_state::update(scope, &unit, None, None, Some(Some("loaded".into()))))
        },
        Some("JobRemoved") => {
            let (_, _, unit, _): (u32, OwnedObjectPath, String, String) = message.body().deserialize().map_err(|e| e.to_string())?;
            Ok(scoped_units(scope).contains(&unit))
        },
        _ => Ok(false),
    }
}
// Only a signal about a declared unit wakes the solver. Its own status reads
// open logind sessions and transient units; their signals are not news.
fn concerns_declared(scope: &str, message: &Message) -> bool {
    let header = message.header();
    let (names, paths) = declared(scope);
    match header.member().map(|m| m.as_str()) {
        Some("PropertiesChanged") => header.path().is_some_and(|p| paths.contains(p.as_str())) &&
            message.body().deserialize::<(String, HashMap<String, OwnedValue>, Vec<String>)>().is_ok_and(|(interface, changed, invalidated)| {
                interface == "org.freedesktop.systemd1.Unit" && ["ActiveState", "SubState"].iter().any(|key| changed.contains_key(*key) || invalidated.iter().any(|value| value == key))
            }),
        Some("UnitNew" | "UnitRemoved") => message.body().deserialize::<(String, OwnedObjectPath)>().is_ok_and(|(unit, _)| names.contains(&unit)),
        Some("JobRemoved") => message.body().deserialize::<(u32, OwnedObjectPath, String, String)>().is_ok_and(|(_, _, unit, _)| names.contains(&unit)),
        Some("Reloading") => message.body().deserialize::<(bool,)>().is_ok_and(|(active,)| !active),
        _ => false,
    }
}

fn manager_owner_changed(message: &Message) -> bool {
    let header=message.header();
    header.sender().is_some_and(|s|s.as_str()=="org.freedesktop.DBus") &&
        header.path().is_some_and(|p|p.as_str()=="/org/freedesktop/DBus") &&
        header.interface().is_some_and(|i|i.as_str()=="org.freedesktop.DBus") &&
        header.member().is_some_and(|m|m.as_str()=="NameOwnerChanged") &&
        message.body().deserialize::<(String,String,String)>().is_ok_and(|(name,_,_)|name=="org.freedesktop.systemd1")
}

// Establish a receive-order barrier and apply already delivered later events
// before making a snapshot available to the solver.
async fn settled_scope(conn: &Connection, scope: &str, events: &mut MessageStream, manager_owner: &str, pending: &mut VecDeque<Message>) -> Result<zbus::message::Sequence, String> {
    let (_,mut barrier)=snapshot_scope(conn,scope,events,manager_owner,pending).await?;
    loop {
        let query=conn.call_method(Some("org.freedesktop.DBus"),"/org/freedesktop/DBus",Some("org.freedesktop.DBus"),"GetNameOwner",&("org.freedesktop.systemd1",));
        tokio::pin!(query);
        let reply=loop {
            tokio::select! {
                biased;
                result=&mut query => break result.map_err(|e|e.to_string())?,
                item=events.next() => match item {
                    Some(Ok(message)) if manager_owner_changed(&message) => return Err("pid2-systemd-owner-changed".into()),
                    Some(Ok(message)) if message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(scope,&message) => {
                        if pending.len()>=256 { return Err("pid2-snapshot-signal-overflow".into()); }
                        pending.push_back(message);
                    },
                    Some(Ok(_)) => {},
                    Some(Err(error)) => return Err(error.to_string()),
                    None => return Err("pid2-systemd-stream-closed".into()),
                }
            }
        };
        let current: String=reply.body().deserialize().map_err(|e|e.to_string())?;
        if current!=manager_owner { return Err("pid2-systemd-owner-changed".into()); }
        loop {
            let item=if let Some(message)=pending.pop_front() { Some(Some(Ok(message))) } else { events.next().now_or_never() };
            match item {
                None => return Ok(barrier),
                Some(Some(Ok(message))) if manager_owner_changed(&message) => return Err("pid2-systemd-owner-changed".into()),
                Some(Some(Ok(message))) if message.recv_position()>barrier && message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(scope,&message) => {
                    let reloading=message.header().member().is_some_and(|m|m.as_str()=="Reloading");
                    let invalidated=if reloading { false } else {
                        match update_scope(scope,&message) {
                            Ok(_) => false,
                            Err(error) if error=="pid2-unit-state-invalidated" => true,
                            Err(error) if error=="pid2-unit-not-watched" => false,
                            Err(error) => return Err(error),
                        }
                    };
                    if reloading || invalidated {
                        let (_,position)=snapshot_scope(conn,scope,events,manager_owner,pending).await?;
                        barrier=position;
                        break;
                    }
                },
                Some(Some(Ok(_))) => {},
                Some(Some(Err(error))) => return Err(error.to_string()),
                Some(None) => return Err("pid2-systemd-stream-closed".into()),
            }
        }
    }
}

fn owner_uid() -> Result<u32, String> {
    let name = CString::new("owner").map_err(|e| e.to_string())?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buf = [0u8; 16384];
    let status = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
    if status != 0 || result.is_null() { return Err("pid2-owner-account-unavailable".into()); }
    Ok(pwd.pw_uid)
}

async fn streams(conn: &Connection, scope: &str) -> Result<(MessageStream,String),String> {
    // One receive-ordered stream prevents Manager and PropertiesChanged signals
    // from overtaking one another after a reload or a collected unit's return.
    let mut incoming=MessageStream::from(conn);
    incoming.set_max_queued(1024);
    let bus=Proxy::new(conn,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus").await.map_err(|e|e.to_string())?;
    let owner_rule=MatchRule::builder().msg_type(Type::Signal).sender("org.freedesktop.DBus").map_err(|e|e.to_string())?.path("/org/freedesktop/DBus").map_err(|e|e.to_string())?.interface("org.freedesktop.DBus").map_err(|e|e.to_string())?.member("NameOwnerChanged").map_err(|e|e.to_string())?.add_arg("org.freedesktop.systemd1").map_err(|e|e.to_string())?.build();
    let _: ()=bus.call("AddMatch",&(owner_rule.to_string(),)).await.map_err(|e|e.to_string())?;
    let owner: String=bus.call("GetNameOwner",&("org.freedesktop.systemd1",)).await.map_err(|e|e.to_string())?;
    let proxy = Proxy::new(conn,"org.freedesktop.systemd1","/org/freedesktop/systemd1","org.freedesktop.systemd1.Manager").await.map_err(|e|e.to_string())?;
    for member in ["UnitNew", "UnitRemoved", "JobRemoved", "Reloading"] {
        let rule = MatchRule::builder().msg_type(Type::Signal).sender("org.freedesktop.systemd1").map_err(|e|e.to_string())?.path("/org/freedesktop/systemd1").map_err(|e|e.to_string())?.interface("org.freedesktop.systemd1.Manager").map_err(|e|e.to_string())?.member(member).map_err(|e|e.to_string())?.build();
        let _: ()=bus.call("AddMatch",&(rule.to_string(),)).await.map_err(|e|e.to_string())?;
    }
    for unit in scoped_units(scope) {
        let path = unit_path(&unit);
        let rule = MatchRule::builder().msg_type(Type::Signal).sender("org.freedesktop.systemd1").map_err(|e|e.to_string())?.path(path.as_str()).map_err(|e|e.to_string())?.interface("org.freedesktop.DBus.Properties").map_err(|e|e.to_string())?.member("PropertiesChanged").map_err(|e|e.to_string())?.build();
        let _: ()=bus.call("AddMatch",&(rule.to_string(),)).await.map_err(|e|e.to_string())?;
    }
    let _: () = proxy.call("Subscribe", &()).await.map_err(|e|e.to_string())?;
    Ok((incoming,owner))
}

async fn watch_systemd(tx: Wake, online: Arc<AtomicBool>,mut config:tokio::sync::watch::Receiver<()>) {
    loop {
        if let Err(error)=refresh_units() {
            eprintln!("pid2-system-unit-config: {error}");
        }
        let watched=scoped_units("system");
        let connected: Result<(),String> = async {
            let conn = Connection::system().await.map_err(|e|e.to_string())?;
            let (mut events,manager_owner) = streams(&conn,"system").await?;
            let mut pending=VecDeque::new();
            let mut barrier = settled_scope(&conn,"system",&mut events,&manager_owner,&mut pending).await?;
            if watched!=scoped_units("system") {return Err("pid2-unit-watch-reconfigured".into());}
            set_installed("system",watched.clone());
            crate::stats::indicators::unit_state::set_online("system",true);
            online.store(true,Ordering::Release); sense(&tx,"system");
            loop {
                let item = if let Some(message)=pending.pop_front() { Some(Ok(message)) } else { tokio::select! {
                    result=config.changed()=>{result.map_err(|_|"pid2-unit-config-closed")?;if let Err(error)=refresh_units(){eprintln!("pid2-system-unit-config: {error}");continue;}if watched!=scoped_units("system") {return Err("pid2-unit-watch-reconfigured".into());}continue;},
                    message=events.next()=>message,
                }};
                match item {
                    Some(Ok(message)) if manager_owner_changed(&message) => return Err("pid2-systemd-owner-changed".into()),
                    Some(Ok(message)) if message.recv_position()>barrier && message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared("system",&message) => {
                        let reloading = message.header().member().is_some_and(|m| m.as_str()=="Reloading");
                        let changed = if reloading {
                            crate::stats::indicators::unit_state::set_online("system",false); online.store(false,Ordering::Release); tx.offline("system");
                            barrier=settled_scope(&conn,"system",&mut events,&manager_owner,&mut pending).await?;
                            crate::stats::indicators::unit_state::set_online("system",true); online.store(true,Ordering::Release); true
                        } else {
                            match update_scope("system",&message) {
                                Ok(changed) => changed,
                                Err(error) if error=="pid2-unit-state-invalidated" => {
                                    crate::stats::indicators::unit_state::set_online("system",false); online.store(false,Ordering::Release); tx.offline("system");
                                    barrier=settled_scope(&conn,"system",&mut events,&manager_owner,&mut pending).await?;
                                    crate::stats::indicators::unit_state::set_online("system",true); online.store(true,Ordering::Release); true
                                },
                                Err(error) => { eprintln!("pid2-system-signal: {error}"); false }
                            }
                        };
                        if changed { if let Some(name)=message_unit("system",&message) { if message.header().member().is_some_and(|m|m.as_str()=="JobRemoved") { job_wake(&tx,"system",&name); } else { unit_wake(&tx,"system",&name); } } else { sense(&tx,"system"); } }
                    },
                    Some(Ok(_)) => {},
                    Some(Err(e)) => return Err(e.to_string()), None => return Err("pid2-systemd-stream-closed".into())
                }
            }
        }.await;
        clear_installed("system");
        crate::stats::indicators::unit_state::set_online("system",false);
        online.store(false,Ordering::Release); tx.offline("system");
        let reconfigured=matches!(&connected,Err(error) if error=="pid2-unit-watch-reconfigured");
        if let Err(error)=connected { if !reconfigured {eprintln!("pid2-system-systemd-watch: {error}");} }
        if tx.closed() { return; }
        if reconfigured {continue;}
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

// The owner child has no database and relays only bounded observed unit states.
fn emit_owner_states() -> Result<(),String> {
    for unit in scoped_units("owner") {
        if let Some(state) = crate::stats::indicators::unit_state::get("owner", &unit) {
            let line = serde_json::json!({"kind":"state","unit":unit,"state":state});
            writeln!(std::io::stdout(),"{line}").map_err(|e|e.to_string())?;
        }
    }
    std::io::stdout().flush().map_err(|e|e.to_string())
}
async fn owner_child() -> Result<(),String> {
    let raw=std::env::var("CADUCEUS_PID2_OWNER_UNITS").map_err(|_|"pid2-owner-child-units-missing")?;
    let units:HashSet<String>=serde_json::from_str(&raw).map_err(|_|"pid2-owner-child-units-invalid")?;
    unit_sets().write().map_err(|_|"pid2-unit-watch-lock-poisoned")?.insert("owner".into(),units);
    let uid=owner_uid()?;
    if unsafe { libc::geteuid() } != uid { return Err("pid2-owner-child-wrong-uid".into()); }
    let address=format!("unix:path=/run/user/{uid}/bus");
    let conn=zbus::connection::Builder::address(address.as_str()).map_err(|e|e.to_string())?.build().await.map_err(|e|e.to_string())?;
    let (mut events,manager_owner)=streams(&conn,"owner").await?;
    let mut pending=VecDeque::new();
    let mut barrier=settled_scope(&conn,"owner",&mut events,&manager_owner,&mut pending).await?;
    emit_owner_states()?;
    writeln!(std::io::stdout(),"ready").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?;
    loop {
        let item=if let Some(message)=pending.pop_front() { Some(Ok(message)) } else { events.next().await };
        match item {
            Some(Ok(message)) if manager_owner_changed(&message) => return Err("pid2-systemd-owner-changed".into()),
            Some(Ok(message)) if message.recv_position()>barrier && message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared("owner",&message) => {
                let reloading = message.header().member().is_some_and(|m| m.as_str()=="Reloading");
                let job = message.header().member().is_some_and(|m| m.as_str()=="JobRemoved");
                let changed = if reloading {
                    writeln!(std::io::stdout(),"syncing").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?;
                    barrier=settled_scope(&conn,"owner",&mut events,&manager_owner,&mut pending).await?;
                    emit_owner_states()?;
                    writeln!(std::io::stdout(),"ready").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?;
                    false
                } else {
                    match update_scope("owner",&message) {
                        Ok(changed) => changed,
                        Err(error) if error=="pid2-unit-state-invalidated" => {
                            writeln!(std::io::stdout(),"syncing").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?;
                            barrier=settled_scope(&conn,"owner",&mut events,&manager_owner,&mut pending).await?;
                            emit_owner_states()?;
                            writeln!(std::io::stdout(),"ready").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?;
                            false
                        },
                        Err(error) if error=="pid2-unit-not-watched" => false,
                        Err(error) => return Err(error),
                    }
                };
                if changed { emit_owner_states()?; }
                if changed && job { if let Some(name)=message_unit("owner",&message) { writeln!(std::io::stdout(),"{}",serde_json::json!({"kind":"job","unit":name})).and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?; } }
            },
            Some(Ok(_)) => {},
            Some(Err(e)) => return Err(e.to_string()), None => return Err("pid2-owner-stream-closed".into()),
        }
    }
}

pub fn owner_sense_cli() -> i32 {
    let runtime=match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime)=>runtime, Err(error)=>{ eprintln!("pid2-owner-runtime: {error}"); return 1; }
    };
    match runtime.block_on(owner_child()) { Ok(())=>0, Err(error)=>{eprintln!("pid2-owner-child: {error}");1} }
}

async fn watch_owner(tx: Wake, online: Arc<AtomicBool>,mut config:tokio::sync::watch::Receiver<()>) {
    loop {
        if let Err(error)=refresh_units() {
            eprintln!("pid2-owner-unit-config: {error}");
        }
        let watched=scoped_units("owner");
        let connected = async {
            let executable=std::env::current_exe().map_err(|e|e.to_string())?;
            let uid=owner_uid()?;
            let mut command=if unsafe { libc::geteuid() } == 0 {
                let mut c=tokio::process::Command::new("runuser"); c.arg("-u").arg("owner").arg("--").arg(executable); c
            } else if unsafe { libc::geteuid() } == uid {
                tokio::process::Command::new(executable)
            } else { return Err("pid2-owner-sense-wrong-uid".into()); };
            let watched_json=serde_json::to_string(&watched).map_err(|e|e.to_string())?;
            command.arg("pid2-owner-sense").env("CADUCEUS_PID2_OWNER_UNITS",watched_json).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).kill_on_drop(true);
            let mut child=command.spawn().map_err(|e|e.to_string())?;
            let stdout=child.stdout.take().ok_or("pid2-owner-child-pipe-missing")?;
            let mut lines=BufReader::new(stdout);
            let mut bytes=Vec::new();
            let mut reconfigure_pending=false;
            loop {
                if reconfigure_pending && bytes.is_empty() {return Err("pid2-unit-watch-reconfigured".into());}
                let count=if bytes.last()==Some(&b'\n') {bytes.len()} else {
                    let mut bounded=(&mut lines).take(4097u64.saturating_sub(bytes.len() as u64));
                    tokio::select! {
                        result=config.changed()=>{result.map_err(|_|"pid2-unit-config-closed")?;if let Err(error)=refresh_units(){eprintln!("pid2-owner-unit-config: {error}");continue;}reconfigure_pending=watched!=scoped_units("owner");continue;},
                        result=bounded.read_until(b'\n',&mut bytes)=>result.map_err(|e|e.to_string())?,
                    }
                };
                if count==0 { break; }
                if bytes.len()>4096 || bytes.last()!=Some(&b'\n') { return Err("pid2-owner-child-line-too-long".into()); }
                bytes.pop();
                let line=String::from_utf8(std::mem::take(&mut bytes)).map_err(|_|"pid2-owner-child-protocol-invalid")?;
                match line.as_str() {
                    "syncing" => { if online.load(Ordering::Acquire) {crate::stats::indicators::unit_state::set_online("owner",false); online.store(false,Ordering::Release); tx.offline("owner");} },
                    "ready" => { if watched!=scoped_units("owner") {return Err("pid2-unit-watch-reconfigured".into());} set_installed("owner",watched.clone()); crate::stats::indicators::unit_state::set_online("owner",true); online.store(true,Ordering::Release); eprintln!("pid2-owner-sense-online"); sense(&tx,"owner"); },
                    "job" if online.load(Ordering::Acquire) => { sense(&tx,"owner"); },
                    _ => {
                        let frame: serde_json::Value = serde_json::from_str(&line).map_err(|_|"pid2-owner-child-protocol-invalid")?;
                        let unit = frame.get("unit").and_then(|v|v.as_str()).ok_or("pid2-owner-child-unit-missing")?;
                        if !watched.contains(unit) { return Err("pid2-owner-child-unit-undeclared".into()); }
                        if frame.get("kind").and_then(|v|v.as_str())==Some("job") { if online.load(Ordering::Acquire) { job_wake(&tx,"owner",unit); } continue; }
                        if frame.get("kind").and_then(|v|v.as_str()) != Some("state") { return Err("pid2-owner-child-protocol-invalid".into()); }
                        let state: crate::stats::indicators::unit_state::UnitState = serde_json::from_value(frame.get("state").cloned().ok_or("pid2-owner-child-state-missing")?).map_err(|e|e.to_string())?;
                        let before=crate::stats::indicators::unit_state::get("owner",unit).and_then(|v|v.active_state);
                        let active=state.active_state.clone();
                        if crate::stats::indicators::unit_state::set("owner",unit,state) {
                            if before!=active { record_transition("owner",unit); }
                            if online.load(Ordering::Acquire) { unit_wake(&tx,"owner",unit); }
                        }
                    },
                }
            }
            let _=child.wait().await;
            Err::<(),String>("pid2-owner-child-exited".into())
        }.await;
        clear_installed("owner");
        crate::stats::indicators::unit_state::set_online("owner",false);
        online.store(false,Ordering::Release); tx.offline("owner");
        // This identity cannot become root or owner within this process.  Do
        // not let unrelated systemd activity re-arm a permanently failed sense.
        let wrong_uid=matches!(&connected, Err(error) if error=="pid2-owner-sense-wrong-uid");
        let reconfigured=matches!(&connected,Err(error) if error=="pid2-unit-watch-reconfigured");
        if let Err(error)=connected { if !reconfigured {eprintln!("pid2-owner-systemd-watch: {error}");} }
        if wrong_uid { return; }
        if tx.closed() { return; }
        if reconfigured {continue;}
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

fn udev_socket() -> Result<AsyncFd<OwnedFd>, String> {
    let fd = unsafe { libc::socket(libc::AF_NETLINK,libc::SOCK_DGRAM|libc::SOCK_NONBLOCK|libc::SOCK_CLOEXEC,libc::NETLINK_KOBJECT_UEVENT) };
    if fd < 0 { return Err(std::io::Error::last_os_error().to_string()); }
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    address.nl_groups = 2;
    let rc = unsafe { libc::bind(fd.as_raw_fd(),(&address as *const libc::sockaddr_nl).cast(),std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t) };
    if rc < 0 { return Err(std::io::Error::last_os_error().to_string()); }
    AsyncFd::new(fd).map_err(|e|e.to_string())
}

fn udev_change(data: &[u8]) -> Result<Option<(String,String,String)>,()> {
    // Group 2 carries a libudev monitor header, followed by its property block.
    if data.len()<40 || &data[..8]!=b"libudev\0" || &data[8..12]!=[0xfe,0xed,0xca,0xfe] { return Err(()); }
    let word=|offset:usize| u32::from_ne_bytes(data[offset..offset+4].try_into().unwrap()) as usize;
    let header=word(12); let offset=word(16); let length=word(20);
    if header<40 || offset<header || offset.checked_add(length).is_none_or(|end|end>data.len()) { return Err(()); }
    let mut subsystem=None; let mut device=None; let mut action=None;
    for field in data[offset..offset+length].split(|byte|*byte==0).filter(|field|!field.is_empty()) {
        let value=std::str::from_utf8(field).map_err(|_|())?;
        let (key,value)=value.split_once('=').ok_or(())?;
        let slot=match key { "SUBSYSTEM"=>Some(&mut subsystem), "DEVPATH"=>Some(&mut device), "ACTION"=>Some(&mut action), _=>None };
        if let Some(slot)=slot {if slot.is_some_and(|old|old!=value) {return Err(());} *slot=Some(value);}
    }
    let subsystem=subsystem.ok_or(())?;
    if subsystem!="block" && subsystem!="drm" { return Ok(None); }
    let device=device.filter(|v|v.starts_with('/') && v.len()<=4096).ok_or(())?;
    let action=action.ok_or(())?;
    Ok(Some((subsystem.to_owned(),device.to_owned(),action.to_owned())))
}

fn wake_address() -> Result<std::os::unix::net::SocketAddr, String> {
    use std::{hash::{Hash,Hasher},os::linux::net::SocketAddrExt};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    crate::stats::db_path().hash(&mut hasher);
    std::os::unix::net::SocketAddr::from_abstract_name(format!("caduceus-pid2-{:016x}",hasher.finish())).map_err(|e|e.to_string())
}
static LOCAL_WAKE: OnceLock<Wake> = OnceLock::new();
// The datagram is only a hint. Separate processes keep a bounded coalesced
// dirty set in PID 2's SQLite until serve collects it on a wake or heartbeat.
fn persist_wake(key:&DirtyKey) -> Result<(),String> {
    let mut encoded=serde_json::to_string(key).map_err(|e|e.to_string())?;
    if encoded.len()>4096 {encoded=serde_json::to_string(&DirtyKey::All).map_err(|e|e.to_string())?;}
    let all=serde_json::to_string(&DirtyKey::All).map_err(|e|e.to_string())?;
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    super::tables(&db)?;
    let tx=db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).map_err(|e|e.to_string())?;
    let count:i64=tx.query_row("SELECT count(*) FROM pid2_dirty_wakes",[],|r|r.get(0)).map_err(|e|e.to_string())?;
    let is_all:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pid2_dirty_wakes WHERE key=?1)",[&all],|r|r.get(0)).map_err(|e|e.to_string())?;
    let already:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM pid2_dirty_wakes WHERE key=?1)",[&encoded],|r|r.get(0)).map_err(|e|e.to_string())?;
    let overflow=encoded!=all && !is_all && !already && count>=512;
    if encoded==all || overflow {
        tx.execute("DELETE FROM pid2_dirty_wakes",[]).map_err(|e|e.to_string())?;
        tx.execute("INSERT INTO pid2_dirty_wakes(key,queued_at) VALUES(?1,?2)",rusqlite::params![all,super::now()]).map_err(|e|e.to_string())?;
    } else {
        let key=if is_all {&all} else {&encoded};
        // REPLACE allocates a new AUTOINCREMENT id. An acknowledgement of an
        // older snapshot cannot delete a later occurrence of the same key.
        tx.execute("INSERT OR REPLACE INTO pid2_dirty_wakes(key,queued_at) VALUES(?1,?2)",rusqlite::params![key,super::now()]).map_err(|e|e.to_string())?;
    }
    tx.commit().map_err(|e|e.to_string())?;
    drop(db);
    if overflow {super::solver::deed("dirty-overflow","pid2","full-walk",None);}
    Ok(())
}
fn pending_wakes() -> Result<Vec<(i64,DirtyKey)>,String> {
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    let mut q=db.prepare("SELECT id,key FROM pid2_dirty_wakes ORDER BY id").map_err(|e|e.to_string())?;
    let rows=q.query_map([],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?))).map_err(|e|e.to_string())?.collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    Ok(rows.into_iter().map(|(id,raw)|(id,serde_json::from_str(&raw).unwrap_or(DirtyKey::All))).collect())
}
fn acknowledge_wakes(rows:&[(i64,DirtyKey)]) -> Result<(),String> {
    if rows.is_empty() {return Ok(());}
    let mut db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    let tx=db.transaction().map_err(|e|e.to_string())?;
    for (id,_) in rows {tx.execute("DELETE FROM pid2_dirty_wakes WHERE id=?1",[id]).map_err(|e|e.to_string())?;}
    tx.commit().map_err(|e|e.to_string())
}
fn wakes_waiting()->Result<bool,String> {
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    db.query_row("SELECT EXISTS(SELECT 1 FROM pid2_dirty_wakes)",[],|r|r.get(0)).map_err(|e|e.to_string())
}
fn notify_key_result(key:DirtyKey) -> Result<(),String> {
    if let Some(local)=LOCAL_WAKE.get() { local.push(key); }
    else {
        persist_wake(&key).map_err(|error|format!("pid2-command-wake-persist-failed: {error}"))?;
        if let (Ok(addr),Ok(socket),Ok(bytes))=(wake_address(),std::os::unix::net::UnixDatagram::unbound(),serde_json::to_vec(&key)) {
            if let Err(error)=socket.send_to_addr(&bytes,&addr) { eprintln!("pid2-command-wake-undelivered: {error}"); }
        }
    }
    Ok(())
}
fn notify_key(key:DirtyKey) {if let Err(error)=notify_key_result(key) {eprintln!("{error}");}}
pub fn notify() { notify_key(DirtyKey::All); }
pub(super) fn notify_routine(id:&str) -> Result<(),String> { notify_key_result(DirtyKey::Routine(id.to_owned())) }
pub(super) fn notify_line(id:&str,line:&str) -> Result<(),String> { notify_key_result(DirtyKey::Line(id.to_owned(),line.to_owned())) }
pub(super) fn notify_unit(scope:&str,name:&str) -> Result<(),String> { notify_key_result(DirtyKey::Unit(scope.to_owned(),name.to_owned())) }
pub(super) fn notify_schedule() -> Result<(),String> { notify_key_result(DirtyKey::Schedule) }
async fn watch_commands(tx: Wake) {
    let result = (|| -> Result<tokio::net::UnixDatagram,String> {
        let addr = wake_address()?;
        let socket = std::os::unix::net::UnixDatagram::bind_addr(&addr).map_err(|e|e.to_string())?;
        socket.set_nonblocking(true).map_err(|e|e.to_string())?;
        tokio::net::UnixDatagram::from_std(socket).map_err(|e|e.to_string())
    })();
    let socket = match result { Ok(s)=>s, Err(e)=>{ eprintln!("pid2-command-watch: {e}"); return; } };
    let _ = LOCAL_WAKE.set(tx.clone());
    let mut buf = [0u8;16384];
    loop {
        match socket.recv(&mut buf).await {
            Ok(_)=>{let _=tx.tx.try_send(());},
            Err(_)=>break,
        }
    }
}
async fn watch_fd(make: fn()->Result<AsyncFd<OwnedFd>,String>, label: &'static str, tx: Wake, online: Arc<AtomicBool>) {
    // A missing history entry is unknown.  Clearing at the bound or on a
    // sense discontinuity cannot turn a potentially relevant event away.
    let mut history=HashMap::<(String,String),DeviceState>::new();
    loop {
        match make() {
            Ok(fd) => {
                online.store(true,Ordering::Release); sense(&tx,label);
                loop {
                    let mut ready = match fd.readable().await { Ok(ready)=>ready, Err(_)=>break };
                    let mut buf = [0u8; 16384];
                    let count = unsafe { libc::recv(fd.get_ref().as_raw_fd(),buf.as_mut_ptr().cast(),buf.len(),libc::MSG_TRUNC) };
                    if count > 0 {
                        if count as usize>buf.len() { history.clear(); sense(&tx,"udev"); }
                        else { match udev_change(&buf[..count as usize]) {
                            Ok(Some((subsystem,device,action)))=>{
                                let identity=(subsystem.clone(),device.clone());
                                let before=history.get(&identity).cloned().unwrap_or(DeviceState::Unknown);
                                let after=if action=="remove" {DeviceState::Absent} else {super::solver::event_device_facts(&subsystem,&device)};
                                if action=="remove" {history.remove(&identity);} else {
                                    if history.len()>=512 && !history.contains_key(&identity) {history.clear();}
                                    history.insert(identity,after.clone());
                                }
                                tx.push(DirtyKey::Device(subsystem,device,before,after));
                            },
                            Ok(None)=>{}, Err(())=>{history.clear();sense(&tx,"udev");},
                        }}
                    } else {
                        let err=std::io::Error::last_os_error();
                        if count<0 && err.raw_os_error()==Some(libc::ENOBUFS) { history.clear(); sense(&tx,"udev"); continue; }
                        if count == 0 || err.kind()!=std::io::ErrorKind::WouldBlock { break; }
                        ready.clear_ready();
                    }
                }
            }
            Err(error) => eprintln!("pid2-{label}-watch: {error}"),
        }
        history.clear(); online.store(false,Ordering::Release); tx.offline(label);
        if tx.closed() { return; }
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}
// The cache contains only mountpoint names, not the mountinfo body.  Its
// fixed byte bound prevents retaining an unbounded kernel snapshot.
fn mount_snapshot(file: &std::fs::File) -> Result<HashSet<PathBuf>,String> {
    let mut file=file;
    file.seek(SeekFrom::Start(0)).map_err(|e|format!("pid2-mountinfo-seek: {e}"))?;
    let mut content=String::new();
    std::io::Read::take(&mut file,16*1024*1024+1).read_to_string(&mut content).map_err(|e|format!("pid2-mountinfo-read: {e}"))?;
    if content.len()>16*1024*1024 { return Err("pid2-mountinfo-too-large".into()); }
    Ok(content.lines().filter_map(|line|line.split_whitespace().nth(4)).map(|path|PathBuf::from(path.replace("\\040"," ").replace("\\011","\t").replace("\\012","\n").replace("\\134","\\"))).collect())
}

async fn watch_mounts(tx: Wake, mounts: Arc<RwLock<Option<HashSet<PathBuf>>>>) {
    let watched = (|| -> Result<AsyncFd<std::fs::File>,String> {
        let file=std::fs::File::open("/proc/self/mountinfo").map_err(|e|e.to_string())?;
        AsyncFd::with_interest(file,Interest::PRIORITY).map_err(|e|e.to_string())
    })();
    let result: Result<(),String> = async {
        let fd=watched?;
        let initial=mount_snapshot(fd.get_ref())?;
        *mounts.write().map_err(|_|"pid2-mount-cache-lock-poisoned")?=Some(initial);
        sense(&tx,"mount");
        loop {
            let mut ready=fd.ready(Interest::PRIORITY).await.map_err(|e|e.to_string())?;
            let next=mount_snapshot(fd.get_ref())?;
            let watched=super::solver::watched_mounts()?;
            let changed={
                let mut cache=mounts.write().map_err(|_|"pid2-mount-cache-lock-poisoned")?;
                let changed:Vec<_>=watched.into_iter().filter(|path|cache.as_ref().is_none_or(|old|old.contains(path)!=next.contains(path))).collect();
                *cache=Some(next);
                changed
            };
            ready.clear_ready();
            tx.mount_event.send_replace(());
            for path in changed { tx.push(DirtyKey::Mount(path)); }
        }
    }.await;
    if let Ok(mut cache)=mounts.write() { *cache=None; }
    tx.offline("mount");
    if let Err(error)=result { eprintln!("pid2-mount-watch: {error}"); }
}

pub struct Senses { pub system: Arc<AtomicBool>, pub owner: Arc<AtomicBool>, pub udev: Arc<AtomicBool>, pub mounts: Arc<RwLock<Option<HashSet<PathBuf>>>>, pub(super) kernel: Arc<kernel_senses::Cache> }
impl Senses { pub fn online(&self, scope: &str) -> bool { match scope { "system"=>self.system.load(Ordering::Acquire), "owner"=>self.owner.load(Ordering::Acquire), "udev"=>self.udev.load(Ordering::Acquire), _=>false } } }

fn route_deadlines(tx:&Wake, fired:&mut HashSet<(String,String,i64,i64)>) -> Result<Option<Duration>,String> {
    let db=crate::stats::open_db()?.lock().map_err(|_|"pid2-database-lock-poisoned")?;
    super::tables(&db)?;
    let rows:HashSet<(String,String,i64,i64)>={
        let mut query=db.prepare("SELECT routine_id,line,step_index,deadline FROM pid2_route_steps WHERE deadline IS NOT NULL").map_err(|e|e.to_string())?;
        let rows=query.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).map_err(|e|e.to_string())?.collect::<Result<HashSet<_>,_>>().map_err(|e|e.to_string())?;
        rows
    };
    drop(db);
    fired.retain(|key|rows.contains(key));
    let observed_at=super::now();
    let mut next=None;
    for key in rows {
        if fired.contains(&key) {continue;}
        if key.3<=observed_at {
            tx.push(DirtyKey::Line(key.0.clone(),key.1.clone()));
            fired.insert(key);
        } else {next=Some(next.map_or(key.3,|old:i64|old.min(key.3)));}
    }
    let current=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    Ok(next.map(|second|Duration::from_secs(second.max(0) as u64).saturating_sub(current)))
}
pub async fn run() {
    if let Err(error)=super::schedule::wake_interrupted() {eprintln!("pid2-schedule-interrupted-wake: {error}");}
    if let Err(error)=refresh_units() {eprintln!("pid2-unit-watch-config: {error}");}
    let (channel,mut rx) = mpsc::channel::<()>(1);
    let (reconfigure,config_rx)=tokio::sync::watch::channel(());
    let (mount_event,mount_rx)=tokio::sync::watch::channel(());
    let tx=Wake{tx:channel,pending:Arc::new(Mutex::new(Pending::default())),offline:Arc::new(std::sync::atomic::AtomicU8::new(0)),reconfigure,mount_event};
    let senses = Arc::new(Senses { system:Arc::new(AtomicBool::new(false)),owner:Arc::new(AtomicBool::new(false)),udev:Arc::new(AtomicBool::new(false)),mounts:Arc::new(RwLock::new(None)),kernel:Arc::new(kernel_senses::Cache::default()) });
    let tasks = [
        tokio::spawn(kernel_senses::run(tx.clone(),senses.kernel.clone(),config_rx.clone(),mount_rx)),
        tokio::spawn(watch_mounts(tx.clone(),senses.mounts.clone())),
        tokio::spawn(watch_systemd(tx.clone(),senses.system.clone(),config_rx.clone())),
        tokio::spawn(watch_owner(tx.clone(),senses.owner.clone(),config_rx)),
        tokio::spawn(watch_fd(udev_socket,"udev",tx.clone(),senses.udev.clone())),
        tokio::spawn(watch_commands(tx.clone())),
    ];
    tx.push(DirtyKey::Startup);
    // The solver has its own coalesced worker: a slow walk never delays the clock.
    let (solver_tx,mut solver_rx)=mpsc::channel::<()>(1);
    let worker_senses=senses.clone();
    let worker_wake=tx.clone();
    let solver_task=tokio::spawn(async move {
        // A retained failed walk is not a new configuration event.  Track
        // durable wake IDs until acknowledgement so a failed reconcile cannot
        // feed its own reconfiguration back into the kernel watchers.
        let mut configured_durable=HashSet::new();
        while solver_rx.recv().await.is_some() {
            let senses=worker_senses.clone();
            // Preserve the in-memory dirty set if the durable observation fails.
            let durable=match pending_wakes() {Ok(rows)=>rows,Err(error)=>{eprintln!("pid2-command-wake-read-failed: {error}");continue;}};
            let mut keys=match worker_wake.pending.lock() {
                Ok(mut pending)=>{ worker_wake.offline.swap(0,Ordering::AcqRel); if pending.full { pending.full=false; pending.keys.clear(); vec![DirtyKey::All] } else { pending.keys.drain().collect() } },
                Err(_)=>vec![DirtyKey::All],
            };
            let local=keys.clone();
            keys.extend(durable.iter().map(|(_,key)|key.clone()));
            configured_durable.retain(|id|durable.iter().any(|(current,_)|current==id));
            let mut new_config=false;
            for (id,key) in &durable {
                if matches!(key,DirtyKey::Routine(_)|DirtyKey::All|DirtyKey::Startup) && configured_durable.insert(*id) {new_config=true;}
            }
            if new_config {worker_wake.reconfigure.send_replace(());}
            if keys.is_empty() { continue; }
            match tokio::task::spawn_blocking(move || super::solver::reconcile(&senses,keys)).await {
                Ok(Ok(()))=>{if let Err(error)=acknowledge_wakes(&durable) {eprintln!("pid2-command-wake-ack-failed: {error}");}},
                Ok(Err(e))=>{worker_wake.retain(local);eprintln!("pid2-reconcile-failed: {e}");},
                Err(e)=>{worker_wake.retain(local);eprintln!("pid2-reconcile-task-failed: {e}");},
            }
        }
    });
    let mut heartbeat = tokio::time::interval_at(tokio::time::Instant::now()+Duration::from_secs(300),Duration::from_secs(300));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut catchup=true;
    let fire_slots=Arc::new(tokio::sync::Semaphore::new(1));
    let mut fired_routes=HashSet::new();
    'events: loop {
        let mut delay=match super::schedule::clock(catchup) {Ok(delay)=>delay,Err(error)=>{eprintln!("pid2-schedule-clock: {error}");Duration::from_secs(300)}};
        match route_deadlines(&tx,&mut fired_routes) {Ok(Some(route_delay))=>delay=delay.min(route_delay),Ok(None)=>{},Err(error)=>eprintln!("pid2-route-deadline: {error}")}
        catchup=false;
        match super::schedule::queued() {
            Ok(ids)=>for id in ids {
                let Ok(permit)=fire_slots.clone().try_acquire_owned() else { break; };
                tokio::task::spawn_blocking(move || {let result=super::schedule::execute(&id);drop(permit);match result {Ok(true)=>{if let Err(error)=super::events::notify_schedule() {eprintln!("pid2-schedule-wake: {error}");}},Ok(false)=>{},Err(error)=>eprintln!("pid2-schedule-fire: {error}")}});
            },
            Err(error)=>eprintln!("pid2-schedule-queue: {error}"),
        }
        let clock_deadline=tokio::time::Instant::now()+delay;
        loop {
            tokio::select! {
                _=heartbeat.tick()=>{
                    // The heartbeat checks only our durable wake set, not the world.
                    let durable=match wakes_waiting() {Ok(changed)=>changed,Err(error)=>{eprintln!("pid2-command-wake-read-failed: {error}");false}};
                    let bits=tx.offline.load(Ordering::Acquire);
                    for (scope,bit) in [("system",1),("owner",2),("udev",4),("mount",8),("netns",16),("link",32),("file",64)] {
                        let is_offline=if scope=="mount" { senses.mounts.read().map_or(true,|m|m.is_none()) } else if matches!(scope,"netns"|"link"|"file") { false } else { !senses.online(scope) };
                        if bits&bit!=0 || is_offline { tx.push(DirtyKey::Offline(scope.to_owned())); }
                    }
                    for key in senses.kernel.offline_keys() {tx.push(key);}
                    if durable {break;}
                },
                _=tokio::time::sleep_until(clock_deadline)=>break,
                item=rx.recv()=>{
                    if item.is_none() {break 'events;}
                    break;
                }
            }
        }
        let _=solver_tx.try_send(());
    }
    solver_task.abort();
    for task in tasks { task.abort(); }
}
