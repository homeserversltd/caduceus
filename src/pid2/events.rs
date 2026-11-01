//! Coalesced event wakes; observations are always re-read by the solver.
use futures_util::{FutureExt, StreamExt};
use std::{collections::{HashMap, HashSet, VecDeque}, ffi::CString, io::{Read, Seek, SeekFrom, Write}, os::fd::{AsRawFd, FromRawFd, OwnedFd}, path::PathBuf, sync::{Arc, Mutex, OnceLock, RwLock, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::{io::{unix::AsyncFd, AsyncBufReadExt, AsyncReadExt, BufReader, Interest}, sync::mpsc};
use zbus::{Connection, Message, MatchRule, MessageStream, Proxy, message::Type, zvariant::{OwnedObjectPath, OwnedValue}};

#[derive(Clone,Debug,Eq,Hash,PartialEq,serde::Serialize,serde::Deserialize)]
pub(super) enum DirtyKey {
    All, Startup, Unit(String,String), Job(String,String), Sense(String), Mount(PathBuf), Device(String,String),
    Routine(String), Line(String,String), Schedule, Offline(String), Unavailable(String),
}
#[derive(Default)]
struct Pending { keys:HashSet<DirtyKey>, full:bool }
#[derive(Clone)]
struct Wake { tx:mpsc::Sender<()>, pending:Arc<Mutex<Pending>>, offline:Arc<std::sync::atomic::AtomicU8> }
impl Wake {
    fn push(&self,key:DirtyKey) {
        if let Ok(mut pending)=self.pending.lock() {
            if !pending.full {
                if key==DirtyKey::All { pending.full=true; pending.keys.clear(); }
                else if pending.keys.len()>=512 { pending.full=true; pending.keys.clear(); super::solver::deed("dirty-overflow","pid2","full-walk",None); }
                else { pending.keys.insert(key); }
            }
        }
        let _=self.tx.try_send(());
    }
    fn offline(&self,scope:&str) {
        let bit=match scope {"system"=>1,"owner"=>2,"udev"=>4,"mount"=>8,_=>0};
        if let Ok(mut pending)=self.pending.lock() {
            self.offline.fetch_or(bit,Ordering::AcqRel);
            if !pending.full {
                if pending.keys.len()>=512 { pending.full=true; pending.keys.clear(); super::solver::deed("dirty-overflow","pid2","full-walk",None); }
                else { pending.keys.insert(DirtyKey::Unavailable(scope.to_owned())); }
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
// Declared units, by name and by bus path, read once from the routine seat.
fn declared() -> &'static (HashSet<String>, HashSet<String>) {
    static DECLARED: OnceLock<(HashSet<String>, HashSet<String>)> = OnceLock::new();
    DECLARED.get_or_init(|| {
        let names: HashSet<String> = crate::routes::leaf_schema::declaration(super::SCHEMA).and_then(|seat| seat.get("unit_enum")).and_then(|v| v.as_array())
            .map(|units| units.iter().filter_map(|u| u.get("unit").and_then(|v| v.as_str()).map(str::to_owned)).collect()).unwrap_or_default();
        let paths = names.iter().map(|unit| unit_path(unit)).collect();
        (names, paths)
    })
}
fn scoped_units(scope: &str) -> HashSet<String> {
    crate::routes::leaf_schema::declaration(super::SCHEMA).and_then(|seat| seat.get("unit_enum")).and_then(|v| v.as_array())
        .map(|units| units.iter().filter(|u| u.get("scope").and_then(|v| v.as_str()) == Some(scope))
            .filter_map(|u| u.get("unit").and_then(|v| v.as_str()).map(str::to_owned)).collect()).unwrap_or_default()
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
                Some(Ok(message)) if message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(&message) => {
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
fn concerns_declared(message: &Message) -> bool {
    let header = message.header();
    let (names, paths) = declared();
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
                    Some(Ok(message)) if message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(&message) => {
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
                Some(Some(Ok(message))) if message.recv_position()>barrier && message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(&message) => {
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

async fn watch_systemd(tx: Wake, online: Arc<AtomicBool>) {
    loop {
        let connected: Result<(),String> = async {
            let conn = Connection::system().await.map_err(|e|e.to_string())?;
            let (mut events,manager_owner) = streams(&conn,"system").await?;
            let mut pending=VecDeque::new();
            let mut barrier = settled_scope(&conn,"system",&mut events,&manager_owner,&mut pending).await?;
            crate::stats::indicators::unit_state::set_online("system",true);
            online.store(true,Ordering::Release); sense(&tx,"system");
            loop {
                let item = if let Some(message)=pending.pop_front() { Some(Ok(message)) } else { events.next().await };
                match item {
                    Some(Ok(message)) if manager_owner_changed(&message) => return Err("pid2-systemd-owner-changed".into()),
                    Some(Ok(message)) if message.recv_position()>barrier && message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(&message) => {
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
        crate::stats::indicators::unit_state::set_online("system",false);
        online.store(false,Ordering::Release); tx.offline("system");
        if let Err(error)=connected { eprintln!("pid2-system-systemd-watch: {error}"); }
        if tx.closed() { return; }
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
            Some(Ok(message)) if message.recv_position()>barrier && message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(&message) => {
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

async fn watch_owner(tx: Wake, online: Arc<AtomicBool>) {
    loop {
        let connected = async {
            let executable=std::env::current_exe().map_err(|e|e.to_string())?;
            let uid=owner_uid()?;
            let mut command=if unsafe { libc::geteuid() } == 0 {
                let mut c=tokio::process::Command::new("runuser"); c.arg("-u").arg("owner").arg("--").arg(executable); c
            } else if unsafe { libc::geteuid() } == uid {
                tokio::process::Command::new(executable)
            } else { return Err("pid2-owner-sense-wrong-uid".into()); };
            command.arg("pid2-owner-sense").stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).kill_on_drop(true);
            let mut child=command.spawn().map_err(|e|e.to_string())?;
            let stdout=child.stdout.take().ok_or("pid2-owner-child-pipe-missing")?;
            let mut lines=BufReader::new(stdout);
            loop {
                let mut bytes=Vec::new();
                let count=(&mut lines).take(4097).read_until(b'\n',&mut bytes).await.map_err(|e|e.to_string())?;
                if count==0 { break; }
                if count>4096 || bytes.last()!=Some(&b'\n') { return Err("pid2-owner-child-line-too-long".into()); }
                bytes.pop();
                let line=String::from_utf8(bytes).map_err(|_|"pid2-owner-child-protocol-invalid")?;
                match line.as_str() {
                    "syncing" if online.load(Ordering::Acquire) => { crate::stats::indicators::unit_state::set_online("owner",false); online.store(false,Ordering::Release); tx.offline("owner"); },
                    "ready" => { crate::stats::indicators::unit_state::set_online("owner",true); online.store(true,Ordering::Release); eprintln!("pid2-owner-sense-online"); sense(&tx,"owner"); },
                    "job" if online.load(Ordering::Acquire) => { sense(&tx,"owner"); },
                    _ => {
                        let frame: serde_json::Value = serde_json::from_str(&line).map_err(|_|"pid2-owner-child-protocol-invalid")?;
                        let unit = frame.get("unit").and_then(|v|v.as_str()).ok_or("pid2-owner-child-unit-missing")?;
                        if !scoped_units("owner").contains(unit) { return Err("pid2-owner-child-unit-undeclared".into()); }
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
        crate::stats::indicators::unit_state::set_online("owner",false);
        online.store(false,Ordering::Release); tx.offline("owner");
        // This identity cannot become root or owner within this process.  Do
        // not let unrelated systemd activity re-arm a permanently failed sense.
        let wrong_uid=matches!(&connected, Err(error) if error=="pid2-owner-sense-wrong-uid");
        if let Err(error)=connected { eprintln!("pid2-owner-systemd-watch: {error}"); }
        if wrong_uid { return; }
        if tx.closed() { return; }
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

fn udev_change(data: &[u8]) -> Result<Option<(String,String)>,()> {
    // Group 2 carries a libudev monitor header, followed by its property block.
    if data.len()<40 || &data[..8]!=b"libudev\0" || &data[8..12]!=[0xfe,0xed,0xca,0xfe] { return Err(()); }
    let word=|offset:usize| u32::from_ne_bytes(data[offset..offset+4].try_into().unwrap()) as usize;
    let header=word(12); let offset=word(16); let length=word(20);
    if header<40 || offset<header || offset.checked_add(length).is_none_or(|end|end>data.len()) { return Err(()); }
    let mut subsystem=None; let mut device=None; let mut action=None;
    for field in data[offset..offset+length].split(|byte|*byte==0).filter(|field|!field.is_empty()) {
        let value=std::str::from_utf8(field).map_err(|_|())?;
        let (key,value)=value.split_once('=').ok_or(())?;
        match key { "SUBSYSTEM"=>subsystem=Some(value), "DEVPATH"=>device=Some(value), "ACTION"=>action=Some(value), _=>{} }
    }
    let subsystem=subsystem.ok_or(())?;
    if subsystem!="block" && subsystem!="drm" { return Ok(None); }
    let device=device.filter(|v|v.starts_with('/') && v.len()<=4096).ok_or(())?;
    if action.is_none() { return Err(()); }
    Ok(Some((subsystem.to_owned(),device.to_owned())))
}

fn wake_address() -> Result<std::os::unix::net::SocketAddr, String> {
    use std::{hash::{Hash,Hasher},os::linux::net::SocketAddrExt};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    crate::stats::db_path().hash(&mut hasher);
    std::os::unix::net::SocketAddr::from_abstract_name(format!("caduceus-pid2-{:016x}",hasher.finish())).map_err(|e|e.to_string())
}
static LOCAL_WAKE: OnceLock<Wake> = OnceLock::new();
fn notify_key(key:DirtyKey) {
    if let Some(local)=LOCAL_WAKE.get() { local.push(key); }
    else if let (Ok(addr),Ok(socket),Ok(bytes))=(wake_address(),std::os::unix::net::UnixDatagram::unbound(),serde_json::to_vec(&key)) {
        if let Err(error)=socket.send_to_addr(&bytes,&addr) { eprintln!("pid2-command-wake-undelivered: {error}"); }
    }
}
pub fn notify() { notify_key(DirtyKey::All); }
pub(super) fn notify_routine(id:&str) { notify_key(DirtyKey::Routine(id.to_owned())); }
pub(super) fn notify_line(id:&str,line:&str) { notify_key(DirtyKey::Line(id.to_owned(),line.to_owned())); }
pub(super) fn notify_unit(scope:&str,name:&str) { notify_key(DirtyKey::Unit(scope.to_owned(),name.to_owned())); }
pub(super) fn notify_schedule() { notify_key(DirtyKey::Schedule); }
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
            Ok(n)=>tx.push(serde_json::from_slice(&buf[..n]).unwrap_or(DirtyKey::All)),
            Err(_)=>break,
        }
    }
}
async fn watch_fd(make: fn()->Result<AsyncFd<OwnedFd>,String>, label: &'static str, tx: Wake, online: Arc<AtomicBool>) {
    loop {
        match make() {
            Ok(fd) => {
                online.store(true,Ordering::Release); sense(&tx,label);
                loop {
                    let mut ready = match fd.readable().await { Ok(ready)=>ready, Err(_)=>break };
                    let mut buf = [0u8; 16384];
                    let count = unsafe { libc::recv(fd.get_ref().as_raw_fd(),buf.as_mut_ptr().cast(),buf.len(),libc::MSG_TRUNC) };
                    if count > 0 {
                        if count as usize>buf.len() { sense(&tx,"udev"); }
                        else { match udev_change(&buf[..count as usize]) {
                            Ok(Some((subsystem,device)))=>tx.push(DirtyKey::Device(subsystem,device)),
                            Ok(None)=>{}, Err(())=>sense(&tx,"udev"),
                        }}
                    } else {
                        let err=std::io::Error::last_os_error();
                        if count<0 && err.raw_os_error()==Some(libc::ENOBUFS) { sense(&tx,"udev"); continue; }
                        if count == 0 || err.kind()!=std::io::ErrorKind::WouldBlock { break; }
                        ready.clear_ready();
                    }
                }
            }
            Err(error) => eprintln!("pid2-{label}-watch: {error}"),
        }
        online.store(false,Ordering::Release); tx.offline(label);
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
            for path in changed { tx.push(DirtyKey::Mount(path)); }
        }
    }.await;
    if let Ok(mut cache)=mounts.write() { *cache=None; }
    tx.offline("mount");
    if let Err(error)=result { eprintln!("pid2-mount-watch: {error}"); }
}

pub struct Senses { pub system: Arc<AtomicBool>, pub owner: Arc<AtomicBool>, pub udev: Arc<AtomicBool>, pub mounts: Arc<RwLock<Option<HashSet<PathBuf>>>> }
impl Senses { pub fn online(&self, scope: &str) -> bool { match scope { "system"=>self.system.load(Ordering::Acquire), "owner"=>self.owner.load(Ordering::Acquire), "udev"=>self.udev.load(Ordering::Acquire), _=>false } } }
pub async fn run() {
    let (channel,mut rx) = mpsc::channel::<()>(1);
    let tx=Wake{tx:channel,pending:Arc::new(Mutex::new(Pending::default())),offline:Arc::new(std::sync::atomic::AtomicU8::new(0))};
    let senses = Arc::new(Senses { system:Arc::new(AtomicBool::new(false)),owner:Arc::new(AtomicBool::new(false)),udev:Arc::new(AtomicBool::new(false)),mounts:Arc::new(RwLock::new(None)) });
    let tasks = [
        tokio::spawn(watch_mounts(tx.clone(),senses.mounts.clone())),
        tokio::spawn(watch_systemd(tx.clone(),senses.system.clone())),
        tokio::spawn(watch_owner(tx.clone(),senses.owner.clone())),
        tokio::spawn(watch_fd(udev_socket,"udev",tx.clone(),senses.udev.clone())),
        tokio::spawn(watch_commands(tx.clone())),
    ];
    tx.push(DirtyKey::Startup);
    // The solver has its own coalesced worker: a slow walk never delays the clock.
    let (solver_tx,mut solver_rx)=mpsc::channel::<()>(1);
    let worker_senses=senses.clone();
    let worker_wake=tx.clone();
    let solver_task=tokio::spawn(async move {
        while solver_rx.recv().await.is_some() {
            let senses=worker_senses.clone();
            let keys=match worker_wake.pending.lock() {
                Ok(mut pending)=>{ worker_wake.offline.swap(0,Ordering::AcqRel); if pending.full { pending.full=false; pending.keys.clear(); vec![DirtyKey::All] } else { pending.keys.drain().collect() } },
                Err(_)=>vec![DirtyKey::All],
            };
            if keys.is_empty() { continue; }
            match tokio::task::spawn_blocking(move || super::solver::reconcile(&senses,keys)).await {
                Ok(Ok(()))=>{}, Ok(Err(e))=>eprintln!("pid2-reconcile-failed: {e}"), Err(e)=>eprintln!("pid2-reconcile-task-failed: {e}"),
            }
        }
    });
    let mut heartbeat = tokio::time::interval_at(tokio::time::Instant::now()+Duration::from_secs(300),Duration::from_secs(300));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut catchup=true;
    let fire_slots=Arc::new(tokio::sync::Semaphore::new(1));
    'events: loop {
        let delay=match super::schedule::clock(catchup) {Ok(delay)=>delay,Err(error)=>{eprintln!("pid2-schedule-clock: {error}");Duration::from_secs(300)}};
        catchup=false;
        match super::schedule::queued() {
            Ok(ids)=>for id in ids {
                let Ok(permit)=fire_slots.clone().try_acquire_owned() else { break; };
                tokio::task::spawn_blocking(move || {let result=super::schedule::execute(&id);drop(permit);match result {Ok(true)=>super::events::notify_schedule(),Ok(false)=>{},Err(error)=>eprintln!("pid2-schedule-fire: {error}")}});
            },
            Err(error)=>eprintln!("pid2-schedule-queue: {error}"),
        }
        let clock_deadline=tokio::time::Instant::now()+delay;
        loop {
            tokio::select! {
                _=heartbeat.tick()=>{
                    // The existing solver heartbeat must not poll schedule rows.
                    let bits=tx.offline.load(Ordering::Acquire);
                    for (scope,bit) in [("system",1),("owner",2),("udev",4),("mount",8)] {
                        let is_offline=if scope=="mount" { senses.mounts.read().map_or(true,|m|m.is_none()) } else { !senses.online(scope) };
                        if bits&bit!=0 || is_offline { tx.push(DirtyKey::Offline(scope.to_owned())); }
                    }
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
