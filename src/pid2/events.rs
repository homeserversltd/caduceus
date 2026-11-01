//! Coalesced event wakes; observations are always re-read by the solver.
use futures_util::StreamExt;
use std::{collections::{HashMap, HashSet, VecDeque}, ffi::CString, io::Write, os::fd::{AsRawFd, FromRawFd, OwnedFd}, sync::{Arc, OnceLock, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::{io::{unix::AsyncFd, AsyncBufReadExt, AsyncReadExt, BufReader}, sync::{mpsc, Notify}};
use zbus::{Connection, Message, MatchRule, MessageStream, Proxy, message::Type, zvariant::{OwnedObjectPath, OwnedValue}};

type Wake = mpsc::Sender<()>;
fn wake(tx: &Wake) { let _ = tx.try_send(()); }

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
    pending.retain(|message|message.recv_position()>reply.recv_position());
    Ok((!crate::stats::indicators::unit_state::snapshot(scope, &scoped_units(scope), rows).is_empty(),reply.recv_position()))
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
            Ok(unit_state::update(scope, &unit, active, sub, None))
        },
        Some("UnitRemoved") => {
            let (unit, _): (String, OwnedObjectPath) = message.body().deserialize().map_err(|e| e.to_string())?;
            Ok(unit_state::update(scope, &unit, Some(Some("inactive".into())), Some(Some("dead".into())), Some(Some("unloaded".into()))))
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
            let (_,mut barrier) = snapshot_scope(&conn,"system",&mut events,&manager_owner,&mut pending).await?;
            crate::stats::indicators::unit_state::set_online("system",true);
            online.store(true,Ordering::Release); wake(&tx);
            loop {
                let item = if let Some(message)=pending.pop_front() { Some(Ok(message)) } else { events.next().await };
                match item {
                    Some(Ok(message)) if manager_owner_changed(&message) => return Err("pid2-systemd-owner-changed".into()),
                    Some(Ok(message)) if message.recv_position()>barrier && message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(&message) => {
                        let reloading = message.header().member().is_some_and(|m| m.as_str()=="Reloading");
                        let changed = if reloading { let (changed,position)=snapshot_scope(&conn,"system",&mut events,&manager_owner,&mut pending).await?; barrier=position; changed } else {
                            match update_scope("system",&message) {
                                Ok(changed) => changed,
                                Err(error) if error=="pid2-unit-state-invalidated" => { let (changed,position)=snapshot_scope(&conn,"system",&mut events,&manager_owner,&mut pending).await?; barrier=position; changed },
                                Err(error) => { eprintln!("pid2-system-signal: {error}"); false }
                            }
                        };
                        if changed { wake(&tx); }
                    },
                    Some(Ok(_)) => {},
                    Some(Err(e)) => return Err(e.to_string()), None => return Err("pid2-systemd-stream-closed".into())
                }
            }
        }.await;
        crate::stats::indicators::unit_state::set_online("system",false);
        online.store(false,Ordering::Release); wake(&tx);
        if let Err(error)=connected { eprintln!("pid2-system-systemd-watch: {error}"); }
        if tx.is_closed() { return; }
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
    let (_,mut barrier)=snapshot_scope(&conn,"owner",&mut events,&manager_owner,&mut pending).await?;
    emit_owner_states()?;
    writeln!(std::io::stdout(),"ready").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?;
    loop {
        let item=if let Some(message)=pending.pop_front() { Some(Ok(message)) } else { events.next().await };
        match item {
            Some(Ok(message)) if manager_owner_changed(&message) => return Err("pid2-systemd-owner-changed".into()),
            Some(Ok(message)) if message.recv_position()>barrier && message.header().sender().is_some_and(|s|s.as_str()==manager_owner) && concerns_declared(&message) => {
                let reloading = message.header().member().is_some_and(|m| m.as_str()=="Reloading");
                let job = message.header().member().is_some_and(|m| m.as_str()=="JobRemoved");
                let changed = if reloading { let (changed,position)=snapshot_scope(&conn,"owner",&mut events,&manager_owner,&mut pending).await?; barrier=position; changed } else {
                    match update_scope("owner",&message) {
                        Ok(changed) => changed,
                        Err(error) if error=="pid2-unit-state-invalidated" => { let (changed,position)=snapshot_scope(&conn,"owner",&mut events,&manager_owner,&mut pending).await?; barrier=position; changed },
                        Err(error) if error=="pid2-unit-not-watched" => false,
                        Err(error) => return Err(error),
                    }
                };
                if changed { emit_owner_states()?; }
                if changed && job { writeln!(std::io::stdout(),"job").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?; }
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
                    "ready" => { crate::stats::indicators::unit_state::set_online("owner",true); online.store(true,Ordering::Release); eprintln!("pid2-owner-sense-online"); wake(&tx); },
                    "job" if online.load(Ordering::Acquire) => { wake(&tx); },
                    _ => {
                        let frame: serde_json::Value = serde_json::from_str(&line).map_err(|_|"pid2-owner-child-protocol-invalid")?;
                        if frame.get("kind").and_then(|v|v.as_str()) != Some("state") { return Err("pid2-owner-child-protocol-invalid".into()); }
                        let unit = frame.get("unit").and_then(|v|v.as_str()).ok_or("pid2-owner-child-unit-missing")?;
                        if !scoped_units("owner").contains(unit) { return Err("pid2-owner-child-unit-undeclared".into()); }
                        let state: crate::stats::indicators::unit_state::UnitState = serde_json::from_value(frame.get("state").cloned().ok_or("pid2-owner-child-state-missing")?).map_err(|e|e.to_string())?;
                        if crate::stats::indicators::unit_state::set("owner",unit,state) {
                            if online.load(Ordering::Acquire) { wake(&tx); }
                        }
                    },
                }
            }
            let _=child.wait().await;
            Err::<(),String>("pid2-owner-child-exited".into())
        }.await;
        crate::stats::indicators::unit_state::set_online("owner",false);
        online.store(false,Ordering::Release); wake(&tx);
        // This identity cannot become root or owner within this process.  Do
        // not let unrelated systemd activity re-arm a permanently failed sense.
        let wrong_uid=matches!(&connected, Err(error) if error=="pid2-owner-sense-wrong-uid");
        if let Err(error)=connected { eprintln!("pid2-owner-systemd-watch: {error}"); }
        if wrong_uid { return; }
        if tx.is_closed() { return; }
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

fn relevant_udev(data: &[u8]) -> bool {
    let mut subsystem = false;
    let mut action = false;
    for field in data.split(|byte| *byte == 0) {
        if matches!(field, b"SUBSYSTEM=block" | b"SUBSYSTEM=drm") { subsystem = true; }
        if matches!(field, b"ACTION=add" | b"ACTION=remove" | b"ACTION=change") { action = true; }
    }
    subsystem && action
}

fn wake_address() -> Result<std::os::unix::net::SocketAddr, String> {
    use std::{hash::{Hash,Hasher},os::linux::net::SocketAddrExt};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    crate::stats::db_path().hash(&mut hasher);
    std::os::unix::net::SocketAddr::from_abstract_name(format!("caduceus-pid2-{:016x}",hasher.finish())).map_err(|e|e.to_string())
}
static LOCAL_WAKE: OnceLock<Notify> = OnceLock::new();
pub fn notify() {
    if let Some(local) = LOCAL_WAKE.get() { local.notify_one(); }
    else if let (Ok(addr),Ok(socket)) = (wake_address(),std::os::unix::net::UnixDatagram::unbound()) { let _ = socket.send_to_addr(&[1],&addr); }
}
async fn watch_commands(tx: Wake, command_wake: Arc<AtomicBool>) {
    let result = (|| -> Result<tokio::net::UnixDatagram,String> {
        let addr = wake_address()?;
        let socket = std::os::unix::net::UnixDatagram::bind_addr(&addr).map_err(|e|e.to_string())?;
        socket.set_nonblocking(true).map_err(|e|e.to_string())?;
        tokio::net::UnixDatagram::from_std(socket).map_err(|e|e.to_string())
    })();
    let socket = match result { Ok(s)=>s, Err(e)=>{ eprintln!("pid2-command-watch: {e}"); return; } };
    let local = LOCAL_WAKE.get_or_init(Notify::new);
    wake(&tx);
    let mut buf = [0u8;1];
    loop {
        tokio::select! {
            result = socket.recv(&mut buf) => if result.is_err() { break; },
            _ = local.notified() => {},
        }
        command_wake.store(true,Ordering::Release); wake(&tx);
    }
}
async fn watch_fd(make: fn()->Result<AsyncFd<OwnedFd>,String>, label: &'static str, tx: Wake, online: Arc<AtomicBool>) {
    loop {
        match make() {
            Ok(fd) => {
                online.store(true,Ordering::Release); wake(&tx);
                loop {
                    let mut ready = match fd.readable().await { Ok(ready)=>ready, Err(_)=>break };
                    let mut buf = [0u8; 16384];
                    let count = unsafe { libc::read(fd.get_ref().as_raw_fd(),buf.as_mut_ptr().cast(),buf.len()) };
                    if count > 0 { if relevant_udev(&buf[..count as usize]) { wake(&tx); } } else {
                        let err=std::io::Error::last_os_error();
                        if count == 0 || err.kind()!=std::io::ErrorKind::WouldBlock { break; }
                        ready.clear_ready();
                    }
                }
            }
            Err(error) => eprintln!("pid2-{label}-watch: {error}"),
        }
        online.store(false,Ordering::Release); wake(&tx);
        if tx.is_closed() { return; }
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}
pub struct Senses { pub system: Arc<AtomicBool>, pub owner: Arc<AtomicBool>, pub udev: Arc<AtomicBool> }
impl Senses { pub fn online(&self, scope: &str) -> bool { match scope { "system"=>self.system.load(Ordering::Acquire), "owner"=>self.owner.load(Ordering::Acquire), "udev"=>self.udev.load(Ordering::Acquire), _=>false } } }
pub async fn run() {
    let (tx,mut rx) = mpsc::channel::<()>(1);
    let command_wake=Arc::new(AtomicBool::new(false));
    let senses = Arc::new(Senses { system:Arc::new(AtomicBool::new(false)),owner:Arc::new(AtomicBool::new(false)),udev:Arc::new(AtomicBool::new(false)) });
    let tasks = [
        tokio::spawn(watch_systemd(tx.clone(),senses.system.clone())),
        tokio::spawn(watch_owner(tx.clone(),senses.owner.clone())),
        tokio::spawn(watch_fd(udev_socket,"udev",tx.clone(),senses.udev.clone())),
        tokio::spawn(watch_commands(tx.clone(),command_wake.clone())),
    ];
    wake(&tx);
    // The solver has its own coalesced worker: a slow walk never delays the clock.
    let (solver_tx,mut solver_rx)=mpsc::channel::<()>(1);
    let solver_command=Arc::new(AtomicBool::new(false));
    let solver_heartbeat=Arc::new(AtomicBool::new(false));
    let worker_senses=senses.clone();
    let worker_command=solver_command.clone();
    let worker_heartbeat=solver_heartbeat.clone();
    let solver_task=tokio::spawn(async move {
        while solver_rx.recv().await.is_some() {
            let senses=worker_senses.clone();
            let command=worker_command.swap(false,Ordering::AcqRel);
            let heartbeat=worker_heartbeat.swap(false,Ordering::AcqRel);
            match tokio::task::spawn_blocking(move || super::solver::reconcile(&senses,command,heartbeat)).await {
                Ok(Ok(()))=>{}, Ok(Err(e))=>eprintln!("pid2-reconcile-failed: {e}"), Err(e)=>eprintln!("pid2-reconcile-task-failed: {e}"),
            }
        }
    });
    let mut heartbeat = tokio::time::interval_at(tokio::time::Instant::now()+Duration::from_secs(300),Duration::from_secs(300));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut catchup=true;
    let fire_slots=Arc::new(tokio::sync::Semaphore::new(16));
    'events: loop {
        let delay=match super::schedule::clock(catchup) {Ok(delay)=>delay,Err(error)=>{eprintln!("pid2-schedule-clock: {error}");Duration::from_secs(300)}};
        catchup=false;
        match super::schedule::queued() {
            Ok(ids)=>for id in ids {
                let Ok(permit)=fire_slots.clone().try_acquire_owned() else { break; };
                tokio::task::spawn_blocking(move || {let _permit=permit; if let Err(error)=super::schedule::execute(&id) {eprintln!("pid2-schedule-fire: {error}");}});
            },
            Err(error)=>eprintln!("pid2-schedule-queue: {error}"),
        }
        let clock_deadline=tokio::time::Instant::now()+delay;
        loop {
            tokio::select! {
                _=heartbeat.tick()=>{
                    // The existing solver heartbeat must not poll schedule rows.
                    solver_heartbeat.store(true,Ordering::Release);
                    let _=solver_tx.try_send(());
                },
                _=tokio::time::sleep_until(clock_deadline)=>break,
                item=rx.recv()=>{
                    if item.is_none() {break 'events;}
                    break;
                }
            }
        }
        if command_wake.swap(false,Ordering::AcqRel) {solver_command.store(true,Ordering::Release);}
        let _=solver_tx.try_send(());
    }
    solver_task.abort();
    for task in tasks { task.abort(); }
}
