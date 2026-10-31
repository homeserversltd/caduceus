//! Coalesced event wakes; observations are always re-read by the solver.
use futures_util::StreamExt;
use std::{ffi::CString, io::Write, os::fd::{AsRawFd, FromRawFd, OwnedFd}, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration};
use tokio::{io::{unix::AsyncFd, AsyncBufReadExt, BufReader}, sync::{mpsc, Notify}};
use zbus::{Connection, MatchRule, MessageStream, Proxy, message::Type};

type Wake = mpsc::Sender<()>;
fn wake(tx: &Wake) { let _ = tx.try_send(()); }

fn owner_uid() -> Result<u32, String> {
    let name = CString::new("owner").map_err(|e| e.to_string())?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buf = [0u8; 16384];
    let status = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr().cast(), buf.len(), &mut result) };
    if status != 0 || result.is_null() { return Err("pid2-owner-account-unavailable".into()); }
    Ok(pwd.pw_uid)
}

async fn streams(conn: &Connection) -> Result<(MessageStream,MessageStream),String> {
    let proxy = Proxy::new(conn,"org.freedesktop.systemd1","/org/freedesktop/systemd1","org.freedesktop.systemd1.Manager").await.map_err(|e|e.to_string())?;
    let managers = MatchRule::builder().msg_type(Type::Signal).sender("org.freedesktop.systemd1").map_err(|e|e.to_string())?.path("/org/freedesktop/systemd1").map_err(|e|e.to_string())?.interface("org.freedesktop.systemd1.Manager").map_err(|e|e.to_string())?.build();
    let changes = MatchRule::builder().msg_type(Type::Signal).sender("org.freedesktop.systemd1").map_err(|e|e.to_string())?.path_namespace("/org/freedesktop/systemd1").map_err(|e|e.to_string())?.interface("org.freedesktop.DBus.Properties").map_err(|e|e.to_string())?.member("PropertiesChanged").map_err(|e|e.to_string())?.build();
    let manager_stream = MessageStream::for_match_rule(managers,conn,Some(64)).await.map_err(|e|e.to_string())?;
    let changed_stream = MessageStream::for_match_rule(changes,conn,Some(64)).await.map_err(|e|e.to_string())?;
    let _: () = proxy.call("Subscribe", &()).await.map_err(|e|e.to_string())?;
    Ok((manager_stream,changed_stream))
}

async fn watch_systemd(tx: Wake, online: Arc<AtomicBool>, owner_changed: Arc<Notify>) {
    loop {
        let connected: Result<(),String> = async {
            let conn = Connection::system().await.map_err(|e|e.to_string())?;
            let (mut managers,mut changes) = streams(&conn).await?;
            online.store(true,Ordering::Release); wake(&tx); owner_changed.notify_one();
            loop {
                let item = tokio::select! { item=managers.next()=>item, item=changes.next()=>item };
                match item { Some(Ok(_)) => { wake(&tx); owner_changed.notify_one(); }, Some(Err(e)) => return Err(e.to_string()), None => return Err("pid2-systemd-stream-closed".into()) }
            }
        }.await;
        online.store(false,Ordering::Release); wake(&tx);
        if let Err(error)=connected { eprintln!("pid2-system-systemd-watch: {error}"); }
        if tx.is_closed() { return; }
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}

// The owner child has no database and only relays bus subscription events.
async fn owner_child() -> Result<(),String> {
    let uid=owner_uid()?;
    if unsafe { libc::geteuid() } != uid { return Err("pid2-owner-child-wrong-uid".into()); }
    let address=format!("unix:path=/run/user/{uid}/bus");
    let conn=zbus::connection::Builder::address(address.as_str()).map_err(|e|e.to_string())?.build().await.map_err(|e|e.to_string())?;
    let (mut managers,mut changes)=streams(&conn).await?;
    writeln!(std::io::stdout(),"ready").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?;
    loop {
        let item=tokio::select! { item=managers.next()=>item, item=changes.next()=>item };
        match item {
            Some(Ok(_)) => { writeln!(std::io::stdout(),"wake").and_then(|_|std::io::stdout().flush()).map_err(|e|e.to_string())?; },
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

async fn watch_owner(tx: Wake, online: Arc<AtomicBool>, changed: Arc<Notify>) {
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
            let mut lines=BufReader::new(stdout).lines();
            while let Some(line)=lines.next_line().await.map_err(|e|e.to_string())? {
                match line.as_str() {
                    "ready" => { online.store(true,Ordering::Release); eprintln!("pid2-owner-sense-online"); wake(&tx); },
                    "wake" if online.load(Ordering::Acquire) => { wake(&tx); },
                    _ => return Err("pid2-owner-child-protocol-invalid".into()),
                }
            }
            let _=child.wait().await;
            Err::<(),String>("pid2-owner-child-exited".into())
        }.await;
        online.store(false,Ordering::Release); wake(&tx);
        // This identity cannot become root or owner within this process.  Do
        // not let unrelated systemd activity re-arm a permanently failed sense.
        let wrong_uid=matches!(&connected, Err(error) if error=="pid2-owner-sense-wrong-uid");
        if let Err(error)=connected { eprintln!("pid2-owner-systemd-watch: {error}"); }
        if wrong_uid { return; }
        if tx.is_closed() { return; }
        tokio::select! { _=tokio::time::sleep(Duration::from_secs(300))=>{}, _=changed.notified()=>{} }
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

fn wake_address() -> Result<std::os::unix::net::SocketAddr, String> {
    use std::{hash::{Hash,Hasher},os::linux::net::SocketAddrExt};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    crate::stats::db_path().hash(&mut hasher);
    std::os::unix::net::SocketAddr::from_abstract_name(format!("caduceus-pid2-{:016x}",hasher.finish())).map_err(|e|e.to_string())
}
pub fn notify() {
    if let (Ok(addr),Ok(socket)) = (wake_address(),std::os::unix::net::UnixDatagram::unbound()) { let _ = socket.send_to_addr(&[1],&addr); }
}
async fn watch_commands(tx: Wake, command_wake: Arc<AtomicBool>) {
    let result = (|| -> Result<tokio::net::UnixDatagram,String> {
        let addr = wake_address()?;
        let socket = std::os::unix::net::UnixDatagram::bind_addr(&addr).map_err(|e|e.to_string())?;
        socket.set_nonblocking(true).map_err(|e|e.to_string())?;
        tokio::net::UnixDatagram::from_std(socket).map_err(|e|e.to_string())
    })();
    let socket = match result { Ok(s)=>s, Err(e)=>{ eprintln!("pid2-command-watch: {e}"); return; } };
    wake(&tx);
    let mut buf = [0u8;1];
    while socket.recv(&mut buf).await.is_ok() { command_wake.store(true,Ordering::Release); wake(&tx); }
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
                    if count > 0 { wake(&tx); } else {
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
    let owner_changed=Arc::new(Notify::new());
    let tasks = [
        tokio::spawn(watch_systemd(tx.clone(),senses.system.clone(),owner_changed.clone())),
        tokio::spawn(watch_owner(tx.clone(),senses.owner.clone(),owner_changed)),
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
