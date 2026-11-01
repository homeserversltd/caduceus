//! Independent, bounded systemd subscription for the services indicator.
use super::unit_state;
use futures_util::{FutureExt, StreamExt};
use std::{collections::{BTreeSet, HashMap, HashSet, VecDeque}, sync::OnceLock};
use tokio::sync::watch;
use zbus::{Connection, MatchRule, Message, MessageStream, Proxy, message::Type, zvariant::{OwnedObjectPath, OwnedValue}};

type Units = BTreeSet<String>;
static WATCH: OnceLock<watch::Sender<Units>> = OnceLock::new();

pub(super) fn configure(units: Units) {
    let sender = WATCH.get_or_init(|| {
        let (tx, rx) = watch::channel(Units::new());
        let spawn = std::thread::Builder::new().name("caduceus-stats-unit-watch".into()).spawn(move || {
            if let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() {
                runtime.block_on(run(rx));
            }
        });
        if spawn.is_err() { unit_state::stats_online(false); }
        tx
    });
    // Retrying a disconnected subscriber uses the already-existing sample wake;
    // it introduces no new clock or periodic bus read while online.
    if *sender.borrow() != units || !unit_state::stats_is_online() {
        unit_state::stats_online(false);
        sender.send_replace(units);
    }
}

fn unit_path(unit: &str) -> String {
    let label: String = unit.bytes().map(|b| if b.is_ascii_alphanumeric() { (b as char).to_string() } else { format!("_{b:02x}") }).collect();
    format!("/org/freedesktop/systemd1/unit/{label}")
}

async fn run(mut desired: watch::Receiver<Units>) {
    loop {
        let names = desired.borrow_and_update().clone();
        unit_state::stats_online(false);
        if names.is_empty() {
            unit_state::stats_retain(&HashSet::new());
            if desired.changed().await.is_err() { return; }
            continue;
        }
        let configuration_changed = tokio::select! {
            _ = subscribe(names) => false,
            changed = desired.changed() => { if changed.is_err() { return; } true },
        };
        unit_state::stats_online(false);
        // When a connection fails, wait for the sampling worker to request a
        // retry, or for an actual configuration change. Never busy-loop.
        if !configuration_changed && !desired.has_changed().unwrap_or(false) && desired.changed().await.is_err() { return; }
    }
}

fn owner_changed(message: &Message) -> bool {
    let h = message.header();
    h.sender().is_some_and(|v| v.as_str() == "org.freedesktop.DBus") &&
    h.interface().is_some_and(|v| v.as_str() == "org.freedesktop.DBus") &&
    h.member().is_some_and(|v| v.as_str() == "NameOwnerChanged") &&
    message.body().deserialize::<(String,String,String)>().is_ok_and(|(name,_,_)| name == "org.freedesktop.systemd1")
}

fn relevant(message: &Message, owner: &str, paths: &HashMap<String,String>, names: &HashSet<String>) -> bool {
    if !message.header().sender().is_some_and(|s| s.as_str() == owner) { return false; }
    match message.header().member().map(|m| m.as_str()) {
        Some("PropertiesChanged") => message.header().path().is_some_and(|p| paths.contains_key(p.as_str())) &&
            message.body().deserialize::<(String,HashMap<String,OwnedValue>,Vec<String>)>().is_ok_and(|(interface, changed, invalid)| {
                interface == "org.freedesktop.systemd1.Unit" && ["ActiveState", "SubState"].iter().any(|key| changed.contains_key(*key) || invalid.iter().any(|value| value == key))
            }),
        Some("UnitNew" | "UnitRemoved") => message.body().deserialize::<(String,OwnedObjectPath)>().is_ok_and(|(name,_)| names.contains(&name)),
        Some("Reloading" | "UnitFilesChanged") => true,
        _ => false,
    }
}

// Drain the bounded stream while a manager call is outstanding, preserving
// receive order and refusing overflow rather than silently losing state.
#[derive(Debug)]
enum CallError { Bus(zbus::Error), Stream(String) }
async fn call(conn: &Connection, events: &mut MessageStream, pending: &mut VecDeque<Message>, owner: &str, paths: &HashMap<String,String>, names: &HashSet<String>, member: &str, unit: Option<&str>) -> Result<Message,CallError> {
    let request = async {
        if let Some(unit) = unit {
            conn.call_method(Some("org.freedesktop.systemd1"), "/org/freedesktop/systemd1", Some("org.freedesktop.systemd1.Manager"), member, &(unit,)).await
        } else {
            conn.call_method(Some("org.freedesktop.systemd1"), "/org/freedesktop/systemd1", Some("org.freedesktop.systemd1.Manager"), member, &()).await
        }
    };
    tokio::pin!(request);
    loop {
        tokio::select! {
            biased;
            result = &mut request => return result.map_err(CallError::Bus),
            item = events.next() => match item {
                Some(Ok(message)) if owner_changed(&message) => return Err(CallError::Stream("systemd-owner-changed".into())),
                Some(Ok(message)) if relevant(&message,owner,paths,names) => {
                    if pending.len() >= 1024 { return Err(CallError::Stream("stats-unit-signal-overflow".into())); }
                    pending.push_back(message);
                },
                Some(Ok(_)) => {},
                Some(Err(e)) => return Err(CallError::Stream(e.to_string())),
                None => return Err(CallError::Stream("stats-unit-stream-closed".into())),
            }
        }
    }
}

async fn subscribe(units: Units) -> Result<(),String> {
    let names: HashSet<String> = units.into_iter().collect();
    let paths: HashMap<String,String> = names.iter().map(|name| (unit_path(name),name.clone())).collect();
    let conn = Connection::system().await.map_err(|e|e.to_string())?;
    let mut events = MessageStream::from(&conn);
    events.set_max_queued(1024);
    let bus = Proxy::new(&conn,"org.freedesktop.DBus","/org/freedesktop/DBus","org.freedesktop.DBus").await.map_err(|e|e.to_string())?;
    let rule = MatchRule::builder().msg_type(Type::Signal).sender("org.freedesktop.DBus").map_err(|e|e.to_string())?.path("/org/freedesktop/DBus").map_err(|e|e.to_string())?.interface("org.freedesktop.DBus").map_err(|e|e.to_string())?.member("NameOwnerChanged").map_err(|e|e.to_string())?.add_arg("org.freedesktop.systemd1").map_err(|e|e.to_string())?.build();
    let _: () = bus.call("AddMatch", &(rule.to_string(),)).await.map_err(|e|e.to_string())?;
    let owner: String = bus.call("GetNameOwner", &("org.freedesktop.systemd1",)).await.map_err(|e|e.to_string())?;
    for member in ["UnitNew", "UnitRemoved", "Reloading", "UnitFilesChanged"] {
        let rule = MatchRule::builder().msg_type(Type::Signal).sender("org.freedesktop.systemd1").map_err(|e|e.to_string())?.path("/org/freedesktop/systemd1").map_err(|e|e.to_string())?.interface("org.freedesktop.systemd1.Manager").map_err(|e|e.to_string())?.member(member).map_err(|e|e.to_string())?.build();
        let _: () = bus.call("AddMatch", &(rule.to_string(),)).await.map_err(|e|e.to_string())?;
    }
    for path in paths.keys() {
        let rule = MatchRule::builder().msg_type(Type::Signal).sender("org.freedesktop.systemd1").map_err(|e|e.to_string())?.path(path.as_str()).map_err(|e|e.to_string())?.interface("org.freedesktop.DBus.Properties").map_err(|e|e.to_string())?.member("PropertiesChanged").map_err(|e|e.to_string())?.build();
        let _: () = bus.call("AddMatch", &(rule.to_string(),)).await.map_err(|e|e.to_string())?;
    }
    let manager = Proxy::new(&conn,"org.freedesktop.systemd1","/org/freedesktop/systemd1","org.freedesktop.systemd1.Manager").await.map_err(|e|e.to_string())?;
    let _: () = manager.call("Subscribe", &()).await.map_err(|e|e.to_string())?;
    unit_state::stats_retain(&names);
    let mut pending = VecDeque::new();
    let mut resnapshot = true;
    let mut refiles = true;
    loop {
        if resnapshot {
            unit_state::stats_online(false);
            let reply = call(&conn,&mut events,&mut pending,&owner,&paths,&names,"ListUnits",None).await.map_err(|e|format!("{e:?}"))?;
            let position = reply.recv_position();
            let rows: Vec<unit_state::UnitRow> = reply.body().deserialize().map_err(|e|e.to_string())?;
            unit_state::snapshot("stats",&names,rows);
            pending.retain(|message| message.recv_position() > position || message.header().member().is_some_and(|m| m.as_str() == "UnitFilesChanged"));
            resnapshot = false;
        }
        if refiles {
            unit_state::stats_online(false);
            for name in &names {
                match call(&conn,&mut events,&mut pending,&owner,&paths,&names,"GetUnitFileState",Some(name)).await {
                    Ok(reply) => {
                        let state: String = reply.body().deserialize().map_err(|e|e.to_string())?;
                        unit_state::stats_file_state(name,Some(state),false);
                    },
                    Err(CallError::Bus(zbus::Error::MethodError(error,_,_))) if error.as_str() == "org.freedesktop.systemd1.NoSuchUnit" || error.as_str() == "org.freedesktop.DBus.Error.FileNotFound" => unit_state::stats_file_state(name,None,true),
                    Err(error) => return Err(format!("{error:?}")),
                }
            }
            refiles = false;
        }
        let item = if let Some(message) = pending.pop_front() {
            Some(Ok(message))
        } else if let Some(ready) = events.next().now_or_never() {
            ready
        } else {
            unit_state::stats_online(true);
            events.next().await
        };
        let message = match item { Some(Ok(m)) => m, Some(Err(e)) => return Err(e.to_string()), None => return Err("stats-unit-stream-closed".into()) };
        if owner_changed(&message) { return Err("systemd-owner-changed".into()); }
        if !relevant(&message,&owner,&paths,&names) { continue; }
        match message.header().member().map(|m| m.as_str()) {
            Some("Reloading") => {
                let (active,): (bool,) = message.body().deserialize().map_err(|e|e.to_string())?;
                if !active { resnapshot = true; refiles = true; }
            },
            Some("UnitFilesChanged") => refiles = true,
            Some("UnitNew" | "UnitRemoved") => {
                let removed = message.header().member().is_some_and(|m|m.as_str()=="UnitRemoved");
                let (unit,_): (String,OwnedObjectPath) = message.body().deserialize().map_err(|e|e.to_string())?;
                if removed { unit_state::update("stats",&unit,Some(Some("inactive".into())),Some(Some("dead".into())),Some(Some("unloaded".into()))); }
                else { unit_state::update("stats",&unit,None,None,Some(Some("loaded".into()))); }
            },
            Some("PropertiesChanged") => {
                let unit = paths.get(message.header().path().ok_or("stats-unit-path-missing")?.as_str()).ok_or("stats-unit-not-watched")?;
                let (_,mut changed,invalid): (String,HashMap<String,OwnedValue>,Vec<String>) = message.body().deserialize().map_err(|e|e.to_string())?;
                if invalid.iter().any(|v| v == "ActiveState" || v == "SubState") { resnapshot = true; continue; }
                let active = changed.remove("ActiveState").map(|v| String::try_from(v).map(Some).map_err(|e|e.to_string())).transpose()?;
                let sub = changed.remove("SubState").map(|v| String::try_from(v).map(Some).map_err(|e|e.to_string())).transpose()?;
                unit_state::update("stats",unit,active,sub,None);
            },
            _ => {},
        }
    }
}
