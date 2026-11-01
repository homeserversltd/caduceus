//! In-process snapshot of systemd units observed by the subscribed managers.
use std::{collections::{HashMap, HashSet}, sync::{OnceLock, RwLock, atomic::{AtomicBool, Ordering}}};
use zbus::zvariant::OwnedObjectPath;

pub(crate) type UnitRow = (String, String, String, String, String, String, OwnedObjectPath, u32, String, OwnedObjectPath);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct UnitState {
    pub(crate) active_state: Option<String>,
    pub(crate) sub_state: Option<String>,
    pub(crate) load_state: Option<String>,
    pub(crate) unit_file_state: Option<String>,
}
impl UnitState {
    fn absent() -> Self {
        Self { active_state: Some("inactive".into()), sub_state: Some("dead".into()), load_state: Some("unloaded".into()), unit_file_state: None }
    }
}

static STATES: OnceLock<RwLock<HashMap<(String, String), UnitState>>> = OnceLock::new();
static SYSTEM_ONLINE: AtomicBool = AtomicBool::new(false);
static OWNER_ONLINE: AtomicBool = AtomicBool::new(false);
fn states() -> &'static RwLock<HashMap<(String, String), UnitState>> { STATES.get_or_init(|| RwLock::new(HashMap::new())) }

pub(crate) fn set_online(scope: &str, online: bool) {
    match scope { "system" => &SYSTEM_ONLINE, "owner" => &OWNER_ONLINE, _ => return }.store(online, Ordering::Release);
}

pub(crate) fn observed(scope: &str, unit: &str) -> Option<UnitState> {
    let online = match scope { "system" => &SYSTEM_ONLINE, "owner" => &OWNER_ONLINE, _ => return None };
    if !online.load(Ordering::Acquire) { return None; }
    let state = get(scope, unit)?;
    if !online.load(Ordering::Acquire) { return None; }
    if state.active_state.is_none() || state.sub_state.is_none() || state.load_state.is_none() { return None; }
    Some(state)
}

pub(crate) fn get(scope: &str, unit: &str) -> Option<UnitState> {
    states().read().ok()?.get(&(scope.to_owned(), unit.to_owned())).cloned()
}

pub(crate) fn set(scope: &str, unit: &str, state: UnitState) -> bool {
    let Ok(mut stored) = states().write() else { return false; };
    let key = (scope.to_owned(), unit.to_owned());
    if stored.get(&key) == Some(&state) { return false; }
    stored.insert(key, state);
    true
}

// A manager snapshot is limited to the caller's explicitly watched names.
pub(crate) fn snapshot(scope: &str, watched: &HashSet<String>, rows: Vec<UnitRow>) -> Vec<String> {
    let mut next: HashMap<String, UnitState> = watched.iter().map(|unit| (unit.clone(), UnitState::absent())).collect();
    for (name, _, load, active, sub, _, _, _, _, _) in rows {
        if let Some(state) = next.get_mut(&name) {
            state.active_state = Some(active);
            state.sub_state = Some(sub);
            state.load_state = Some(load);
        }
    }
    let Ok(mut stored) = states().write() else { return Vec::new(); };
    let mut changed = Vec::new();
    for (unit, mut state) in next {
        let key = (scope.to_owned(), unit.clone());
        if let Some(old) = stored.get(&key) { state.unit_file_state = old.unit_file_state.clone(); }
        if stored.get(&key) != Some(&state) { changed.push(unit); stored.insert(key, state); }
    }
    changed
}

pub(crate) fn update(scope: &str, unit: &str, active: Option<Option<String>>, sub: Option<Option<String>>, load: Option<Option<String>>) -> bool {
    let Ok(mut stored) = states().write() else { return false; };
    let Some(state) = stored.get_mut(&(scope.to_owned(), unit.to_owned())) else { return false; };
    let old = state.clone();
    if let Some(value) = active { state.active_state = value; }
    if let Some(value) = sub { state.sub_state = value; }
    if let Some(value) = load { state.load_state = value; }
    *state != old
}

// Statistics has its own connection, lifetime, and key space.  Its availability
// must never invalidate or overwrite the system scope used by the sequencer.
static STATS_ONLINE: AtomicBool = AtomicBool::new(false);

pub(crate) fn stats_online(online: bool) {
    STATS_ONLINE.store(online, Ordering::Release);
}

pub(crate) fn stats_is_online() -> bool {
    STATS_ONLINE.load(Ordering::Acquire)
}

pub(crate) fn stats_observed(unit: &str) -> Option<UnitState> {
    if !STATS_ONLINE.load(Ordering::Acquire) { return None; }
    let state = get("stats", unit)?;
    if !STATS_ONLINE.load(Ordering::Acquire) { return None; }
    if state.active_state.is_none() || state.sub_state.is_none() || state.load_state.is_none() { return None; }
    Some(state)
}

// Discard departed names; the statistics cache is bounded by its watched set.
pub(crate) fn stats_retain(watched: &HashSet<String>) {
    if let Ok(mut stored) = states().write() {
        stored.retain(|(scope, unit), _| scope != "stats" || watched.contains(unit));
    }
}

pub(crate) fn stats_file_state(unit: &str, state: Option<String>, not_found: bool) {
    if let Ok(mut stored) = states().write() {
        if let Some(row) = stored.get_mut(&("stats".to_owned(), unit.to_owned())) {
            row.unit_file_state = state;
            if not_found { row.load_state = Some("not-found".into()); }
            else if row.load_state.as_deref() == Some("not-found") { row.load_state = Some("unloaded".into()); }
        }
    }
}
