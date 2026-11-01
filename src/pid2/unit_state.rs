//! In-process snapshot of systemd units observed by the subscribed managers.
use std::{collections::{HashMap, HashSet}, sync::{OnceLock, RwLock}};
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
fn states() -> &'static RwLock<HashMap<(String, String), UnitState>> { STATES.get_or_init(|| RwLock::new(HashMap::new())) }

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
