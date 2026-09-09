use super::{observation, seat, Refusal, Result, XENIA};
use crate::shared::config;
use serde_json::{json, Value};
use std::fs;
use std::io::ErrorKind;

pub const CONFIG: &str = "/etc/appliance/config.json";
pub const REGISTER: &str = "/etc/appliance/xenia.json";

#[derive(Clone)]
pub struct House {
    pub config: Value,
    pub register: Value,
}

/// Caller owns config::transaction_lock for the entire pair's observation.
pub fn read() -> Result<House> {
    let bytes =
        fs::read(config::path(CONFIG)).map_err(|e| observation("A", CONFIG, e.to_string()))?;
    let config: Value =
        serde_json::from_slice(&bytes).map_err(|e| observation("A", CONFIG, e.to_string()))?;
    if !config.get("tabs").is_some_and(Value::is_object) {
        return Err(Refusal::new(
            "A",
            "config.tabs",
            "house-unsound: tabs is not an object",
            "Restore a JSON config with a tabs object.",
        ));
    }
    let register = match fs::read(config::path(REGISTER)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| observation("A", REGISTER, format!("register-json-invalid: {e}")))?,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            json!({"schema": XENIA, "xenoi": {}, "written_at": 0})
        }
        Err(error) => return Err(observation("A", REGISTER, error.to_string())),
    };
    seat::form(XENIA, Some("register"), &register, "A", "register")?;
    let xenoi = register["xenoi"]
        .as_object()
        .ok_or_else(|| observation("A", "register.xenoi", "register-map-invalid"))?;
    for (id, entry) in xenoi {
        seat::field(
            XENIA,
            "id",
            &json!(id),
            "A",
            &format!("register.xenoi.{id}"),
        )?;
        if entry["id"].as_str() != Some(id) {
            return Err(observation(
                "A",
                &format!("register.xenoi.{id}.id"),
                "register-identity-mismatch",
            ));
        }
    }
    Ok(House { config, register })
}

pub fn snapshot() -> Result<House> {
    let _lock = config::transaction_lock().map_err(|e| observation("A", "config.lock", e))?;
    read()
}

pub fn same_declaration(existing: &Value, proposed: &Value) -> bool {
    let mut existing = existing.clone();
    let mut proposed = proposed.clone();
    for value in [&mut existing, &mut proposed] {
        if let Some(object) = value.as_object_mut() {
            object.remove("installed");
            object.remove("discovered");
        }
    }
    existing == proposed
}

fn write(path: &str, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| observation("transaction", path, e.to_string()))?;
    bytes.push(b'\n');
    config::atomic_write_owned(&config::path(path), &bytes, 0o660)
        .map_err(|e| observation("transaction", path, e))
}

/// Called after network validation, under the same process-wide config lock.
/// A changed snapshot is refused rather than validating new bytes using stale
/// remote evidence. Repeating the call observes and validates the new world.
pub fn admit(before: &House, proposed: &Value, row: &Value) -> Result<Value> {
    let _lock =
        config::transaction_lock().map_err(|e| observation("transaction", "config.lock", e))?;
    let mut current = read()?;
    if current.config != before.config || current.register != before.register {
        return Err(observation(
            "transaction",
            "house",
            "house-changed-during-validation: repeat against current bytes",
        ));
    }
    let id = proposed["id"]
        .as_str()
        .ok_or_else(|| observation("transaction", "entry.id", "entry-id-absent"))?;
    let prior = current.register["xenoi"].get(id);
    let entry = match prior {
        Some(existing) if same_declaration(existing, proposed) => existing.clone(),
        Some(_) => {
            return Err(Refusal::new(
                "D",
                "entry.id",
                "owned-entry-differs",
                "Remove the existing guest before replacing its declaration.",
            ))
        }
        None => proposed.clone(),
    };
    let entry_changed = prior.is_none();
    let row_changed = current.config["tabs"].get(id) != Some(row);
    if entry_changed {
        current.register["xenoi"]
            .as_object_mut()
            .unwrap()
            .insert(id.into(), entry.clone());
        current.register["written_at"] = json!(chrono::Utc::now().timestamp());
        write(REGISTER, &current.register)?;
    }
    // Entry rename precedes row rename. If this fails, the existing entry is
    // deliberately retained; an identical repeat repairs just the missing row.
    if row_changed {
        current.config["tabs"]
            .as_object_mut()
            .unwrap()
            .insert(id.into(), row.clone());
        write(CONFIG, &current.config)?;
    }
    Ok(
        json!({"entry": entry, "tabs": row, "changed": entry_changed || row_changed,
        "attempt": {"entry": if entry_changed {"renamed"} else {"unchanged"}, "row": if row_changed {"renamed"} else {"unchanged"}},
        "final": {"entry_present": true, "row_present": true, "converged": true}}),
    )
}

pub fn observe(id: &str, field: &str, snapshot: &Value) -> Result<Value> {
    let _lock =
        config::transaction_lock().map_err(|e| observation("transaction", "config.lock", e))?;
    let mut current = read()?;
    if current.register["xenoi"].get(id).is_none() {
        return Err(Refusal::new(
            "C",
            "id",
            "entry-absent",
            "Admit the guest before writing an observation.",
        ));
    }
    let row = current.config["tabs"].get(id).cloned().ok_or_else(|| {
        observation(
            "transaction",
            &format!("config.tabs.{id}"),
            "tabs-row-absent",
        )
    })?;
    let entry = current.register["xenoi"]
        .as_object_mut()
        .and_then(|xenoi| xenoi.get_mut(id))
        .ok_or_else(|| observation("transaction", "register.xenoi", "register-map-invalid"))?;
    let previous = entry.get(field).cloned();
    entry
        .as_object_mut()
        .ok_or_else(|| observation("transaction", "entry", "entry-object-invalid"))?
        .insert(field.into(), snapshot.clone());
    seat::form(XENIA, Some("entry"), entry, "observe", "entry")?;
    let entry = entry.clone();
    let written_at = chrono::Utc::now().timestamp();
    current.register["written_at"] = json!(written_at);
    write(REGISTER, &current.register)?;
    Ok(json!({
        "entry": entry,
        "tabs": row,
        "changed": previous.as_ref() != Some(snapshot),
        "attempt": {"snapshot": "replaced", "written_at": "moved"},
        "final": {"entry_present": true, "snapshot": field, "written_at": written_at, "converged": true}
    }))
}

pub fn remove(id: &str) -> Result<Value> {
    seat::field(XENIA, "id", &json!(id), "C", "id")?;
    let _lock =
        config::transaction_lock().map_err(|e| observation("transaction", "config.lock", e))?;
    let mut current = read()?;
    let Some(entry) = current.register["xenoi"].get(id).cloned() else {
        // A native row is never removed on the strength of its id alone.
        return Ok(
            json!({"changed": false, "final": {"entry_present": false, "native_row_preserved": true, "converged": true}}),
        );
    };
    let row_changed = current.config["tabs"]
        .as_object_mut()
        .unwrap()
        .remove(id)
        .is_some();
    if row_changed {
        write(CONFIG, &current.config)?;
    }
    // The config row is durably absent before removing ownership from register.
    current.register["xenoi"]
        .as_object_mut()
        .unwrap()
        .remove(id);
    current.register["written_at"] = json!(chrono::Utc::now().timestamp());
    write(REGISTER, &current.register)?;
    Ok(json!({"entry": entry, "changed": true,
        "attempt": {"row": if row_changed {"removed"} else {"already-absent"}, "entry": "removed"},
        "final": {"entry_present": false, "row_present": false, "converged": true}}))
}
