//! Household config lever band: profile-resolved readback and guarded mutation of
//! the appliance household configuration document.
//!
//! All published JSON carries device-logical paths (`/etc/tv/config.json`); the
//! CADUCEUS_ROOT membrane is applied only at the filesystem boundary.

use crate::tools::config as paths;
use chrono::Utc;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone)]
struct Resolved {
    profile: String,
    /// Device-logical path published on receipts; never includes CADUCEUS_ROOT.
    device_path: String,
    /// Root-joined path actually read and written.
    fs_path: PathBuf,
    factory: Option<String>,
}

fn state() -> Option<Value> {
    fs::read_to_string(paths::path("var/lib/caduceus/state.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

fn identity() -> Option<Value> {
    fs::read_to_string(paths::path("etc/caduceus/identity.json"))
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
}

fn normalize(value: &str) -> Option<String> {
    let value = value.to_ascii_lowercase();
    ["homeserver", "console", "tv"]
        .iter()
        .find(|profile| value == **profile || value.contains(*profile))
        .map(|profile| (*profile).to_string())
}

fn resolve() -> Result<Resolved, String> {
    let state = state();
    let identity = identity();
    let profile_file = paths::read_public_profile_value().ok();
    let profile = state
        .as_ref()
        .and_then(|value| value.pointer("/services/household_config/profile"))
        .and_then(Value::as_str)
        .or_else(|| {
            state
                .as_ref()
                .and_then(|value| value.pointer("/services/profile"))
                .and_then(Value::as_str)
        })
        .and_then(normalize)
        .or_else(|| {
            identity
                .as_ref()
                .and_then(|value| {
                    value
                        .get("profile")
                        .or_else(|| value.get("mode"))
                        .or_else(|| value.get("device"))
                })
                .and_then(Value::as_str)
                .and_then(normalize)
        })
        .or_else(|| {
            profile_file
                .as_ref()
                .and_then(|value| value.get("profile").or_else(|| value.get("mode")))
                .and_then(Value::as_str)
                .and_then(normalize)
        })
        .ok_or_else(|| "caduceus-household-config-profile-unknown".to_string())?;
    let explicit = state
        .as_ref()
        .and_then(|value| value.pointer("/services/household_config/path"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let explicit_factory = state
        .as_ref()
        .and_then(|value| value.pointer("/services/household_config/factory"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let (candidates, factory_candidate) = match profile.as_str() {
        "homeserver" => (
            vec![
                "/etc/homeserver/config.json",
                "/etc/homeserver.json",
                "/var/www/homeserver/src/config/homeserver.json",
            ],
            "/etc/homeserver.factory",
        ),
        "console" => (
            vec!["/etc/console/config.json", "/etc/console.json"],
            "/etc/console.factory",
        ),
        "tv" => (
            vec!["/etc/tv/config.json", "/etc/tv.json"],
            "/etc/tv.factory",
        ),
        _ => unreachable!(),
    };
    let device_path = explicit.unwrap_or_else(|| {
        candidates
            .iter()
            .find(|candidate| paths::path(candidate).exists())
            .copied()
            .unwrap_or(candidates[0])
            .to_string()
    });
    let factory = explicit_factory.or_else(|| {
        paths::path(factory_candidate)
            .exists()
            .then(|| factory_candidate.to_string())
    });
    Ok(Resolved {
        profile,
        fs_path: paths::path(&device_path),
        device_path,
        factory,
    })
}

fn read_document(resolved: &Resolved) -> Result<Value, String> {
    let text = fs::read_to_string(&resolved.fs_path)
        .map_err(|_| "caduceus-household-config-missing".to_string())?;
    serde_json::from_str(&text).map_err(|_| "caduceus-household-config-invalid".to_string())
}

fn validate_dotted(path: &str) -> Result<(), String> {
    let invalid = path.trim().is_empty()
        || path.contains('/')
        || path.contains('\\')
        || path.contains("..")
        || path.split('.').any(|segment| segment.is_empty());
    if invalid {
        return Err("caduceus-household-config-path-invalid".to_string());
    }
    Ok(())
}

pub fn path_json() -> Result<Value, String> {
    let resolved = resolve()?;
    Ok(json!({
        "schema": "caduceus.household-config.path.v1",
        "ok": true,
        "profile": resolved.profile,
        "path": resolved.device_path,
        "factory": resolved.factory,
        "firstMissingSignal": "none",
    }))
}

pub fn show_json() -> Result<Value, String> {
    let resolved = resolve()?;
    let document = read_document(&resolved)?;
    Ok(json!({
        "schema": "caduceus.household-config.show.v1",
        "ok": true,
        "profile": resolved.profile,
        "path": resolved.device_path,
        "document": document,
    }))
}

pub fn get_json(path: &str) -> Result<Value, String> {
    validate_dotted(path)?;
    let resolved = resolve()?;
    let document = read_document(&resolved)?;
    let value = path
        .split('.')
        .try_fold(&document, |value, key| value.get(key))
        .cloned()
        .ok_or_else(|| "caduceus-household-config-key-missing".to_string())?;
    Ok(json!({
        "schema": "caduceus.household-config.get.v1",
        "ok": true,
        "profile": resolved.profile,
        "path": path,
        "value": value,
    }))
}

fn deep_merge(target: &mut Value, patch: Value) {
    match (target, patch) {
        (Value::Object(target), Value::Object(patch)) => {
            for (key, value) in patch {
                deep_merge(target.entry(key).or_insert(Value::Null), value);
            }
        }
        (target, patch) => *target = patch,
    }
}

fn set_dotted(document: &mut Value, path: &str, value: Value) -> Result<(), String> {
    validate_dotted(path)?;
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = document;
    for key in &parts[..parts.len() - 1] {
        if !current.is_object() {
            *current = Value::Object(Map::new());
        }
        current = current
            .as_object_mut()
            .unwrap()
            .entry(*key)
            .or_insert_with(|| Value::Object(Map::new()));
    }
    if !current.is_object() {
        *current = Value::Object(Map::new());
    }
    current
        .as_object_mut()
        .unwrap()
        .insert(parts[parts.len() - 1].to_string(), value);
    Ok(())
}

fn mutate(op: &str, target: &str, update: Value) -> Result<Value, String> {
    let resolved = resolve()?;
    let mut document = read_document(&resolved)?;
    let before = document.clone();
    let keys_touched: Vec<String> = if op == "set" {
        set_dotted(&mut document, target, update)?;
        vec![target.to_string()]
    } else {
        let Value::Object(ref merge) = update else {
            return Err("caduceus-household-config-patch-object-required".to_string());
        };
        let keys = merge.keys().cloned().collect();
        deep_merge(&mut document, update);
        keys
    };
    if document == before {
        return Ok(json!({
            "schema": "caduceus.household-config.mutation.v1",
            "ok": true,
            "profile": resolved.profile,
            "op": op,
            "path": resolved.device_path,
            "changed": false,
            "keysTouched": keys_touched,
            "firstMissingSignal": "none",
        }));
    }
    let stamp = Utc::now().format("%Y%m%dT%H%M%S%9fZ").to_string();
    let backup_device = format!(
        "/var/lib/caduceus/backups/household-config/{}-{stamp}.json",
        resolved.profile
    );
    let backup_fs = paths::path(&backup_device);
    if let Some(parent) = backup_fs.parent() {
        fs::create_dir_all(parent)
            .map_err(|_| "caduceus-household-config-backup-failed".to_string())?;
    }
    fs::copy(&resolved.fs_path, &backup_fs)
        .map_err(|_| "caduceus-household-config-backup-failed".to_string())?;
    let file_name = resolved
        .fs_path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "config.json".to_string());
    let tmp = resolved
        .fs_path
        .with_file_name(format!("{file_name}.tmp.{}", std::process::id()));
    let mut rendered = serde_json::to_vec_pretty(&document)
        .map_err(|_| "caduceus-household-config-render-failed".to_string())?;
    rendered.push(b'\n');
    let mut file =
        fs::File::create(&tmp).map_err(|_| "caduceus-household-config-write-failed".to_string())?;
    file.write_all(&rendered)
        .and_then(|()| file.sync_all())
        .map_err(|_| "caduceus-household-config-write-failed".to_string())?;
    drop(file);
    fs::rename(&tmp, &resolved.fs_path)
        .map_err(|_| "caduceus-household-config-write-failed".to_string())?;
    let receipt = json!({
        "schema": "caduceus.household-config.mutation.v1",
        "ok": true,
        "profile": resolved.profile,
        "op": op,
        "path": resolved.device_path,
        "backup": backup_device,
        "changed": true,
        "keysTouched": keys_touched,
        "readWritePaths": [resolved.device_path, backup_device],
        "firstMissingSignal": "none",
    });
    let receipt_device = format!("/var/lib/caduceus/receipts/household-config-{stamp}.json");
    let receipt_fs = paths::path(&receipt_device);
    if let Some(parent) = receipt_fs.parent() {
        fs::create_dir_all(parent)
            .map_err(|_| "caduceus-household-config-receipt-failed".to_string())?;
    }
    let rendered_receipt = serde_json::to_vec_pretty(&receipt)
        .map_err(|_| "caduceus-household-config-receipt-failed".to_string())?;
    fs::write(&receipt_fs, rendered_receipt)
        .map_err(|_| "caduceus-household-config-receipt-failed".to_string())?;
    Ok(receipt)
}

pub fn set_json(path: &str, value: Value) -> Result<Value, String> {
    mutate("set", path, value)
}

pub fn patch_json(merge: Value) -> Result<Value, String> {
    mutate("patch", "household-config", merge)
}
