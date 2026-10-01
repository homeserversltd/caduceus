use crate::shared::config as paths;
use chrono::Utc;
use serde_json::{json, Map, Value};
use std::ffi::CString;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::path::PathBuf;

pub fn root() -> PathBuf {
    std::env::var_os("CADUCEUS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn path(relative: &str) -> PathBuf {
    root().join(relative.trim_start_matches('/'))
}

pub fn read_public_file(relative: &str) -> Result<String, String> {
    let path = path(relative);
    fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))
}

pub fn read_public_profile_text() -> Result<String, String> {
    let mut errors = Vec::new();
    for candidate in [
        "etc/caduceus/profile.yaml",
        "etc/caduceus/profile.yml",
        "etc/caduceus/profile.json",
    ] {
        match read_public_file(candidate) {
            Ok(text) => return Ok(text),
            Err(err) => errors.push(err),
        }
    }
    Err(format!("caduceus-profile-missing: {}", errors.join("; ")))
}

pub fn read_public_profile_value() -> Result<serde_json::Value, String> {
    let text = read_public_profile_text()?;
    serde_yaml::from_str(&text).map_err(|err| format!("caduceus-profile-invalid: {err}"))
}

pub fn overlay_birth_profile_fields(value: &mut serde_json::Value) -> Result<(), String> {
    let text = read_public_file("etc/appliance/profile.json")
        .map_err(|err| format!("caduceus-birth-certificate-missing: {err}"))?;
    let birth: serde_json::Value = serde_json::from_str(&text)
        .map_err(|err| format!("caduceus-birth-certificate-invalid: {err}"))?;
    let profile = birth
        .get("profile")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "caduceus-birth-certificate-profile-missing".to_string())?
        .to_string();
    let object = value
        .as_object_mut()
        .ok_or_else(|| "caduceus-public-profile-invalid".to_string())?;
    for field in ["device", "profile", "mode"] {
        object.insert(
            field.to_string(),
            serde_json::Value::String(profile.clone()),
        );
    }
    Ok(())
}

pub fn public_profile_present() -> bool {
    read_public_profile_text().is_ok()
}

pub fn read_file_at(absolute: &str) -> Result<String, String> {
    fs::read_to_string(absolute).map_err(|err| format!("{absolute}: {err}"))
}

/// Household configuration documents are read-write for the service user and
/// the service group because the owner account is a member of that group by
/// ruling. This is asserted after every write, not delegated to the process
/// umask or directory defaults.
const OWNED_FILE_MODE: u32 = 0o660;
const CONFIG_TARGET_SYMLINK: &str = "caduceus-config-target-symlink";

#[derive(Debug, Clone)]
struct Resolved {
    /// Receipt-only metadata; it never selects a config path.
    profile: String,
    /// Device-logical path published on receipts; never includes CADUCEUS_ROOT.
    device_path: String,
    /// Root-joined path actually read and written.
    fs_path: PathBuf,
}

fn normalize(value: &str) -> Option<String> {
    match value.to_ascii_lowercase().as_str() {
        "homeserver" => Some("homeserver".to_string()),
        "homeconsole" => Some("homeconsole".to_string()),
        "tv" => Some("tv".to_string()),
        _ => Some("probe".to_string()),
    }
}

fn resolve() -> Result<Resolved, String> {
    let profile_file: Option<Value> =
        fs::read_to_string(paths::path("/etc/appliance/profile.json"))
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok());
    let profile = profile_file
        .as_ref()
        .and_then(|value| value.get("profile"))
        .and_then(Value::as_str)
        .and_then(normalize)
        .ok_or_else(|| {
            "caduceus-household-config-profile-unknown: /etc/appliance/profile.json".to_string()
        })?;
    let device_path = "/etc/appliance/config.json".to_string();
    Ok(Resolved {
        profile,
        fs_path: paths::path(&device_path),
        device_path,
    })
}

pub fn resolved_profile() -> Result<String, String> {
    resolve().map(|resolved| resolved.profile)
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

pub fn declared_bind() -> Result<SocketAddr, String> {
    let value =
        get_json("caduceus.bind").map_err(|error| format!("caduceus-bind-undeclared: {error}"))?;
    value["value"]
        .as_str()
        .and_then(|bind| bind.parse::<SocketAddr>().ok())
        .ok_or_else(|| {
            "caduceus-bind-undeclared: caduceus.bind must be a socket address string".to_string()
        })
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

fn remove_dotted(document: &mut Value, path: &str) -> Result<(), String> {
    validate_dotted(path)?;
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = document;
    for key in &parts[..parts.len() - 1] {
        let Some(next) = current
            .as_object_mut()
            .and_then(|object| object.get_mut(*key))
        else {
            return Ok(());
        };
        current = next;
    }
    if let Some(object) = current.as_object_mut() {
        object.remove(parts[parts.len() - 1]);
    }
    Ok(())
}

fn get_dotted<'a>(document: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.')
        .try_fold(document, |value, key| value.get(key))
}

/// A narrow rollback token for one dotted JSON set. It records only the old
/// leaf and ancestors absent when that set ran; rollback never replaces a
/// later whole-document snapshot.
pub(crate) struct JsonSetRollback {
    path: String,
    previous: Option<Value>,
    expected: Value,
    introduced_ancestors: Vec<String>,
}

fn json_set_rollback(
    document: &Value,
    path: &str,
    expected: &Value,
) -> Result<JsonSetRollback, String> {
    validate_dotted(path)?;
    if !document.is_object() {
        return Err("caduceus-household-config-path-invalid".to_string());
    }
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = Some(document);
    let mut introduced_ancestors = Vec::new();
    for (index, key) in parts[..parts.len() - 1].iter().enumerate() {
        let prefix = parts[..=index].join(".");
        match current.and_then(|value| value.get(*key)) {
            Some(value) if value.is_object() => current = Some(value),
            Some(_) => return Err("caduceus-household-config-path-invalid".to_string()),
            None => {
                introduced_ancestors.push(prefix);
                current = None;
            }
        }
    }
    Ok(JsonSetRollback {
        path: path.to_string(),
        previous: get_dotted(document, path).cloned(),
        expected: expected.clone(),
        introduced_ancestors,
    })
}

fn prune_empty_ancestors(document: &mut Value, ancestors: &[String]) -> Result<(), String> {
    for path in ancestors.iter().rev() {
        let is_empty_object = get_dotted(document, path)
            .and_then(Value::as_object)
            .is_some_and(Map::is_empty);
        if is_empty_object {
            remove_dotted(document, path)?;
        }
    }
    Ok(())
}

/// Atomically replace a Caduceus-owned file with a fully synced, owner-created
/// sibling. Callers validate and render before this boundary so a refusal never
/// changes the prior durable bytes.
pub fn atomic_write_owned(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    ensure_not_symlink_target(path)?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "state.json".to_string());
    let temporary = path.with_file_name(format!("{file_name}.tmp.{}", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)
        .map_err(|error| error.to_string())?;
    let config_path = paths::path("/etc/appliance/config.json");
    let is_household_config = path == config_path.as_path();
    let effective_mode = if is_household_config {
        OWNED_FILE_MODE
    } else {
        mode
    };
    let result = (|| -> Result<(), String> {
        if is_household_config && unsafe { libc::geteuid() } == 0 {
            let gid = caduceus_group_id()?;
            if unsafe { libc::fchown(file.as_raw_fd(), 0 as libc::uid_t, gid) } != 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
        }
        file.set_permissions(fs::Permissions::from_mode(effective_mode))
            .map_err(|error| error.to_string())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        ensure_not_symlink_target(path)?;
        fs::rename(&temporary, path).map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn ensure_not_symlink_target(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(CONFIG_TARGET_SYMLINK.to_string()),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn caduceus_group_id() -> Result<libc::gid_t, String> {
    let name = CString::new("caduceus").expect("static group name contains no NUL");
    let suggested_size = unsafe { libc::sysconf(libc::_SC_GETGR_R_SIZE_MAX) };
    let mut buffer_size = if suggested_size > 0 {
        suggested_size as usize
    } else {
        16 * 1024
    };
    loop {
        let mut buffer = vec![0u8; buffer_size];
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        let status = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut group,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status == libc::ERANGE {
            buffer_size = buffer_size
                .checked_mul(2)
                .ok_or_else(|| "caduceus-config-group-lookup-failed".to_string())?;
            continue;
        }
        if status != 0 {
            return Err(format!(
                "caduceus-config-group-lookup-failed: {}",
                std::io::Error::from_raw_os_error(status)
            ));
        }
        if result.is_null() {
            return Err("caduceus-config-group-missing".to_string());
        }
        return Ok(group.gr_gid);
    }
}

/// Shared with paired Xenia transactions. Acquire before reading either document;
/// callers must release it before network I/O and must not call mutate while held.
pub fn transaction_lock() -> Result<std::sync::MutexGuard<'static, ()>, String> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().map_err(|_| "caduceus-config-lock-poisoned".to_owned())
}

fn mutate(op: &str, target: &str, update: Value) -> Result<Value, String> {
    mutate_with_rollback(op, target, update, None, None)
}

fn mutate_with_rollback(
    op: &str,
    target: &str,
    update: Value,
    capture_rollback: Option<&mut Option<JsonSetRollback>>,
    restore: Option<JsonSetRollback>,
) -> Result<Value, String> {
    let _guard = transaction_lock()?;
    let resolved = resolve()?;
    ensure_not_symlink_target(&resolved.fs_path)?;
    if !resolved.fs_path.is_file() {
        return Err("caduceus-household-config-installed-path-missing".to_string());
    }
    let mut document = read_document(&resolved)?;
    let before = document.clone();
    if let Some(rollback) = restore.as_ref() {
        if get_dotted(&document, &rollback.path) != Some(&rollback.expected) {
            return Err("caduceus-household-config-rollback-conflict".to_string());
        }
    }
    if let Some(capture) = capture_rollback {
        if op != "set" {
            return Err("caduceus-household-config-rollback-set-required".to_string());
        }
        *capture = Some(json_set_rollback(&before, target, &update)?);
    }
    let keys_touched: Vec<String> = if let Some(rollback) = restore {
        if let Some(previous) = rollback.previous {
            set_dotted(&mut document, &rollback.path, previous)?;
        } else {
            remove_dotted(&mut document, &rollback.path)?;
            prune_empty_ancestors(&mut document, &rollback.introduced_ancestors)?;
        }
        vec![rollback.path]
    } else if op == "set" {
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
    let mut rendered = serde_json::to_vec_pretty(&document)
        .map_err(|_| "caduceus-household-config-render-failed".to_string())?;
    rendered.push(b'\n');
    atomic_write_owned(&resolved.fs_path, &rendered, OWNED_FILE_MODE).map_err(|error| {
        if error == CONFIG_TARGET_SYMLINK {
            error
        } else {
            "caduceus-household-config-write-failed".to_string()
        }
    })?;
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

pub(crate) fn set_json_with_rollback(
    path: &str,
    value: Value,
    rollback: &mut Option<JsonSetRollback>,
) -> Result<Value, String> {
    *rollback = None;
    mutate_with_rollback("set", path, value, Some(rollback), None)
}

pub(crate) fn restore_json_set(rollback: JsonSetRollback) -> Result<Value, String> {
    let path = rollback.path.clone();
    mutate_with_rollback("restore", &path, Value::Null, None, Some(rollback))
}

pub fn patch_json(merge: Value) -> Result<Value, String> {
    mutate("patch", "household-config", merge)
}
