use crate::shared::config;
use serde_json::{json, Value};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

const APPLIANCE_CONFIG: &str = "/etc/appliance/config.json";
const POLICY_RECEIPT_SCHEMA: &str = "caduceus.vault.policy-write.v1";
const CONFIG_MUTATION_SCHEMA: &str = "caduceus.household-config.mutation.v1";
const AUTO_UNLOCK_CONFIG_PATH: &str = "global.mounts.vault.auto_unlock";
const HOUSEHOLD_CONFIG_PATH: &str = "/etc/appliance/config.json";
const GOVERNING_KEYFILE: &str = "/root/key/homeconsole-vault.key";
const VAULT_OPEN_KEY_ABSENT_SIGNAL: &str = "agathodaimon-vault-open-key-absent";
const VAULT_OPEN_UNLOCK_REFUSED_SIGNAL: &str = "agathodaimon-vault-unlock-refused";
const VAULT_OPEN_MOUNTPOINT_REFUSED_SIGNAL: &str = "agathodaimon-vault-mountpoint-refused";
const VAULT_OPEN_MOUNT_REFUSED_SIGNAL: &str = "agathodaimon-vault-mount-refused";
const VAULT_DEVICE_UNRESOLVABLE_SIGNAL: &str = "vault-device-unresolvable";

#[derive(Clone)]
struct VaultConfig {
    mapper: String,
    mountpoint: String,
    device: String,
    keyfile: String,
    auto_unlock: Option<bool>,
}

fn root_path(path: &str) -> PathBuf {
    config::path(path)
}
fn logical(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn valid_partlabel(label: &str) -> bool {
    !label.is_empty() && label != "." && label != ".." && !label.contains('/')
}

fn resolve_device(device: &str) -> Result<String, String> {
    const PARTLABEL_PREFIX: &str = "/dev/disk/by-partlabel/";

    let logical_input = if let Some(label) = device.strip_prefix(PARTLABEL_PREFIX) {
        if !valid_partlabel(label) {
            return Err(VAULT_DEVICE_UNRESOLVABLE_SIGNAL.to_string());
        }
        device.to_string()
    } else if device.starts_with("/dev/") {
        device.to_string()
    } else if device.starts_with('/') || !valid_partlabel(device) {
        return Err(VAULT_DEVICE_UNRESOLVABLE_SIGNAL.to_string());
    } else {
        format!("{PARTLABEL_PREFIX}{device}")
    };

    let physical_path = fs::canonicalize(root_path(&logical_input))
        .map_err(|_| VAULT_DEVICE_UNRESOLVABLE_SIGNAL.to_string())?;
    let metadata = fs::metadata(&physical_path)
        .map_err(|_| VAULT_DEVICE_UNRESOLVABLE_SIGNAL.to_string())?;
    if !metadata.file_type().is_block_device() {
        return Err(VAULT_DEVICE_UNRESOLVABLE_SIGNAL.to_string());
    }

    let root = fs::canonicalize(config::root())
        .map_err(|_| VAULT_DEVICE_UNRESOLVABLE_SIGNAL.to_string())?;
    let logical_path = match physical_path.strip_prefix(&root) {
        Ok(relative_path) => Path::new("/").join(relative_path),
        Err(_) if physical_path.starts_with("/dev") => physical_path,
        Err(_) => return Err(VAULT_DEVICE_UNRESOLVABLE_SIGNAL.to_string()),
    };
    if !logical_path.starts_with("/dev") {
        return Err(VAULT_DEVICE_UNRESOLVABLE_SIGNAL.to_string());
    }

    Ok(logical(&logical_path))
}

fn mapper_path(cfg: &VaultConfig) -> PathBuf {
    PathBuf::from("/dev/mapper").join(&cfg.mapper)
}

fn mountpoint_path(cfg: &VaultConfig) -> PathBuf {
    root_path(&cfg.mountpoint)
}

fn log_internal(operation: &str, error: &str) {
    eprintln!("vault-{operation}-failed: {error}");
}

fn config() -> Result<Value, String> {
    let text = fs::read_to_string(root_path(APPLIANCE_CONFIG))
        .map_err(|_| "vault-config-unavailable".to_string())?;
    serde_json::from_str(&text).map_err(|_| "vault-config-invalid".to_string())
}

fn string_at<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
}

fn configured_auto_unlock(cfg: &Value) -> Option<bool> {
    let global_vault = cfg
        .get("global")
        .and_then(|v| v.get("mounts"))
        .and_then(|v| v.get("vault"));
    let top_level_vault = cfg.get("mounts").and_then(|v| v.get("vault"));
    global_vault
        .and_then(|vault| vault.get("auto_unlock"))
        .and_then(Value::as_bool)
        .or_else(|| {
            top_level_vault
                .and_then(|vault| vault.get("auto_unlock"))
                .and_then(Value::as_bool)
        })
}

fn vault_config_from(cfg: &Value) -> Result<Option<VaultConfig>, String> {
    let top_level_vault = cfg.get("mounts").and_then(|v| v.get("vault"));
    let global_vault = cfg
        .get("global")
        .and_then(|v| v.get("mounts"))
        .and_then(|v| v.get("vault"));
    let Some(mounts) = top_level_vault.or(global_vault) else {
        return Ok(None);
    };
    let mapper = string_at(mounts, &["mapper"])
        .ok_or_else(|| "vault-mapper-unconfigured".to_string())?;
    let mountpoint = string_at(mounts, &["mountPoint", "mountpoint", "mount_point"])
        .ok_or_else(|| "vault-mountpoint-unconfigured".to_string())?;
    let auto_unlock = configured_auto_unlock(cfg);
    let (device, keyfile) = if let Some(object) = mounts.as_object() {
        (
            object
                .get("device")
                .or_else(|| object.get("source"))
                .and_then(Value::as_str),
            object
                .get("keyfile")
                .or_else(|| object.get("key_file"))
                .and_then(Value::as_str),
        )
    } else {
        (mounts.as_str(), None)
    };
    Ok(Some(VaultConfig {
        mapper: mapper.to_string(),
        mountpoint: mountpoint.to_string(),
        device: device
            .ok_or_else(|| "vault-device-unconfigured".to_string())?
            .to_string(),
        keyfile: keyfile
            .filter(|value| !value.is_empty())
            .unwrap_or(GOVERNING_KEYFILE)
            .to_string(),
        auto_unlock,
    }))
}

fn vault_config() -> Result<VaultConfig, String> {
    let cfg = config()?;
    vault_config_from(&cfg)?
        .ok_or_else(|| "vault-mount-config-unavailable".to_string())
}

fn safe_mapper(mapper: &str) -> bool {
    !mapper.is_empty()
        && mapper.len() <= 128
        && mapper
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
}
fn safe_mountpoint(path: &str) -> bool {
    path.starts_with('/') && !path.split('/').any(|p| p == "..")
}
fn mounted_read(cfg: &VaultConfig) -> Result<bool, String> {
    if !safe_mapper(&cfg.mapper) || !safe_mountpoint(&cfg.mountpoint) {
        return Err("vault-mount-config-invalid".to_string());
    }
    let mapper_present = mapper_path(cfg)
        .try_exists()
        .map_err(|_| "vault-mapper-observation-unavailable".to_string())?;
    if !mapper_present {
        return Ok(false);
    }
    let text = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| "vault-mount-observation-unavailable".to_string())?;
    let physical_mountpoint = logical(&mountpoint_path(cfg));
    Ok(text.lines().any(|line| {
        line.split(" - ")
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(4)
            .map(decode_mountinfo)
            .is_some_and(|target| target == physical_mountpoint)
    }))
}
fn mounted(cfg: &VaultConfig) -> bool {
    mounted_read(cfg).unwrap_or(false)
}
fn decode_mountinfo(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}
fn read_policy(cfg: &VaultConfig) -> Result<Value, String> {
    let payload = json!({"mapper": &cfg.mapper, "op": "read"});
    let receipt = crate::gate::snake::crossing_path("storage/vault/policy", &payload)
        .map_err(|_| "vault-policy-missing".to_string())?;
    if receipt.get("schema").and_then(Value::as_str) != Some(POLICY_RECEIPT_SCHEMA)
        || receipt.get("op").and_then(Value::as_str) != Some("read")
        || receipt.get("ok").and_then(Value::as_bool) != Some(true)
    {
        return Err("vault-policy-invalid".into());
    }
    Ok(receipt)
}
fn auto_unlock_state_read(cfg: &VaultConfig) -> Result<(bool, &'static str), String> {
    match cfg.auto_unlock {
        Some(enabled) => Ok((enabled, "config")),
        None => {
            let receipt = read_policy(cfg)?;
            let unlock = receipt
                .get("unlock")
                .and_then(Value::as_str)
                .ok_or_else(|| "vault-policy-invalid".to_string())?;
            Ok((unlock == "crypttab_keyfile", "policy-marker"))
        }
    }
}
fn auto_unlock_state(cfg: &VaultConfig) -> (bool, &'static str) {
    auto_unlock_state_read(cfg).unwrap_or((false, "policy-marker"))
}
fn auto_enabled(cfg: &VaultConfig) -> bool {
    auto_unlock_state(cfg).0
}
fn config_auto_unlock_value() -> Result<Option<Value>, String> {
    let document = config()?;
    let mut current = &document;
    for key in ["global", "mounts", "vault"] {
        match current.get(key) {
            None => return Ok(None),
            Some(value) if value.is_object() => current = value,
            Some(_) => return Err("vault-config-posture-path-invalid".to_string()),
        }
    }
    Ok(current.get("auto_unlock").cloned())
}
fn config_mutation_accepted(receipt: &Value, operation: &str) -> bool {
    receipt.get("schema").and_then(Value::as_str) == Some(CONFIG_MUTATION_SCHEMA)
        && receipt.get("ok").and_then(Value::as_bool) == Some(true)
        && receipt.get("op").and_then(Value::as_str) == Some(operation)
        && receipt.get("path").and_then(Value::as_str) == Some(HOUSEHOLD_CONFIG_PATH)
        && receipt
            .get("keysTouched")
            .and_then(Value::as_array)
            .is_some_and(|keys| {
                keys.iter()
                    .any(|key| key.as_str() == Some(AUTO_UNLOCK_CONFIG_PATH))
            })
}
fn set_config_auto_unlock(
    enabled: bool,
    rollback: &mut Option<config::JsonSetRollback>,
) -> Result<(), String> {
    let receipt = config::set_json_with_rollback(
        AUTO_UNLOCK_CONFIG_PATH,
        json!(enabled),
        rollback,
    )?;
    if !config_mutation_accepted(&receipt, "set") {
        return Err("vault-config-posture-write-refused".to_string());
    }
    if config_auto_unlock_value()? != Some(json!(enabled)) {
        return Err("vault-config-posture-write-unverified".to_string());
    }
    Ok(())
}
fn restore_config_auto_unlock(rollback: config::JsonSetRollback) -> Result<(), String> {
    let receipt = config::restore_json_set(rollback)?;
    if !config_mutation_accepted(&receipt, "restore") {
        return Err("vault-config-posture-restore-refused".to_string());
    }
    Ok(())
}
fn current_auto_enabled() -> bool {
    if let Some(enabled) = config()
        .ok()
        .and_then(|document| configured_auto_unlock(&document))
    {
        return enabled;
    }
    vault_config()
        .map(|cfg| auto_enabled(&cfg))
        .unwrap_or(false)
}
fn auto_decrypt_failure(rollback: Option<config::JsonSetRollback>) -> Value {
    if let Some(rollback) = rollback {
        if let Err(error) = restore_config_auto_unlock(rollback) {
            log_internal("auto-decrypt-config-rollback", &error);
        }
    }
    json!({
        "success": false,
        "message": "Unable to update automatic vault decryption.",
        "auto_decrypt_enabled": current_auto_enabled(),
    })
}
fn result(success: bool, message: &str) -> Value {
    json!({"success": success, "message": message})
}
#[derive(Clone, Copy)]
pub(crate) struct GateVaultPosture {
    pub(crate) present: bool,
    pub(crate) mounted: bool,
    pub(crate) auto_decrypt_enabled: bool,
}

pub(crate) fn gate_posture_read() -> Result<Option<GateVaultPosture>, String> {
    let document = config()?;
    let Some(cfg) = vault_config_from(&document)? else {
        return Ok(None);
    };
    let mounted = mounted_read(&cfg)?;
    let (auto_decrypt_enabled, _) = auto_unlock_state_read(&cfg)?;
    Ok(Some(GateVaultPosture {
        present: true,
        mounted,
        auto_decrypt_enabled,
    }))
}

pub fn status_json() -> Value {
    match vault_config() {
        Ok(cfg) => {
            // Status presence is a parsed appliance declaration, not mount state or the staff receipt's `present`.
            let present = true;
            let (auto_decrypt_enabled, auto_unlock_source) = auto_unlock_state(&cfg);
            json!({
                "mounted": mounted(&cfg),
                "auto_decrypt_enabled": auto_decrypt_enabled,
                "auto_unlock_source": auto_unlock_source,
                "present": present,
            })
        }
        Err(_) => {
            let (auto_decrypt_enabled, auto_unlock_source) = config()
                .ok()
                .and_then(|document| configured_auto_unlock(&document))
                .map(|enabled| (enabled, "config"))
                .unwrap_or((false, "policy-marker"));
            json!({
                "mounted": false,
                "auto_decrypt_enabled": auto_decrypt_enabled,
                "auto_unlock_source": auto_unlock_source,
                "present": false,
            })
        }
    }
}
fn open_vault(cfg: &VaultConfig, passphrase: Option<&str>) -> Result<Value, String> {
    let declaration: Value = serde_json::from_str(include_str!("index.json"))
        .map_err(|_| "vault-open-deadline-invalid".to_string())?;
    let seconds = declaration.get("deadline_seconds").and_then(Value::as_u64)
        .filter(|seconds| (1..=600).contains(seconds))
        .ok_or_else(|| "vault-open-deadline-invalid".to_string())?;
    let device = resolve_device(&cfg.device)?;
    let payload = json!({
        "op": "unlock",
        "mapper": &cfg.mapper,
        "device": device,
        "mountpoint": logical(&mountpoint_path(cfg)),
        "passphrase": passphrase,
    });
    let crossing = crate::gate::snake::crossing_path_with_timeout(
        "storage/vault/open", &payload, std::time::Duration::from_secs(seconds),
    ).map_err(|signal| {
        if signal == "caduceus-agathodaimon-timeout" {
            format!("vault-open-timeout: {seconds} seconds")
        } else {
            "vault-open-crossing-unavailable".to_string()
        }
    })?;
    let receipt = crossing.get("receiptPayload")
        .filter(|receipt| receipt.is_object())
        .ok_or_else(|| "vault-open-receipt-invalid".to_string())?;
    let receipt_ok = receipt.get("ok").and_then(Value::as_bool);
    let signal = ["error", "firstMissingSignal", "signal", "message"]
        .iter()
        .filter_map(|field| receipt.get(*field).and_then(Value::as_str))
        .map(str::trim)
        .find(|signal| !signal.is_empty() && !signal.eq_ignore_ascii_case("none"));
    let timeout_reported = ["error", "firstMissingSignal", "signal", "message"]
        .iter()
        .filter_map(|field| receipt.get(*field).and_then(Value::as_str))
        .any(|signal| {
            let lower = signal.to_ascii_lowercase();
            lower.contains("timeout") || lower.contains("timed-out") || lower.contains("timed_out")
        });
    if receipt.get("mounted").and_then(Value::as_bool) == Some(true) {
        let mut answer = result(true, "vault-unlocked-and-mounted");
        // A mounted vault is success; a later failure remains visible, even
        // when the staff did not provide a usable failure signal.
        if timeout_reported {
            answer["warning"] = json!(format!("vault-open-timeout: {seconds} seconds"));
        } else if let Some(signal) = signal {
            answer["warning"] = json!(signal);
        } else if receipt_ok != Some(true) || crossing.get("ok").and_then(Value::as_bool) == Some(false) {
            answer["warning"] = json!("vault-open-post-mount-failure-unknown");
        }
        for field in ["rite", "nas", "nas_roles", "init", "boot_rite"] {
            if let Some(value) = receipt.get(field) {
                answer[field] = value.clone();
            }
        }
        return Ok(answer);
    }
    if timeout_reported {
        return Err(format!("vault-open-timeout: {seconds} seconds"));
    }
    let receipt_ok = receipt_ok.ok_or_else(|| "vault-open-receipt-invalid".to_string())?;
    if crossing.get("ok").and_then(Value::as_bool) != Some(true) {
        let signal = signal.unwrap_or("caduceus-agathodaimon-refused");
        if signal == VAULT_OPEN_KEY_ABSENT_SIGNAL {
            return Ok(if passphrase.is_none() { result(false, "A vault password is required.") } else { result(false, "Unable to unlock the vault.") });
        }
        if signal == VAULT_OPEN_UNLOCK_REFUSED_SIGNAL || signal == VAULT_OPEN_MOUNTPOINT_REFUSED_SIGNAL || signal == VAULT_OPEN_MOUNT_REFUSED_SIGNAL {
            return Ok(result(false, "Unable to unlock the vault."));
        }
        return Err("vault-open-crossing-unavailable".to_string());
    }
    if !receipt_ok {
        return Ok(result(false, "Unable to unlock the vault."));
    }
    if receipt.get("present").and_then(Value::as_bool) == Some(false) && passphrase.is_none() {
        return Ok(result(false, "A vault password is required."));
    }
    if !mapper_path(cfg).exists() {
        log_internal("unlock", "vault-unlock-unverified");
        return Ok(result(false, "Unable to unlock the vault."));
    }
    if mounted(cfg) {
        Ok(result(true, "vault-unlocked-and-mounted"))
    } else {
        log_internal("unlock", "vault-mount-unverified");
        Ok(result(false, "Unable to mount the vault."))
    }
}

pub fn unlock_json(password: Option<&str>) -> Value {
    let cfg = match vault_config() {
        Ok(cfg) => cfg,
        Err(error) => {
            log_internal("unlock", &error);
            return result(false, "Unable to unlock the vault.");
        }
    };
    if !safe_mapper(&cfg.mapper) || !safe_mountpoint(&cfg.mountpoint) {
        log_internal("unlock", "vault-config-invalid");
        return result(false, "Unable to unlock the vault.");
    }
    let passphrase = password.filter(|value| !value.is_empty());
    match open_vault(&cfg, passphrase) {
        Ok(receipt) => receipt,
        Err(error) if error.starts_with("vault-open-timeout:") => {
            log_internal("unlock", &error);
            result(false, &error)
        }
        Err(error) => {
            log_internal("unlock", &error);
            result(false, "Unable to unlock the vault.")
        }
    }
}
pub fn auto_decrypt_json(enabled: bool) -> Value {
    let cfg = match vault_config() {
        Ok(cfg) => cfg,
        Err(error) => {
            log_internal("auto-decrypt", &error);
            return json!({"success":false,"message":"Unable to update automatic vault decryption.","auto_decrypt_enabled":false});
        }
    };
    if !mounted(&cfg) {
        log_internal("auto-decrypt", "vault-must-be-mounted");
        return json!({"success":false,"message":"The vault must be mounted first.","auto_decrypt_enabled":auto_enabled(&cfg)});
    }
    let Ok(_policy) = read_policy(&cfg) else {
        log_internal("auto-decrypt", "vault-policy-invalid");
        return json!({"success":false,"message":"Unable to update automatic vault decryption.","auto_decrypt_enabled":false});
    };
    let mut config_rollback = None;
    if let Err(error) = set_config_auto_unlock(enabled, &mut config_rollback) {
        log_internal("auto-decrypt", &error);
        return auto_decrypt_failure(config_rollback);
    }
    let unlock = if enabled {
        "crypttab_keyfile"
    } else {
        "manual_passphrase"
    };
    let payload = if enabled {
        json!({
            "mapper": &cfg.mapper,
            "op": "write",
            "unlock": "crypttab_keyfile",
            "keyfile": &cfg.keyfile,
        })
    } else {
        json!({
            "mapper": &cfg.mapper,
            "op": "write",
            "unlock": "manual_passphrase",
        })
    };
    let receipt = match crate::gate::snake::crossing_path("storage/vault/policy", &payload) {
        Ok(receipt) => receipt,
        Err(error) => {
            log_internal("auto-decrypt", &error);
            return auto_decrypt_failure(config_rollback);
        }
    };
    if receipt.get("schema").and_then(Value::as_str) != Some(POLICY_RECEIPT_SCHEMA)
        || receipt.get("op").and_then(Value::as_str) != Some("write")
        || receipt.get("unlock").and_then(Value::as_str) != Some(unlock)
        || receipt.get("ok").and_then(Value::as_bool) != Some(true)
    {
        let signal = receipt
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("vault-policy-write-refused");
        log_internal("auto-decrypt", signal);
        return auto_decrypt_failure(config_rollback);
    }
    json!({
        "success": true,
        "message": "vault-auto-decrypt-updated",
        "auto_decrypt_enabled": enabled,
        "auto_unlock": enabled,
    })
}

use axum::extract::Json as ExtractJson;
use axum::http::StatusCode;

async fn vault_unlock_route(
    ExtractJson(body): ExtractJson<crate::gate::VaultUnlockBody>,
) -> Result<(StatusCode, axum::Json<serde_json::Value>), (StatusCode, axum::Json<crate::gate::ApiErrorBody>)> {
    let password = body.password;
    let context = crate::shared::load_trace::current();
    let task = tokio::spawn(async move {
        let response = crate::gate::blocking_task("vault unlock", move || {
            crate::shared::load_trace::with_blocking_context(context, || unlock_json(password.as_deref()))
        })
        .await
        .map(|value| (StatusCode::OK, axum::Json(value)));
        #[cfg(leaf_pid2)]
        crate::pid2::events::notify();
        response
    });
    match task.await {
        Ok(response) => response,
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/storage/vault/unlock",
        axum::routing::post(vault_unlock_route),
    )
}
