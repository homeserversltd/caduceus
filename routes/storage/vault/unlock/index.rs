use crate::shared::config;
use serde_json::{json, Value};
use std::fs;
use std::path::{Path, PathBuf};

const STATE: &str = "/var/lib/homeconsole/state.json";
const APPLIANCE_CONFIG: &str = "/etc/appliance/config.json";
const POLICY_RECEIPT_SCHEMA: &str = "caduceus.vault.policy-write.v1";
const GOVERNING_KEYFILE: &str = "/root/key/homeconsole-vault.key";

#[derive(Clone)]
struct VaultConfig {
    mapper: String,
    mountpoint: String,
    device: String,
    keyfile: String,
}

fn root_path(path: &str) -> PathBuf {
    config::path(path)
}
fn logical(path: &Path) -> String {
    path.to_string_lossy().into_owned()
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

fn state() -> Result<Value, String> {
    let text =
        fs::read_to_string(root_path(STATE)).map_err(|_| "vault-state-unavailable".to_string())?;
    serde_json::from_str(&text).map_err(|_| "vault-state-invalid".to_string())
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

fn vault_config() -> Result<VaultConfig, String> {
    let state = state()?;
    let vault = state.get("vault").unwrap_or(&state);
    let mapper = string_at(vault, &["mapper", "name"])
        .ok_or_else(|| "vault-mapper-unconfigured".to_string())?;
    let mountpoint = string_at(vault, &["mountpoint", "mount_point"])
        .ok_or_else(|| "vault-mountpoint-unconfigured".to_string())?;
    let cfg = config()?;
    let mounts = cfg
        .get("mounts")
        .and_then(|v| v.get("vault"))
        .or_else(|| {
            cfg.get("global")
                .and_then(|v| v.get("mounts"))
                .and_then(|v| v.get("vault"))
        })
        .ok_or_else(|| "vault-mount-config-unavailable".to_string())?;
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
    Ok(VaultConfig {
        mapper: mapper.to_string(),
        mountpoint: mountpoint.to_string(),
        device: device
            .ok_or_else(|| "vault-device-unconfigured".to_string())?
            .to_string(),
        keyfile: keyfile
            .filter(|value| !value.is_empty())
            .unwrap_or(GOVERNING_KEYFILE)
            .to_string(),
    })
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
fn mounted(cfg: &VaultConfig) -> bool {
    if !safe_mapper(&cfg.mapper) || !safe_mountpoint(&cfg.mountpoint) {
        return false;
    }
    if !mapper_path(cfg).exists() {
        return false;
    }
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let physical_mountpoint = logical(&mountpoint_path(cfg));
    text.lines().any(|line| {
        line.split(" - ")
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(4)
            .map(decode_mountinfo)
            .is_some_and(|target| target == physical_mountpoint)
    })
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
fn auto_enabled(cfg: &VaultConfig) -> bool {
    read_policy(cfg)
        .ok()
        .and_then(|receipt| {
            receipt
                .get("unlock")
                .and_then(Value::as_str)
                .map(|v| v == "crypttab_keyfile")
        })
        .unwrap_or(false)
}
fn result(success: bool, message: &str) -> Value {
    json!({"success": success, "message": message})
}
pub fn status_json() -> Value {
    match vault_config() {
        Ok(cfg) => {
            let present = state()
                .ok()
                .and_then(|state| {
                    let vault = state.get("vault").unwrap_or(&state);
                    vault.get("enabled").and_then(Value::as_bool)
                })
                .unwrap_or(false);
            json!({"mounted": mounted(&cfg), "auto_decrypt_enabled": auto_enabled(&cfg), "present": present})
        }
        Err(_) => json!({"mounted": false, "auto_decrypt_enabled": false, "present": false}),
    }
}
fn open_vault(cfg: &VaultConfig, passphrase: Option<&str>) -> Result<(bool, Option<bool>), String> {
    let payload = json!({
        "op": "unlock",
        "mapper": &cfg.mapper,
        "device": &cfg.device,
        "mountpoint": logical(&mountpoint_path(cfg)),
        "passphrase": passphrase,
    });
    let receipt = crate::gate::snake::crossing_path("storage/vault/open", &payload)
        .map_err(|_| "vault-open-crossing-unavailable".to_string())?;
    let ok = receipt
        .get("ok")
        .and_then(Value::as_bool)
        .ok_or_else(|| "vault-open-receipt-invalid".to_string())?;
    let present = receipt.get("present").and_then(Value::as_bool);
    Ok((ok, present))
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
    let (opened, present) = match open_vault(&cfg, passphrase) {
        Ok(receipt) => receipt,
        Err(_) => {
            log_internal("unlock", "vault-open-crossing-unavailable");
            return result(false, "Unable to unlock the vault.");
        }
    };
    if !opened {
        if present == Some(false) && passphrase.is_none() {
            return result(false, "A vault password is required.");
        }
        log_internal("unlock", "vault-open-refused");
        return result(false, "Unable to unlock the vault.");
    }
    if present == Some(false) && passphrase.is_none() {
        return result(false, "A vault password is required.");
    }
    if !mapper_path(&cfg).exists() {
        log_internal("unlock", "vault-unlock-unverified");
        return result(false, "Unable to unlock the vault.");
    }
    if mounted(&cfg) {
        result(true, "vault-unlocked-and-mounted")
    } else {
        log_internal("unlock", "vault-mount-unverified");
        result(false, "Unable to mount the vault.")
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
            return json!({"success":false,"message":"Unable to update automatic vault decryption.","auto_decrypt_enabled":auto_enabled(&cfg)});
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
        return json!({"success":false,"message":"Unable to update automatic vault decryption.","auto_decrypt_enabled":auto_enabled(&cfg)});
    }
    json!({"success":true,"message":"vault-auto-decrypt-updated","auto_decrypt_enabled":enabled})
}

use axum::extract::Json as ExtractJson;
use axum::http::StatusCode;

async fn vault_unlock_route(
    ExtractJson(body): ExtractJson<crate::gate::VaultUnlockBody>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::OK,
        axum::Json(unlock_json(body.password.as_deref())),
    )
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/storage/vault/unlock",
        axum::routing::post(vault_unlock_route),
    )
}
