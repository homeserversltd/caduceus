use crate::shared::config;
use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

const STATE: &str = "/var/lib/homeconsole/state.json";
const APPLIANCE_CONFIG: &str = "/etc/appliance/config.json";
const CRYPTTAB: &str = "/etc/crypttab";
const POLICY_NAME: &str = ".keyman-vault-policy.json";
const POLICY_SCHEMA: &str = "fulcrum.keyman.vault_policy.v1";
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
fn policy_path(cfg: &VaultConfig) -> PathBuf {
    mountpoint_path(cfg).join(POLICY_NAME)
}
fn read_policy(cfg: &VaultConfig) -> Result<Map<String, Value>, String> {
    let text =
        fs::read_to_string(policy_path(cfg)).map_err(|_| "vault-policy-missing".to_string())?;
    let value: Value =
        serde_json::from_str(&text).map_err(|_| "vault-policy-invalid".to_string())?;
    let object = value
        .as_object()
        .ok_or_else(|| "vault-policy-invalid".to_string())?;
    if object.get("schema").and_then(Value::as_str) != Some(POLICY_SCHEMA)
        || object.get("mode").and_then(Value::as_str) != Some("separate_luks_vault")
    {
        return Err("vault-policy-invalid".into());
    }
    Ok(object.clone())
}
fn auto_enabled(cfg: &VaultConfig) -> bool {
    read_policy(cfg)
        .ok()
        .and_then(|p| {
            p.get("unlock")
                .and_then(Value::as_str)
                .map(|v| v == "crypttab_keyfile")
        })
        .unwrap_or(false)
}
fn result(success: bool, message: &str) -> Value {
    json!({"success": success, "message": message})
}
fn sudo_tee(path: &str, data: &[u8]) -> Result<(), String> {
    let mut child = Command::new("/usr/bin/sudo")
        .args(["-n", "/usr/bin/tee", path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| "vault-privileged-command-unavailable")?;
    child
        .stdin
        .take()
        .ok_or_else(|| "vault-privileged-command-unavailable".to_string())?
        .write_all(data)
        .map_err(|error| format!("vault-write-failed: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("vault-write-wait-failed: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            Err(format!("vault-write-failed: status {}", output.status))
        } else {
            Err(format!("vault-write-failed: {stderr}"))
        }
    }
}
fn run_sudo(args: &[&str], stdin: Option<&[u8]>) -> Result<(), String> {
    let mut child = Command::new("/usr/bin/sudo")
        .args(args)
        .stdin(if stdin.is_some() {
            std::process::Stdio::piped()
        } else {
            std::process::Stdio::null()
        })
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|_| "vault-privileged-command-unavailable")?;
    if let Some(bytes) = stdin {
        child
            .stdin
            .take()
            .ok_or_else(|| "vault-privileged-command-unavailable".to_string())?
            .write_all(bytes)
            .map_err(|_| "vault-command-failed")?;
    }
    let output = child
        .wait_with_output()
        .map_err(|error| format!("vault-command-wait-failed: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            Err(format!("vault-command-failed: status {}", output.status))
        } else {
            Err(format!("vault-command-failed: {stderr}"))
        }
    }
}
fn uuid_for(device: &str, old: &str) -> String {
    let output = Command::new("/usr/bin/sudo")
        .args(["-n", "/usr/sbin/blkid", "-s", "UUID", "-o", "value", device])
        .output();
    output
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| old.to_string())
}
fn crypttab_line(cfg: &VaultConfig, enabled: bool) -> Result<(String, String), String> {
    let text = fs::read_to_string(root_path(CRYPTTAB))
        .map_err(|_| "vault-crypttab-unavailable".to_string())?;
    let mut existing = None;
    let mut replaced = false;
    let mut lines = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first().copied() == Some(cfg.mapper.as_str()) {
            existing = fields.get(1).copied();
            if !replaced {
                let source = uuid_for(&cfg.device, existing.unwrap_or("none"));
                let key = if enabled {
                    if cfg.keyfile.is_empty() {
                        return Err("vault-keyfile-unconfigured".into());
                    } else {
                        cfg.keyfile.as_str()
                    }
                } else {
                    "none"
                };
                let opts = if enabled {
                    "luks,nofail"
                } else {
                    "luks,noauto,nofail"
                };
                lines.push(format!("{} {} {} {}", cfg.mapper, source, key, opts));
                replaced = true;
            }
        } else {
            lines.push(line.to_string());
        }
    }
    if !replaced {
        let source = uuid_for(&cfg.device, existing.unwrap_or("none"));
        let key = if enabled {
            if cfg.keyfile.is_empty() {
                return Err("vault-keyfile-unconfigured".into());
            } else {
                cfg.keyfile.as_str()
            }
        } else {
            "none"
        };
        let opts = if enabled {
            "luks,nofail"
        } else {
            "luks,noauto,nofail"
        };
        lines.push(format!("{} {} {} {}", cfg.mapper, source, key, opts));
    }
    let new = format!("{}\n", lines.join("\n"));
    Ok((new, text))
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
fn keyman_unavailable(signal: &str) -> Result<bool, String> {
    log_internal("keyman-open", signal);
    Ok(false)
}

fn keyman_open(cfg: &VaultConfig) -> Result<bool, String> {
    let payload = json!({"device": cfg.device, "mapper": cfg.mapper});
    let receipt = match crate::gate::snake::crossing_path("storage/vault/open", &payload) {
        Ok(receipt) => receipt,
        Err(receipt) => return Err(receipt),
    };
    let Some(present) = receipt.get("present").and_then(Value::as_bool) else {
        return keyman_unavailable("vault-keyman-open-presence-unavailable");
    };
    if !present {
        return Ok(false);
    }
    match receipt.get("ok").and_then(Value::as_bool) {
        Some(false) => Err("vault-keyman-open-refused".to_string()),
        Some(true) => Ok(true),
        None => keyman_unavailable("vault-keyman-open-receipt-invalid"),
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
    if !Path::new("/usr/sbin/cryptsetup").exists() || !Path::new("/usr/bin/mount").exists() {
        log_internal("unlock", "vault-required-command-unavailable");
        return result(false, "Unable to unlock the vault.");
    }
    if !mapper_path(&cfg).exists() {
        match keyman_open(&cfg) {
            Ok(true) => {}
            Ok(false) => {
                let Some(password) = password.filter(|value| !value.is_empty()) else {
                    return result(false, "A vault password is required.");
                };
                if let Err(error) = run_sudo(
                    &[
                        "-n",
                        "/usr/sbin/cryptsetup",
                        "open",
                        "--batch-mode",
                        "--key-file",
                        "-",
                        &cfg.device,
                        &cfg.mapper,
                    ],
                    Some(password.as_bytes()),
                ) {
                    log_internal("unlock", &error);
                    return result(false, "Unable to unlock the vault.");
                }
            }
            Err(error) => {
                log_internal("unlock", &error);
                return result(false, "Unable to unlock the vault.");
            }
        }
    }
    if !mapper_path(&cfg).exists() {
        log_internal("unlock", "vault-unlock-unverified");
        return result(false, "Unable to unlock the vault.");
    }
    if !mounted(&cfg) {
        let mountpoint = logical(&mountpoint_path(&cfg));
        if let Err(error) = run_sudo(&["-n", "/usr/bin/mkdir", "-p", &mountpoint], None) {
            log_internal("unlock", &error);
            return result(false, "Unable to mount the vault.");
        }
        if let Err(error) = run_sudo(
            &[
                "-n",
                "/usr/bin/mount",
                &format!("/dev/mapper/{}", cfg.mapper),
                &mountpoint,
            ],
            None,
        ) {
            log_internal("unlock", &error);
            return result(false, "Unable to mount the vault.");
        }
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
    let Ok(mut policy) = read_policy(&cfg) else {
        log_internal("auto-decrypt", "vault-policy-invalid");
        return json!({"success":false,"message":"Unable to update automatic vault decryption.","auto_decrypt_enabled":false});
    };
    let (crypttab, old) = match crypttab_line(&cfg, enabled) {
        Ok(v) => v,
        Err(error) => {
            log_internal("auto-decrypt", &error);
            return json!({"success":false,"message":"Unable to update automatic vault decryption.","auto_decrypt_enabled":auto_enabled(&cfg)});
        }
    };
    let crypttab_path = logical(&root_path(CRYPTTAB));
    if let Err(error) = sudo_tee(&crypttab_path, crypttab.as_bytes()) {
        log_internal("auto-decrypt", &error);
        return json!({"success":false,"message":"Unable to update automatic vault decryption.","auto_decrypt_enabled":auto_enabled(&cfg)});
    }
    policy.insert(
        "unlock".into(),
        Value::String(
            if enabled {
                "crypttab_keyfile"
            } else {
                "manual_passphrase"
            }
            .into(),
        ),
    );
    let marker = match serde_json::to_vec_pretty(&Value::Object(policy)) {
        Ok(mut bytes) => {
            bytes.push(b'\n');
            bytes
        }
        Err(error) => {
            log_internal(
                "auto-decrypt",
                &format!("vault-policy-serialize-failed: {error}"),
            );
            let _ = sudo_tee(&crypttab_path, old.as_bytes());
            return json!({"success":false,"message":"Unable to update automatic vault decryption.","auto_decrypt_enabled":auto_enabled(&cfg)});
        }
    };
    if let Err(error) = sudo_tee(&logical(&policy_path(&cfg)), &marker) {
        log_internal("auto-decrypt", &error);
        let _ = sudo_tee(&crypttab_path, old.as_bytes());
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
