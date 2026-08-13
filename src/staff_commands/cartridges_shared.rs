//! Caduceus-owned appliance cartridge registry.
//!
//! The registry is declarative Crown metadata. This native Rust band is its
//! only writer; `CADUCEUS_ROOT` keeps local proof on a scratch appliance root.

use crate::shared::config as paths;
use crate::shared::config::atomic_write_owned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

const SCHEMA: &str = "appliance.cartridges.v1";
const DEVICE_PATH: &str = "/etc/appliance/cartridges.json";
const FILE_MODE: u32 = 0o640;

#[derive(Debug)]
pub struct CartridgeError {
    pub status: u16,
    pub signal: &'static str,
}

impl CartridgeError {
    fn bad_request(signal: &'static str) -> Self {
        Self {
            status: 400,
            signal,
        }
    }

    fn conflict(signal: &'static str) -> Self {
        Self {
            status: 409,
            signal,
        }
    }

    fn unavailable(signal: &'static str) -> Self {
        Self {
            status: 503,
            signal,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cartridge {
    pub id: String,
    pub title: String,
    pub url: String,
    pub guest_class: String,
    pub admin_only: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    schema: String,
    cartridges: Vec<Cartridge>,
}

fn registry_path() -> PathBuf {
    paths::path(DEVICE_PATH)
}

fn empty_registry() -> Registry {
    Registry {
        schema: SCHEMA.to_string(),
        cartridges: Vec::new(),
    }
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !id.contains("--")
}

fn valid_url(url: &str) -> bool {
    if url.len() > 2048 || url.chars().any(char::is_whitespace) {
        return false;
    }
    let Some(remainder) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else {
        return false;
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    !authority.is_empty() && !authority.starts_with(':') && !authority.contains('@')
}

fn validate_cartridge(cartridge: &Cartridge) -> Result<(), CartridgeError> {
    if !valid_id(&cartridge.id) {
        return Err(CartridgeError::bad_request("caduceus-cartridge-id-invalid"));
    }
    if cartridge.title.trim().is_empty() || cartridge.title.len() > 256 {
        return Err(CartridgeError::bad_request(
            "caduceus-cartridge-title-invalid",
        ));
    }
    if !valid_url(&cartridge.url) {
        return Err(CartridgeError::bad_request(
            "caduceus-cartridge-url-invalid",
        ));
    }
    if cartridge.guest_class != "iframe" {
        return Err(CartridgeError::bad_request(
            "caduceus-cartridge-guest-class-invalid",
        ));
    }
    Ok(())
}

fn validate_registry(registry: &Registry) -> Result<(), CartridgeError> {
    if registry.schema != SCHEMA {
        return Err(CartridgeError::unavailable(
            "caduceus-cartridge-registry-schema-invalid",
        ));
    }
    let mut ids = std::collections::HashSet::new();
    for cartridge in &registry.cartridges {
        validate_cartridge(cartridge)?;
        if !ids.insert(&cartridge.id) {
            return Err(CartridgeError::unavailable(
                "caduceus-cartridge-registry-duplicate-id",
            ));
        }
    }
    Ok(())
}

fn read_registry() -> Result<Registry, CartridgeError> {
    let path = registry_path();
    if !path.exists() {
        return Ok(empty_registry());
    }
    let text = fs::read_to_string(path)
        .map_err(|_| CartridgeError::unavailable("caduceus-cartridge-registry-read-failed"))?;
    let registry: Registry = serde_json::from_str(&text)
        .map_err(|_| CartridgeError::unavailable("caduceus-cartridge-registry-invalid"))?;
    validate_registry(&registry)?;
    Ok(registry)
}

fn write_registry(registry: &Registry) -> Result<(), CartridgeError> {
    validate_registry(registry)?;
    let path = registry_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| {
            CartridgeError::unavailable("caduceus-cartridge-registry-parent-create-failed")
        })?;
    }
    let mut bytes = serde_json::to_vec_pretty(registry)
        .map_err(|_| CartridgeError::unavailable("caduceus-cartridge-registry-render-failed"))?;
    bytes.push(b'\n');
    atomic_write_owned(&path, &bytes, FILE_MODE)
        .map_err(|_| CartridgeError::unavailable("caduceus-cartridge-registry-write-failed"))
}

pub fn passage_bytes() -> Result<Vec<u8>, CartridgeError> {
    let path = registry_path();
    if !path.exists() {
        return serde_json::to_vec(&empty_registry())
            .map_err(|_| CartridgeError::unavailable("caduceus-cartridge-registry-render-failed"));
    }
    fs::read(path)
        .map_err(|_| CartridgeError::unavailable("caduceus-cartridge-registry-read-failed"))
}

pub fn admit(cartridge: Cartridge) -> Result<Value, CartridgeError> {
    validate_cartridge(&cartridge)?;
    let mut registry = read_registry()?;
    if registry
        .cartridges
        .iter()
        .any(|existing| existing.id == cartridge.id)
    {
        return Err(CartridgeError::conflict("caduceus-cartridge-id-duplicate"));
    }
    registry.cartridges.push(cartridge.clone());
    write_registry(&registry)?;
    Ok(json!({
        "schema": "caduceus.cartridges.mutation.v1",
        "ok": true,
        "operation": "admit",
        "cartridge": cartridge,
        "cartridgeCount": registry.cartridges.len(),
        "firstMissingSignal": "none",
    }))
}

pub fn remove(id: &str) -> Result<Value, CartridgeError> {
    if !valid_id(id) {
        return Err(CartridgeError::bad_request("caduceus-cartridge-id-invalid"));
    }
    let mut registry = read_registry()?;
    let Some(position) = registry
        .cartridges
        .iter()
        .position(|cartridge| cartridge.id == id)
    else {
        return Err(CartridgeError {
            status: 404,
            signal: "caduceus-cartridge-not-found",
        });
    };
    let cartridge = registry.cartridges.remove(position);
    write_registry(&registry)?;
    Ok(json!({
        "schema": "caduceus.cartridges.mutation.v1",
        "ok": true,
        "operation": "remove",
        "cartridge": cartridge,
        "cartridgeCount": registry.cartridges.len(),
        "firstMissingSignal": "none",
    }))
}
