#[path = "power/index.rs"]
pub mod power;
#[path = "products/index.rs"]
pub mod products;
#[path = "scan/index.rs"]
pub mod scan;

use crate::shared::{config, pjlink, receipts};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
mod catalog;
use std::time::{SystemTime, UNIX_EPOCH};

fn profile() -> Result<Value, String> {
    Ok(config::carapace().clone())
}

pub fn devices_json() -> Result<Value, String> {
    let profile = profile()?;
    let devices = profile
        .get("pjlink")
        .and_then(|value| value.get("devices"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(json!({
        "schema": "caduceus.pjlink.devices.v1",
        "ok": true,
        "count": devices.len(),
        "devices": devices,
        "firstMissingSignal": "none"
    }))
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase")]
pub struct KnownProductEntry {
    pub schema: String,
    pub id: String,
    pub device_id: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
    pub manufacturer: Option<String>,
    pub product_name: Option<String>,
    pub other_info: Option<String>,
    pub class: Option<String>,
    pub source: Option<String>,
    pub first_seen_epoch: Option<u64>,
    pub last_seen_epoch: Option<u64>,
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn dry_run_product_for(device_id: &str) -> Option<pjlink::PjlinkProductInfo> {
    profile()
        .ok()
        .and_then(|profile| profile.get("pjlink").cloned())
        .and_then(|pjlink| pjlink.get("devices").cloned())
        .and_then(|devices| devices.as_array().cloned())
        .and_then(|devices| {
            devices.into_iter().find_map(|device| {
                if device.get("id").and_then(Value::as_str) == Some(device_id) {
                    device.get("known_product").cloned()
                } else {
                    None
                }
            })
        })
        .and_then(|value| serde_json::from_value(value).ok())
}

fn entry_from_scan(
    receipt: &pjlink::PjlinkProductScanReceipt,
    source: &str,
) -> Result<KnownProductEntry, String> {
    let product = receipt
        .product
        .clone()
        .ok_or_else(|| "caduceus-pjlink-product-scan-empty".to_string())?;
    let id = format!(
        "{}:{}:{}",
        receipt.device_id,
        product
            .manufacturer
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        product
            .product_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string())
    )
    .replace(' ', "-")
    .to_lowercase();
    let stamp = now_epoch();
    Ok(KnownProductEntry {
        schema: catalog::schema()?,
        id,
        device_id: Some(receipt.device_id.clone()),
        host: Some(receipt.host.clone()),
        port: Some(receipt.port),
        manufacturer: product.manufacturer,
        product_name: product.product_name,
        other_info: product.other_info,
        class: product.class,
        source: Some(source.to_string()),
        first_seen_epoch: Some(stamp),
        last_seen_epoch: Some(stamp),
    })
}

pub fn known_products_json() -> Result<Value, String> {
    let entries = catalog::list()?;
    Ok(json!({
        "schema": "caduceus.pjlink.known-products.v1",
        "ok": true,
        "catalogPath": crate::stats::db_path().display().to_string(),
        "count": entries.len(),
        "entries": entries,
        "firstMissingSignal": "none"
    }))
}

pub fn scan_product_json(device_id: &str, dry_run: bool) -> Result<Value, String> {
    let device = device_by_id(device_id)?;
    let receipt = pjlink::run_product_scan(&device, dry_run, dry_run_product_for(device_id));
    serde_json::to_value(receipt)
        .map_err(|err| format!("caduceus-pjlink-product-scan-invalid:{err}"))
}

pub fn add_known_product_json(
    device_id: &str,
    dry_run: bool,
    from_profile: bool,
) -> Result<Value, String> {
    let device = device_by_id(device_id)?;
    let profile_product = dry_run_product_for(device_id);
    let receipt = pjlink::run_product_scan(&device, dry_run || from_profile, profile_product);
    if !receipt.ok {
        return serde_json::to_value(receipt)
            .map_err(|err| format!("caduceus-pjlink-product-scan-invalid:{err}"));
    }
    let entry = entry_from_scan(
        &receipt,
        if from_profile {
            "profile-catalog"
        } else if dry_run {
            "dry-run-profile"
        } else {
            "pjlink-scan"
        },
    )?;
    if dry_run {
        return Ok(json!({
            "schema": "caduceus.pjlink.known-product.add.v1",
            "ok": true,
            "mutation": false,
            "dryRun": true,
            "entry": entry,
            "firstMissingSignal": "none"
        }));
    }
    let count = catalog::add(&entry)?;
    Ok(json!({
        "schema": "caduceus.pjlink.known-product.add.v1",
        "ok": true,
        "mutation": true,
        "dryRun": false,
        "entry": entry,
        "count": count,
        "firstMissingSignal": "none"
    }))
}

pub fn remove_known_product_json(entry_id: &str) -> Result<Value, String> {
    let (removed, count) = catalog::remove(entry_id)?;
    Ok(json!({
        "schema": "caduceus.pjlink.known-product.remove.v1",
        "ok": true,
        "mutation": removed > 0,
        "removed": removed,
        "id": entry_id,
        "count": count,
        "firstMissingSignal": "none"
    }))
}

fn device_by_id(device_id: &str) -> Result<pjlink::PjlinkDevice, String> {
    let devices_value = devices_json()?;
    let Some(devices) = devices_value.get("devices").and_then(Value::as_array) else {
        return Err("caduceus-pjlink-devices-missing".to_string());
    };
    for value in devices {
        let device: pjlink::PjlinkDevice = serde_json::from_value(value.clone())
            .map_err(|err| format!("caduceus-pjlink-device-invalid:{err}"))?;
        if device.id == device_id {
            return Ok(device);
        }
    }
    Err("caduceus-pjlink-device-missing".to_string())
}

pub fn power_json(device_id: &str, state: &str, dry_run: bool) -> Result<Value, String> {
    let device = device_by_id(device_id)?;
    let receipt = pjlink::run_power(&device, state, dry_run);
    let value = serde_json::to_value(&receipt)
        .map_err(|err| format!("caduceus-pjlink-receipt-invalid:{err}"))?;
    if !dry_run {
        let _ = receipts::write_latest(&format!(
            "schema={}\nok={}\ndevice_id={}\nmutation={}\nfirst_missing_signal={}\n",
            receipt.schema,
            receipt.ok,
            receipt.device_id,
            receipt.mutation,
            receipt.first_missing_signal
        ));
    }
    Ok(value)
}

pub fn power_status_json(device_id: &str) -> Result<Value, String> {
    let device = device_by_id(device_id)?;
    let receipt = pjlink::run_power_query(&device);
    serde_json::to_value(&receipt).map_err(|err| format!("caduceus-pjlink-receipt-invalid:{err}"))
}

pub fn devices() -> i32 {
    match devices_json() {
        Ok(value) => {
            println!("schema=caduceus.pjlink.devices.v1");
            println!("count={}", value["count"]);
            if let Some(devices) = value.get("devices").and_then(Value::as_array) {
                for device in devices {
                    println!(
                        "device={} host={} port={}",
                        device.get("id").and_then(Value::as_str).unwrap_or(""),
                        device.get("host").and_then(Value::as_str).unwrap_or(""),
                        device.get("port").and_then(Value::as_u64).unwrap_or(4352),
                    );
                }
            }
            0
        }
        Err(err) => {
            eprintln!("caduceus-pjlink-devices-failed: {err}");
            1
        }
    }
}

pub fn power(device_id: &str, state: &str, rest: &[String]) -> i32 {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    match power_json(device_id, state, dry_run) {
        Ok(value) => {
            println!("schema={}", value["schema"].as_str().unwrap_or(""));
            println!("device_id={device_id}");
            println!("requested_state={state}");
            println!("mutation={}", value["mutation"]);
            println!("dry_run={}", value["dryRun"]);
            println!("ok={}", value["ok"]);
            println!(
                "first_missing_signal={}",
                value["firstMissingSignal"].as_str().unwrap_or("")
            );
            if value.get("ok").and_then(Value::as_bool) == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            println!("schema=caduceus.pjlink.power.v1");
            println!("device_id={device_id}");
            println!("requested_state={state}");
            println!("mutation=false");
            println!("dry_run={dry_run}");
            println!("ok=false");
            println!("first_missing_signal={err}");
            1
        }
    }
}

pub fn power_status(device_id: &str) -> i32 {
    match power_status_json(device_id) {
        Ok(value) => {
            println!("schema={}", value["schema"].as_str().unwrap_or(""));
            println!("device_id={device_id}");
            println!("ok={}", value["ok"]);
            println!(
                "first_missing_signal={}",
                value["firstMissingSignal"].as_str().unwrap_or("")
            );
            if let Some(response) = value.get("response").and_then(Value::as_str) {
                println!("response={response}");
            }
            if value.get("ok").and_then(Value::as_bool) == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            println!("schema=caduceus.pjlink.power-status.v1");
            println!("device_id={device_id}");
            println!("ok=false");
            println!("first_missing_signal={err}");
            1
        }
    }
}

pub(crate) fn import_catalog_at_serve_start() {
    // The importer owns its deed and stream fallback. Import errors keep reads
    // import-required; neither those nor an unavailable deed stop the listeners.
    let _ = catalog::import_legacy();
}

pub fn import_known_catalog() -> i32 {
    match catalog::import_legacy() {
        Ok((changed, signal)) => {
            println!("command=pjlink catalog import");
            println!("changed={changed}");
            println!("ok=true");
            println!("outcome={}", if changed { "applied" } else { "unchanged" });
            println!("signal={signal}");
            0
        }
        Err(error) => {
            eprintln!("caduceus-pjlink-catalog-import-failed: {error}");
            1
        }
    }
}

pub fn known_products() -> i32 {
    match known_products_json() {
        Ok(value) => {
            println!("schema=caduceus.pjlink.known-products.v1");
            println!("count={}", value["count"]);
            if let Some(entries) = value.get("entries").and_then(Value::as_array) {
                for entry in entries {
                    println!(
                        "entry={} device={} manufacturer={} product={}",
                        entry.get("id").and_then(Value::as_str).unwrap_or(""),
                        entry.get("deviceId").and_then(Value::as_str).unwrap_or(""),
                        entry
                            .get("manufacturer")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                        entry
                            .get("productName")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown"),
                    );
                }
            }
            0
        }
        Err(err) => {
            eprintln!("caduceus-pjlink-known-products-failed: {err}");
            1
        }
    }
}

pub fn scan_product(device_id: &str, rest: &[String]) -> i32 {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    match scan_product_json(device_id, dry_run) {
        Ok(value) => {
            println!("schema={}", value["schema"].as_str().unwrap_or(""));
            println!("device_id={device_id}");
            println!("dry_run={}", value["dryRun"]);
            println!("ok={}", value["ok"]);
            if let Some(product) = value.get("product") {
                println!(
                    "manufacturer={}",
                    product
                        .get("manufacturer")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                );
                println!(
                    "product={}",
                    product
                        .get("productName")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                );
            }
            println!(
                "first_missing_signal={}",
                value["firstMissingSignal"].as_str().unwrap_or("")
            );
            if value.get("ok").and_then(Value::as_bool) == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            println!("schema=caduceus.pjlink.product-scan.v1");
            println!("device_id={device_id}");
            println!("ok=false");
            println!("first_missing_signal={err}");
            1
        }
    }
}

pub fn add_known_product(device_id: &str, rest: &[String]) -> i32 {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let from_profile = rest.iter().any(|arg| arg == "--from-profile");
    match add_known_product_json(device_id, dry_run, from_profile) {
        Ok(value) => {
            println!("schema={}", value["schema"].as_str().unwrap_or(""));
            println!("device_id={device_id}");
            println!("mutation={}", value["mutation"]);
            println!("dry_run={}", value["dryRun"]);
            if let Some(entry) = value.get("entry") {
                println!(
                    "entry={}",
                    entry.get("id").and_then(Value::as_str).unwrap_or("")
                );
            }
            println!("ok={}", value["ok"]);
            println!(
                "first_missing_signal={}",
                value["firstMissingSignal"].as_str().unwrap_or("")
            );
            if value.get("ok").and_then(Value::as_bool) == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            println!("schema=caduceus.pjlink.known-product.add.v1");
            println!("device_id={device_id}");
            println!("ok=false");
            println!("first_missing_signal={err}");
            1
        }
    }
}

pub fn remove_known_product(entry_id: &str) -> i32 {
    match remove_known_product_json(entry_id) {
        Ok(value) => {
            println!("schema=caduceus.pjlink.known-product.remove.v1");
            println!("id={entry_id}");
            println!("mutation={}", value["mutation"]);
            println!("removed={}", value["removed"]);
            println!("ok={}", value["ok"]);
            println!(
                "first_missing_signal={}",
                value["firstMissingSignal"].as_str().unwrap_or("")
            );
            0
        }
        Err(err) => {
            println!("schema=caduceus.pjlink.known-product.remove.v1");
            println!("id={entry_id}");
            println!("ok=false");
            println!("first_missing_signal={err}");
            1
        }
    }
}
