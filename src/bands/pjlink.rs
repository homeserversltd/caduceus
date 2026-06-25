use crate::tools::{config, pjlink, receipts};
use serde_json::{json, Value};

fn profile() -> Result<Value, String> {
    config::read_public_profile_value()
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
