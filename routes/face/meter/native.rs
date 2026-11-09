use chrono::Utc;
use serde_json::{json, Value};

const MIB: u64 = 1024 * 1024;

pub async fn read_meter(envelope: &Value) -> Value {
    let result = meter(envelope);
    let mut receipt = match result {
        Ok(receipt) => receipt,
        Err(signal) => json!({
            "ok": false,
            "firstMissingSignal": signal
        }),
    };
    if let Some(fields) = receipt.as_object_mut() {
        fields.insert("verb".into(), json!("meter"));
        fields.insert("host".into(), json!(hostname()));
        fields.insert("timestamp".into(), json!(now_iso()));
    }
    receipt
}

fn meter(envelope: &Value) -> Result<Value, &'static str> {
    let kind = envelope
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("kind"))
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty())
        .ok_or("face-meter-kind-required")?;
    let (label, missing) = match kind {
        "cpu" => ("CPU", "CPU usage is missing from the sample"),
        "ram" => ("RAM", "Memory usage or total is missing from the sample"),
        "disk" => ("DSK", "Root disk usage or total is missing from the sample"),
        "temp" => ("TMP", "CPU temperature is missing from the sample"),
        "gpu" => ("GPU", "GPU utilization is missing from the sample"),
        _ => return Err("face-meter-kind-invalid"),
    };
    let device = if kind == "gpu" {
        match envelope.get("payload").and_then(|payload| payload.get("device")) {
            None => 0,
            Some(value) => value.as_u64().ok_or("face-meter-device-invalid")?,
        }
    } else {
        0
    };
    let sample = crate::stats::current()
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
    if kind == "gpu" {
        return Ok(gpu_meter(sample.as_ref(), device));
    }
    let Some(sample) = sample else {
        return Ok(unknown(label, "No current statistics sample"));
    };
    let reading = match kind {
        "cpu" => number(&sample, "/cpu/usagePercent").map(|pct| {
            let pct = pct.round() as i128;
            success(
                format!("CPU {}", bars(pct)),
                format!("CPU: {pct}%"),
                class_for(pct),
                json!(pct as i64),
            )
        }),
        "ram" => byte_usage(&sample["memory"]).map(|(used, total, pct)| {
            success(
                format!("RAM {}", bars(pct)),
                format!("RAM: {pct}% ({}/{} MiB)", used / MIB, total / MIB),
                class_for(pct),
                json!(pct as i64),
            )
        }),
        "disk" => sample
            .pointer("/disk/usage")
            .and_then(Value::as_array)
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.get("path").and_then(Value::as_str) == Some("/"))
            })
            .and_then(|entry| byte_usage(entry))
            .map(|(used, total, pct)| {
                success(
                    format!("DSK {}", bars(pct)),
                    format!("Disk /: {pct}% ({}/{} MiB)", used / MIB, total / MIB),
                    class_for(pct),
                    json!(pct as i64),
                )
            }),
        "temp" => sample
            .pointer("/temperature/bySource")
            .and_then(Value::as_array)
            .and_then(|entries| {
                entries
                    .iter()
                    .filter_map(|entry| {
                        if entry.get("label").and_then(Value::as_str) != Some("cpu") {
                            return None;
                        }
                        number(entry, "/celsius").map(|temp| (temp, entry))
                    })
                    .max_by(|a, b| a.0.total_cmp(&b.0))
            })
            .map(|(temp, entry)| {
                let celsius = temp.round() as i128;
                let pct = ((celsius - 30) * 100).div_euclid(70).clamp(0, 100);
                let class = if temp >= 90.0 {
                    "high"
                } else if temp >= 75.0 {
                    "medium"
                } else {
                    "low"
                };
                let sensor = entry
                    .get("sensor")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("CPU sensor");
                success(
                    format!("TMP {}", bars(pct)),
                    format!("CPU package temperature ({sensor}): {celsius}°C"),
                    class,
                    json!(celsius as i64),
                )
            }),
        _ => unreachable!(),
    };
    Ok(reading.unwrap_or_else(|| unknown(label, missing)))
}

fn gpu_meter(sample: Option<&Value>, device: u64) -> Value {
    let label = if device == 0 {
        "GPU".to_owned()
    } else {
        format!("GPU{}", u128::from(device) + 1)
    };
    let row = sample
        .and_then(|sample| sample.pointer("/gpu/devices"))
        .and_then(Value::as_array)
        .and_then(|devices| usize::try_from(device).ok().and_then(|index| devices.get(index)));
    let Some(row) = row else {
        return if device == 0 {
            unknown(&label, "GPU utilization is missing from the sample")
        } else {
            success(String::new(), String::new(), "absent", Value::Null)
        };
    };
    let Some(pct) = number(row, "/utilizationPercent") else {
        return unknown(&label, "GPU utilization is missing from the sample");
    };
    let pct = pct.round() as i128;
    let id = row.get("id").and_then(Value::as_str).unwrap_or("unknown");
    let mut tooltip = format!("{label}: {id} {pct}%");
    if let Some(temp) = number(row, "/temperatureCelsius") {
        tooltip.push_str(&format!(" · {}°C", temp.round() as i64));
    }
    success(
        format!("{label} {}", bars(pct)),
        tooltip,
        class_for(pct),
        json!(pct as i64),
    )
}

fn number(value: &Value, pointer: &str) -> Option<f64> {
    value
        .pointer(pointer)?
        .as_f64()
        .filter(|value| value.is_finite())
}

fn byte_usage(value: &Value) -> Option<(u64, u64, i128)> {
    let used = value.get("usedBytes")?.as_u64()?;
    let total = value
        .get("MemTotal")
        .or_else(|| value.get("totalBytes"))?
        .as_u64()?;
    if total == 0 {
        return None;
    }
    let percent = (u128::from(used) * 100 / u128::from(total)) as i128;
    Some((used, total, percent))
}

fn unknown(label: &str, tooltip: &str) -> Value {
    success(
        format!("{label} ????"),
        tooltip.to_owned(),
        "unknown",
        Value::Null,
    )
}

fn success(text: String, tooltip: String, class: &str, value: Value) -> Value {
    json!({
        "ok": true,
        "firstMissingSignal": "none",
        "text": text,
        "tooltip": tooltip,
        "class": class,
        "value": value
    })
}

fn bars(percent: i128) -> String {
    let filled = ((percent + 24).div_euclid(25)).clamp(0, 4) as usize;
    format!("{}{}", "▰".repeat(filled), "▱".repeat(4 - filled))
}

fn class_for(percent: i128) -> &'static str {
    if percent >= 85 {
        "high"
    } else if percent >= 60 {
        "medium"
    } else {
        "low"
    }
}

fn hostname() -> String {
    let mut bytes = vec![0_u8; 256];
    let result =
        unsafe { libc::gethostname(bytes.as_mut_ptr().cast::<libc::c_char>(), bytes.len()) };
    if result != 0 {
        return String::new();
    }
    if let Some(end) = bytes.iter().position(|byte| *byte == 0) {
        bytes.truncate(end);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

fn now_iso() -> String {
    let now = Utc::now();
    let seconds = now.format("%Y-%m-%dT%H:%M:%S");
    let micros = now.timestamp_subsec_micros();
    if micros == 0 {
        format!("{seconds}Z")
    } else {
        format!("{seconds}.{micros:06}Z")
    }
}
