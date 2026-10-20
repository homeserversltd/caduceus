use chrono::Utc;
use serde_json::{json, Value};
use std::{
    ffi::CString,
    path::{Path, PathBuf},
    time::Duration,
};

const MIB: u128 = 1024 * 1024;
const CPU_FAILED: &str = "face-meter-cpu-observation-failed";
const CPU_INVALID: &str = "face-meter-cpu-observation-invalid";
const RAM_COMMAND_FAILED: &str = "face-meter-ram-command-failed";
const RAM_INVALID: &str = "face-meter-ram-observation-invalid";
const RAM_TOTAL_INVALID: &str = "face-meter-ram-total-invalid";
const DISK_COMMAND_FAILED: &str = "face-meter-disk-command-failed";
const DISK_INVALID: &str = "face-meter-disk-observation-invalid";
const DISK_TOTAL_INVALID: &str = "face-meter-disk-total-invalid";

pub async fn read_meter(envelope: &Value) -> Value {
    let result = meter(envelope).await;
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

async fn meter(envelope: &Value) -> Result<Value, &'static str> {
    let kind = envelope
        .get("payload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("kind"))
        .and_then(Value::as_str)
        .filter(|kind| !kind.is_empty())
        .ok_or("face-meter-kind-required")?;

    match kind {
        "cpu" => {
            let percent = cpu_percent().await?;
            let value = json_integer(percent, CPU_INVALID)?;
            Ok(success(
                format!("CPU {}", bars(percent)),
                format!("CPU: {percent}%"),
                class_for(percent),
                value,
            ))
        }
        "ram" => {
            let (total, used) = memory_values().await?;
            if total <= 0 {
                return Err(RAM_TOTAL_INVALID);
            }
            let percent = used.checked_mul(100).ok_or(RAM_INVALID)?.div_euclid(total);
            let value = json_integer(percent, RAM_INVALID)?;
            Ok(success(
                format!("RAM {}", bars(percent)),
                format!("RAM: {percent}% ({used}/{total} MiB)"),
                class_for(percent),
                value,
            ))
        }
        "disk" => {
            let (used, total, percent) = disk_values().await?;
            if total <= 0 {
                return Err(DISK_TOTAL_INVALID);
            }
            let percent_json = json_integer(percent, DISK_INVALID)?;
            Ok(success(
                format!("DSK {}", bars(percent)),
                format!("Disk /: {percent}% ({used}/{total} MiB)"),
                class_for(percent),
                percent_json,
            ))
        }
        "temp" => match temperature_celsius().await {
            None => Ok(json!({
                "ok": true,
                "firstMissingSignal": "none",
                "text": "TMP ????",
                "tooltip": "No temperature sensor found",
                "class": "high",
                "value": Value::Null
            })),
            Some(celsius) => {
                let percent = celsius
                    .checked_sub(30)
                    .and_then(|delta| delta.checked_mul(100))
                    .ok_or("face-meter-temp-observation-invalid")?
                    .div_euclid(70)
                    .clamp(0, 100);
                let value = json_integer(celsius, "face-meter-temp-observation-invalid")?;
                let class = if celsius >= 90 {
                    "high"
                } else if celsius >= 75 {
                    "medium"
                } else {
                    "low"
                };
                Ok(success(
                    format!("TMP {}", bars(percent)),
                    format!("CPU package temperature: {celsius}°C"),
                    class,
                    value,
                ))
            }
        },
        _ => Err("face-meter-kind-invalid"),
    }
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

fn json_integer(value: i128, signal: &'static str) -> Result<Value, &'static str> {
    i64::try_from(value)
        .map(|value| json!(value))
        .map_err(|_| signal)
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

async fn cpu_percent() -> Result<i128, &'static str> {
    let (total1, idle1) = cpu_sample().await?;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let (total2, idle2) = cpu_sample().await?;
    let delta_total = total2.checked_sub(total1).ok_or(CPU_INVALID)?;
    let delta_idle = idle2.checked_sub(idle1).ok_or(CPU_INVALID)?;
    if delta_total <= 0 {
        return Ok(0);
    }
    delta_total
        .checked_sub(delta_idle)
        .and_then(|busy| busy.checked_mul(100))
        .map(|busy| busy.div_euclid(delta_total))
        .ok_or(CPU_INVALID)
}

async fn cpu_sample() -> Result<(i128, i128), &'static str> {
    let text = tokio::fs::read_to_string("/proc/stat")
        .await
        .map_err(|_| CPU_FAILED)?;
    let line = text.lines().next().ok_or(CPU_FAILED)?;
    let mut values = Vec::with_capacity(8);
    for field in line.split_whitespace().skip(1).take(8) {
        values.push(field.parse::<i128>().map_err(|_| CPU_FAILED)?);
    }
    if values.len() != 8 {
        return Err(CPU_INVALID);
    }
    let total = values
        .iter()
        .try_fold(0_i128, |sum, value| sum.checked_add(*value))
        .ok_or(CPU_INVALID)?;
    let idle = values[3].checked_add(values[4]).ok_or(CPU_INVALID)?;
    Ok((total, idle))
}

async fn memory_values() -> Result<(i128, i128), &'static str> {
    let text = tokio::fs::read_to_string("/proc/meminfo")
        .await
        .map_err(|_| RAM_COMMAND_FAILED)?;
    let mut total_kib = None;
    let mut available_kib = None;
    for line in text.lines() {
        let Some((key, raw_values)) = line.split_once(':') else {
            continue;
        };
        let is_total = match key {
            "MemTotal" if total_kib.is_none() => true,
            "MemAvailable" if available_kib.is_none() => false,
            _ => continue,
        };
        let mut values = raw_values.split_whitespace();
        let value = values.next().ok_or(RAM_INVALID)?;
        let unit = values.next().ok_or(RAM_INVALID)?;
        if unit != "kB" {
            return Err(RAM_INVALID);
        }
        let value = value.parse::<i128>().map_err(|_| RAM_INVALID)?;
        if is_total {
            total_kib = Some(value);
        } else {
            available_kib = Some(value);
        }
    }
    let total_kib = total_kib.ok_or(RAM_INVALID)?;
    let available_kib = available_kib.ok_or(RAM_INVALID)?;
    let total = total_kib.div_euclid(1024);
    let used = total_kib
        .checked_sub(available_kib)
        .ok_or(RAM_INVALID)?
        .max(0)
        .div_euclid(1024);
    Ok((total, used))
}

async fn disk_values() -> Result<(i128, i128, i128), &'static str> {
    tokio::task::spawn_blocking(statvfs_values)
        .await
        .map_err(|_| DISK_COMMAND_FAILED)?
}

fn statvfs_values() -> Result<(i128, i128, i128), &'static str> {
    let root = CString::new("/").expect("root path has no NUL");
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(root.as_ptr(), &mut stats) } != 0 {
        return Err(DISK_COMMAND_FAILED);
    }
    let block_size = if stats.f_frsize == 0 {
        stats.f_bsize as u128
    } else {
        stats.f_frsize as u128
    };
    if block_size == 0 {
        return Err(DISK_INVALID);
    }
    let blocks = stats.f_blocks as u128;
    let free_blocks = stats.f_bfree as u128;
    let available_blocks = stats.f_bavail as u128;
    if free_blocks > blocks {
        return Err(DISK_INVALID);
    }
    let used_blocks = blocks - free_blocks;
    let total_bytes = blocks.checked_mul(block_size).ok_or(DISK_INVALID)?;
    let used_bytes = used_blocks.checked_mul(block_size).ok_or(DISK_INVALID)?;
    let total_mib = ceil_div(total_bytes, MIB).ok_or(DISK_INVALID)?;
    let used_mib = ceil_div(used_bytes, MIB).ok_or(DISK_INVALID)?;
    let denominator = used_blocks
        .checked_add(available_blocks)
        .ok_or(DISK_INVALID)?;
    let percent = if denominator == 0 {
        100
    } else {
        used_blocks
            .checked_mul(100)
            .and_then(|value| value.checked_add(denominator - 1))
            .ok_or(DISK_INVALID)?
            / denominator
    };
    Ok((
        i128::try_from(used_mib).map_err(|_| DISK_INVALID)?,
        i128::try_from(total_mib).map_err(|_| DISK_INVALID)?,
        i128::try_from(percent).map_err(|_| DISK_INVALID)?,
    ))
}

fn ceil_div(value: u128, divisor: u128) -> Option<u128> {
    let quotient = value / divisor;
    if value % divisor == 0 {
        Some(quotient)
    } else {
        quotient.checked_add(1)
    }
}

async fn temperature_celsius() -> Option<i128> {
    let hwmon = entries_matching(Path::new("/sys/class/hwmon"), "hwmon", None).await;
    for sensor in hwmon {
        if read_utf8_trimmed(&sensor.join("name")).await.as_deref() != Some("coretemp") {
            continue;
        }
        let labels = entries_matching(&sensor, "temp", Some("_label")).await;
        for label in labels {
            if read_utf8_trimmed(&label).await.as_deref() != Some("Package id 0") {
                continue;
            }
            let Some(name) = label.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix("_label") else {
                continue;
            };
            let input = label.with_file_name(format!("{stem}_input"));
            if let Some(raw) = read_ascii_integer(&input).await {
                if let Some(celsius) = round_millidegrees(raw) {
                    return Some(celsius);
                }
            }
        }
        if let Some(raw) = read_ascii_integer(&sensor.join("temp1_input")).await {
            if let Some(celsius) = round_millidegrees(raw) {
                return Some(celsius);
            }
        }
    }

    let zones = entries_matching(Path::new("/sys/class/thermal"), "thermal_zone", None).await;
    for zone in zones {
        let Some(kind) = read_utf8_trimmed(&zone.join("type")).await else {
            continue;
        };
        if kind != "x86_pkg_temp" && kind != "acpitz" {
            continue;
        }
        if let Some(raw) = read_ascii_integer(&zone.join("temp")).await {
            if let Some(celsius) = round_millidegrees(raw) {
                return Some(celsius);
            }
        }
    }
    None
}

async fn entries_matching(directory: &Path, prefix: &str, suffix: Option<&str>) -> Vec<PathBuf> {
    let Ok(mut reader) = tokio::fs::read_dir(directory).await else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    loop {
        let entry = match reader.next_entry().await {
            Ok(Some(entry)) => entry,
            Ok(None) | Err(_) => break,
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(prefix) && suffix.map_or(true, |suffix| name.ends_with(suffix)) {
            entries.push(entry.path());
        }
    }
    entries.sort_by_key(|path| {
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    });
    entries
}

async fn read_utf8_trimmed(path: &Path) -> Option<String> {
    tokio::fs::read_to_string(path)
        .await
        .ok()
        .map(|text| text.trim().to_owned())
}

async fn read_ascii_integer(path: &Path) -> Option<i128> {
    let text = tokio::fs::read_to_string(path).await.ok()?;
    if !text.is_ascii() {
        return None;
    }
    text.trim().parse::<i128>().ok()
}

fn round_millidegrees(raw: i128) -> Option<i128> {
    raw.checked_add(500).map(|value| value.div_euclid(1000))
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
