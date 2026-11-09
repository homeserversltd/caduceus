//! Rev-selected thermal and GPU observations. No device is inferred from a probe.
use super::*;

#[derive(Default)]
pub(super) struct HardwareCache {
    rev: Option<String>,
    nvidia: BTreeMap<String, (Instant, Option<NvidiaGpuCache>)>,
    rc6: BTreeMap<String, (Instant, u64)>,
}

fn matches_device(device: &PathBuf, spec: &Value) -> bool {
    let Some(vendor) = spec.get("vendor").and_then(Value::as_str) else { return false };
    if clean_optional_text(&device.join("vendor")).as_deref() != Some(vendor) { return false; }
    match spec.get("card_match").and_then(Value::as_str) {
        Some(selector) if selector.starts_with("pci:") => fs::canonicalize(device).ok()
            .and_then(|path| path.file_name().map(|name| name.to_string_lossy().to_ascii_lowercase()))
            .as_deref() == Some(&selector[4..].to_ascii_lowercase()),
        Some(selector) if selector.starts_with("vendor:") => &selector[7..] == vendor,
        _ => false,
    }
}

fn sysfs_device(spec: &Value) -> Option<PathBuf> {
    let mut matches = Vec::new();
    for entry in fs::read_dir("/sys/class/drm").ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.strip_prefix("card").map_or(false, |number| !number.is_empty() && number.bytes().all(|c| c.is_ascii_digit())) { continue; }
        let path = entry.path().join("device");
        if matches_device(&path, spec) { matches.push(path); }
    }
    // A vendor-only selector must not silently select one of multiple devices.
    if matches.len() == 1 { matches.pop() } else { None }
}

fn selected_hwmon_sources(dir: &PathBuf, driver: &str, labels: &[String], category: &'static str) -> Vec<TemperatureSource> {
    let mut sources = Vec::new();
    for entry in fs::read_dir(dir).ok().into_iter().flatten().flatten() {
        let hwmon = entry.path();
        if clean_optional_text(&hwmon.join("name")).as_deref() != Some(driver) { continue; }
        for file in fs::read_dir(&hwmon).ok().into_iter().flatten().flatten() {
            let filename = file.file_name().to_string_lossy().into_owned();
            let Some(channel) = indexed_input(&filename, "temp") else { continue };
            let path = file.path();
            let sensor_label = clean_optional_text(&path.with_file_name(format!("{channel}_label")));
            if !labels.iter().any(|label| sensor_label.as_deref() == Some(label.as_str())) { continue; }
            let metadata = SensorMetadata { source: input_identity(&path), name: Some(driver.to_owned()), sensor_label, channel: channel.clone(), label: category };
            sources.push(TemperatureSource { validity_base: Some(path.with_file_name(channel.clone())), milli_celsius: temperature_unit_is_milli_celsius(Some(driver), &channel), path, metadata });
        }
    }
    sources
}

fn sysfs_fan_percent(device: &PathBuf) -> Option<f64> {
    for entry in fs::read_dir(device.join("hwmon")).ok()?.flatten() {
        for file in fs::read_dir(entry.path()).ok().into_iter().flatten().flatten() {
            let filename = file.file_name().to_string_lossy().into_owned();
            let Some(channel) = filename.strip_suffix("_max") else { continue };
            if !channel.strip_prefix("pwm").map_or(false, |n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())) { continue; }
            let Ok(maximum) = read_numeric(&file.path()) else { continue };
            let Ok(value) = read_numeric(&file.path().with_file_name(channel)) else { continue };
            if maximum > 0.0 && value >= 0.0 && value <= maximum { return Some(value * 100.0 / maximum); }
        }
    }
    None
}

fn nvidia_at(pci: &str) -> Option<NvidiaGpuCache> {
    let mut command = Command::new("nvidia-smi");
    command.args(["-i", pci, "--query-gpu=uuid,utilization.gpu,temperature.gpu,fan.speed,memory.used,memory.total", "--format=csv,noheader,nounits"])
        .stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().ok()?;
    let status = match crate::shared::child_wait::until(&mut child, Instant::now() + Duration::from_millis(900)).ok()? {
        Some(status) => status,
        None => { let _ = child.kill(); let _ = child.wait(); return None; }
    };
    if !status.success() { return None; }
    let mut output = String::new();
    child.stdout.take()?.read_to_string(&mut output).ok()?;
    if output.lines().filter(|line| !line.trim().is_empty()).count() != 1 { return None; }
    Some(nvidia_gpu_output(&output))
}

fn labels(spec: &Value, key: &str) -> Vec<String> {
    spec.get(key).and_then(Value::as_array).into_iter().flatten()
        .filter_map(Value::as_str).map(str::to_owned).collect()
}

/// Select the entire winning device row; never combine keys across devices.
fn busiest(devices: &[Value]) -> Option<serde_json::Map<String, Value>> {
    devices.iter().filter_map(|device| {
        let load = device.get("utilizationPercent")?.as_f64()?;
        load.is_finite().then_some((load, device))
    }).max_by(|left, right| left.0.total_cmp(&right.0))
      .and_then(|(_, device)| device.as_object().cloned())
}

pub(super) fn collect(cache: &mut HardwareCache, hardware: Option<&Value>) -> (Value, Value, Vec<Value>, Option<i64>) {
    let rev = hardware.and_then(|value| value.get("rev")).and_then(Value::as_str).map(str::to_owned);
    if cache.rev != rev { cache.nvidia.clear(); cache.rc6.clear(); cache.rev = rev; }
    let Some(hardware) = hardware else { return (Value::Null, Value::Null, Vec::new(), None) };
    let mut readings = Vec::new();
    let mut unavailable = Vec::new();
    for sensor in hardware.get("cpu_temperature").and_then(Value::as_array).into_iter().flatten() {
        let (Some(driver), Some(label)) = (sensor.get("hwmon_name").and_then(Value::as_str), sensor.get("label").and_then(Value::as_str)) else { continue };
        let sources = selected_hwmon_sources(&PathBuf::from("/sys/class/hwmon"), driver, &[label.to_owned()], "cpu");
        let (good, bad) = read_temperature_sources(&sources, false);
        readings.extend(good); unavailable.extend(bad);
    }
    let mut devices = Vec::new();
    let mut fans_unavailable = Vec::new();
    let mut gpu_ts = None;
    for spec in hardware.get("gpus").and_then(Value::as_array).into_iter().flatten() {
        let (Some(id), Some(vendor), Some(source)) = (spec.get("id").and_then(Value::as_str), spec.get("vendor").and_then(Value::as_str), spec.get("source").and_then(Value::as_str)) else { continue };
        let mut row = serde_json::Map::new();
        row.insert("id".into(), json!(id)); row.insert("vendor".into(), json!(vendor));
        match source {
            "i915-rc6" => {
                let Some(device) = sysfs_device(spec) else { devices.push(Value::Object(row)); continue };
                // sysfs_device returns cardN/device, not the resolved PCI path.
                let Some(card) = device.parent() else { devices.push(Value::Object(row)); continue };
                if let Some(rc6_ms) = clean_optional_text(&card.join("gt/gt0/rc6_residency_ms")).and_then(|value| value.parse::<u64>().ok()) {
                    let now = Instant::now();
                    if let Some((previous, previous_ms)) = cache.rc6.insert(id.to_owned(), (now, rc6_ms)) {
                        let wall_ms = now.duration_since(previous).as_secs_f64() * 1000.0;
                        if let Some(delta) = rc6_ms.checked_sub(previous_ms) {
                            if wall_ms > 0.0 {
                                let busy = (100.0 - 100.0 * delta as f64 / wall_ms).clamp(0.0, 100.0).round() as u64;
                                row.insert("utilizationPercent".into(), json!(busy));
                            }
                        }
                    }
                }
            }
            "drm-sysfs" => {
                let Some(device) = sysfs_device(spec) else { devices.push(Value::Object(row)); continue };
                for (file, key) in [("gpu_busy_percent", "utilizationPercent"), ("mem_info_vram_used", "memoryUsedBytes"), ("mem_info_vram_total", "memoryTotalBytes")] {
                    if let Some(value) = clean_optional_text(&device.join(file)).and_then(|value| value.parse::<u64>().ok()) { row.insert(key.into(), json!(value)); }
                }
                if let Some(percent) = sysfs_fan_percent(&device) { row.insert("fanPercent".into(), json!(percent)); }
                let sources = selected_hwmon_sources(&device.join("hwmon"), "amdgpu", &labels(spec, "temperature_labels"), "gpu");
                let (good, bad) = read_temperature_sources(&sources, false);
                // Prefer the edge sensor where available; otherwise use a named source.
                let temperature = good.iter().find(|reading| reading.metadata.sensor_label.as_deref() == Some("edge")).or_else(|| good.first());
                if let Some(reading) = temperature { row.insert("temperatureCelsius".into(), json!(reading.celsius)); }
                readings.extend(good); unavailable.extend(bad);
            }
            "nvidia-smi" => {
                let Some(pci) = spec.get("card_match").and_then(Value::as_str).and_then(|s| s.strip_prefix("pci:")) else { devices.push(Value::Object(row)); continue };
                let needs_refresh = cache.nvidia.get(id).map_or(true, |(instant, _)| instant.elapsed() >= Duration::from_secs(60));
                if needs_refresh {
                    // Record failures too, so a failed command cannot spawn at 1 Hz.
                    cache.nvidia.insert(id.to_owned(), (Instant::now(), nvidia_at(pci)));
                }
                if let Some((_, Some(sample))) = cache.nvidia.get(id) {
                    row.extend(sample.metrics.clone());
                    if let Some(reading) = sample.temperatures.first() { row.insert("temperatureCelsius".into(), json!(reading.celsius)); }
                    readings.extend(sample.temperatures.iter().cloned());
                    unavailable.extend(sample.temperature_unavailable.iter().cloned());
                    fans_unavailable.extend(sample.fans_unavailable.iter().cloned());
                    gpu_ts = Some(sample.sampled_at);
                }
            }
            _ => {}
        }
        devices.push(Value::Object(row));
    }
    readings.sort_by(|left, right| left.metadata.source.cmp(&right.metadata.source));
    unavailable.sort_by(|left, right| left.metadata.source.cmp(&right.metadata.source));
    let temperature = if readings.is_empty() && unavailable.is_empty() { Value::Null } else {
        let mean = if readings.is_empty() { Value::Null } else { json!(readings.iter().map(|r| r.celsius).sum::<f64>() / readings.len() as f64) };
        json!({"celsius": mean, "sources": readings.len(), "bySource": readings.iter().map(temperature_reading_value).collect::<Vec<_>>(), "unavailableSources": unavailable.iter().map(unavailable_reading_value).collect::<Vec<_>>()})
    };
    let gpu = if devices.is_empty() { Value::Null } else {
        let mut out = busiest(&devices).unwrap_or_default();
        out.insert("devices".into(), json!(devices));
        Value::Object(out)
    };
    (temperature, gpu, fans_unavailable, gpu_ts)
}
