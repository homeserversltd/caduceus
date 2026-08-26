//! Bounded native maintenance for the appliance journal and log channel.

use crate::shared::{config, hyalos::CHANNEL_PATH};
use chrono::{TimeZone, Utc};
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::{interval, Duration};

const LOG_LIMIT: u64 = 200 * 1024 * 1024;
const RECEIPT_DIR: &str = "var/lib/caduceus/receipts";
static STARTED: OnceLock<()> = OnceLock::new();
static RECEIPT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn start() {
    if STARTED.set(()).is_err() {
        return;
    }
    tokio::spawn(async {
        let mut ticker = interval(Duration::from_secs(15 * 60));
        loop {
            ticker.tick().await;
            match tokio::task::spawn_blocking(maintenance_tick).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!(
                    "caduceus-maintenance-tick-failed: {}",
                    bounded_error(&error)
                ),
                Err(error) => eprintln!(
                    "caduceus-maintenance-tick-failed: {}",
                    bounded_error(&error.to_string())
                ),
            }
        }
    });
}

fn maintenance_tick() -> Result<(), String> {
    let mut errors = Vec::new();

    match vacuum_journal() {
        Ok(freed) if freed > 0 => {
            if let Err(error) = write_receipt(&json!({
                "schema": "caduceus.log-maintenance.v1",
                "event": "journal-vacuum",
                "ok": true,
                "freed_bytes": freed,
            })) {
                errors.push(format!("journal-vacuum receipt: {error}"));
            }
        }
        Ok(_) => {}
        Err(error) => errors.push(format!("journal-vacuum: {error}")),
    }

    if let Err(error) = maintain_appliance_log_with_limit(LOG_LIMIT) {
        errors.push(format!("appliance-log rotation: {error}"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(bounded_error(&errors.join("; ")))
    }
}

fn vacuum_journal() -> Result<u64, String> {
    let output = Command::new("journalctl")
        .arg("--vacuum-size=300M")
        .env("LC_ALL", "C")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("journalctl invocation: {error}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        return Err(format!("journalctl exited {}", output.status));
    }
    Ok(parse_freed(&text))
}

fn parse_freed(text: &str) -> u64 {
    let lower = text.to_ascii_lowercase();
    let mut total = 0u64;
    for start in lower.match_indices("freed ").map(|(index, _)| index) {
        let token = lower[start + 6..].split_whitespace().next().unwrap_or("");
        let split_at = token
            .char_indices()
            .find(|(_, character)| !character.is_ascii_digit() && *character != '.')
            .map(|(index, _)| index)
            .unwrap_or(token.len());
        let (number_text, unit_text) = token.split_at(split_at);
        let multiplier = match unit_text {
            "b" => 1.0,
            "k" => 1024.0,
            "m" => 1024.0 * 1024.0,
            "g" => 1024.0 * 1024.0 * 1024.0,
            _ => continue,
        };
        let number = number_text.parse::<f64>().unwrap_or(0.0);
        if number.is_finite() && number > 0.0 {
            total = total.saturating_add((number * multiplier) as u64);
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::parse_freed;

    #[test]
    fn parse_freed_sums_all_vacuum_lines() {
        assert_eq!(
            parse_freed(
                "Vacuuming done, freed 1.5M of archived journals.\nVacuuming done, freed 2K"
            ),
            1_574_912
        );
    }

    #[test]
    fn parse_freed_returns_zero_for_malformed_or_missing_values() {
        assert_eq!(
            parse_freed("Vacuuming done, freed nonsense\nother output"),
            0
        );
        assert_eq!(parse_freed("journal vacuum completed"), 0);
    }
}

pub fn maintain_appliance_log_with_limit(limit: u64) -> Result<Value, String> {
    let path = config::path(CHANNEL_PATH);
    let size = match fs::metadata(&path) {
        Ok(metadata) => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(json!({"rotated": false}));
        }
        Err(error) => return Err(error.to_string()),
    };
    if size <= limit {
        return Ok(json!({"rotated": false, "fileSize": size}));
    }
    let parent = path
        .parent()
        .ok_or_else(|| "appliance-log-parent-missing".to_string())?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let stamp = now_nanos();
    let generation = next_generation(parent, stamp);
    let name = generation
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let temporary = parent.join(format!(".appliance.log.{stamp}.tmp"));
    if let Err(e) = write_gzip(&temporary, &path) {
        let _ = fs::remove_file(&temporary);
        return Err(e.to_string());
    }
    if let Err(e) = fs::rename(&temporary, &generation) {
        let _ = fs::remove_file(&temporary);
        return Err(e.to_string());
    }
    if let Err(e) = OpenOptions::new().write(true).truncate(true).open(&path) {
        let _ = write_receipt(
            &json!({"schema":"caduceus.log-maintenance.v1","event":"rotation","ok":false,"mutation":"archive-renamed","generation":name,"error":bounded_error(&e.to_string())}),
        );
        return Err(e.to_string());
    }
    if let Err(error) = remove_older_generations(parent, &name) {
        let cleanup_error = bounded_error(&error);
        let receipt_error = write_receipt(&json!({
            "schema": "caduceus.log-maintenance.v1",
            "event": "rotation",
            "ok": false,
            "mutation": "archive-renamed-and-truncated",
            "generation": name,
            "error": cleanup_error,
        }))
        .err();
        return Err(match receipt_error {
            Some(receipt_error) => {
                bounded_error(&format!("{error}; failure receipt: {receipt_error}"))
            }
            None => error,
        });
    }
    let result = json!({
        "rotated": true,
        "fileSize": size,
        "generation": name,
        "rotationTimestamp": timestamp_for(stamp),
    });
    write_receipt(&json!({
        "schema": "caduceus.log-maintenance.v1",
        "event": "rotation",
        "ok": true,
        "generation": result["generation"],
        "rotation_timestamp": result["rotationTimestamp"],
        "file_size": size,
    }))?;
    Ok(result)
}

fn next_generation(parent: &Path, stamp: u128) -> PathBuf {
    let mut number = stamp;
    loop {
        let path = parent.join(format!("appliance.log.{number}.1.gz"));
        if !path.exists() {
            return path;
        }
        number += 1;
    }
}
fn generation_timestamp(name: &str) -> Option<u128> {
    name.strip_prefix("appliance.log.")?
        .strip_suffix(".1.gz")?
        .parse()
        .ok()
}
fn remove_older_generations(parent: &Path, current: &str) -> Result<(), String> {
    if generation_timestamp(current).is_none() {
        return Err("invalid-current-generation-name".to_string());
    }
    let entries = fs::read_dir(parent).map_err(|error| error.to_string())?;
    let mut errors = Vec::new();

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                errors.push(error.to_string());
                continue;
            }
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let is_older = name != current
            && name.starts_with("appliance.log.")
            && name.ends_with(".1.gz")
            && generation_timestamp(&name).is_some();
        if is_older {
            if let Err(error) = fs::remove_file(entry.path()) {
                errors.push(format!("{name}: {error}"));
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(bounded_error(&errors.join("; ")))
    }
}
fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
fn timestamp_for(stamp: u128) -> String {
    let seconds = (stamp / 1_000_000_000) as i64;
    let nanos = (stamp % 1_000_000_000) as u32;
    Utc.timestamp_opt(seconds, nanos)
        .single()
        .map(|value| value.to_rfc3339())
        .unwrap_or_else(|| stamp.to_string())
}
fn write_gzip(path: &Path, source: &Path) -> io::Result<()> {
    let input = File::open(source)?;
    let output = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    let mut input = io::BufReader::new(input);
    io::copy(&mut input, &mut encoder)?;
    let mut output = encoder.finish()?;
    output.flush()?;
    output.sync_all()
}
fn write_receipt(body: &Value) -> Result<(), String> {
    let dir = config::path(RECEIPT_DIR);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let sequence = RECEIPT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("log-maintenance-{}-{sequence}.json", now_nanos()));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    serde_json::to_writer(&mut f, body).map_err(|e| e.to_string())?;
    f.write_all(b"\n").map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())
}
fn bounded_error(error: &str) -> String {
    error.chars().take(240).collect()
}
pub fn latest_rotation_timestamp() -> Option<String> {
    let parent = Path::new(CHANNEL_PATH).parent()?.to_str()?;
    fs::read_dir(config::path(parent))
        .ok()?
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().to_string();
            generation_timestamp(&n).map(|s| (s, timestamp_for(s)))
        })
        .max_by_key(|(s, _)| *s)
        .map(|(_, v)| v)
}
