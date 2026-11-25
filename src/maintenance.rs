//! Native maintenance for the appliance journal and expired Hyalos deeds.

use crate::shared::hyalos;
use serde_json::{json, Value};
use std::fs;
use std::io::ErrorKind;
use std::sync::OnceLock;
use tokio::time::{interval, Duration};

static STARTED: OnceLock<()> = OnceLock::new();

pub fn start() {
    if STARTED.set(()).is_err() {
        return;
    }
    remove_remainders();
    tokio::spawn(async {
        match tokio::task::spawn_blocking(hyalos::prepare_existing).await {
            Ok(Ok(())) => {}
            Ok(Err(signal)) => eprintln!("caduceus-hyalos-index-prepare-failed: {signal}"),
            Err(_) => eprintln!("caduceus-hyalos-index-prepare-failed: worker-failed"),
        }
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

fn remove_remainders() {
    // Remainders: /var/lib/caduceus/backups and receipts/log-maintenance-<n>-<n>.json.
    let mut failed = false;
    if let Err(error) = fs::remove_dir_all(crate::shared::config::path("/var/lib/caduceus/backups")) {
        failed |= error.kind() != ErrorKind::NotFound;
    }
    match fs::read_dir(crate::shared::config::path("/var/lib/caduceus/receipts")) {
        Ok(entries) => {
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => {
                        failed = true;
                        continue;
                    }
                };
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                let Some(numbers) = name.strip_prefix("log-maintenance-").and_then(|s| s.strip_suffix(".json")) else { continue };
                let Some((first, second)) = numbers.split_once('-') else { continue };
                if first.is_empty() || second.is_empty()
                    || !first.bytes().all(|b| b.is_ascii_digit())
                    || !second.bytes().all(|b| b.is_ascii_digit())
                {
                    continue;
                }
                match entry.file_type() {
                    Ok(kind) if kind.is_file() => {
                        if let Err(error) = fs::remove_file(entry.path()) {
                            failed |= error.kind() != ErrorKind::NotFound;
                        }
                    }
                    Ok(_) => {}
                    Err(error) => failed |= error.kind() != ErrorKind::NotFound,
                }
            }
        }
        Err(error) => failed |= error.kind() != ErrorKind::NotFound,
    }
    if failed {
        eprintln!("caduceus-remainder-removal-failed");
    }
}

fn maintenance_tick() -> Result<(), String> {
    let mut errors = Vec::new();
    let mut freed_bytes = 0;
    match vacuum_journal() {
        Ok(freed) => freed_bytes = freed.unwrap_or(0),
        Err(error) => errors.push(format!("journal-vacuum: {error}")),
    }
    match hyalos::prune_expired() {
        Ok(0) => {}
        Ok(deleted) => {
            if let Err(error) = hyalos::record_prune(deleted, freed_bytes) {
                errors.push(format!("maintenance log: {error}"));
            }
        }
        Err(error) => errors.push(format!("hyalos-prune: {error}")),
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(bounded_error(&errors.join("; ")))
    }
}

fn vacuum_journal() -> Result<Option<u64>, String> {
    let receipt = crate::gate::snake::crossing_path_receipt("appliance/journal-vacuum", &json!({}))?;
    match receipt.get("ok").and_then(Value::as_bool) {
        Some(true) if crate::gate::receipt_succeeded(&receipt) => {}
        Some(true) | Some(false) => {
            return Err(receipt
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .filter(|signal| *signal != "none")
                .unwrap_or("caduceus-journal-vacuum-refused")
                .to_string());
        }
        None => return Err("caduceus-journal-vacuum-result-unobserved".to_string()),
    }
    let freed = receipt
        .get("freed_bytes")
        .and_then(Value::as_u64)
        .or_else(|| receipt.get("freedBytes").and_then(Value::as_u64))
        .or_else(|| receipt.as_str().map(parse_freed))
        .or_else(|| {
            receipt
                .get("output")
                .or_else(|| receipt.get("stdout"))
                .and_then(Value::as_str)
                .map(parse_freed)
        });
    Ok(freed.filter(|freed| *freed > 0))
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

fn bounded_error(error: &str) -> String {
    error.chars().take(240).collect()
}
