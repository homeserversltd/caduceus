//! Native maintenance for expired Hyalos deeds.

use crate::shared::hyalos;
use std::fs;
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
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

fn remove_remainder_tree(path: &Path) -> bool {
    let directory = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(directory) => directory,
        Err(error) if error.kind() == ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    let mut failed = false;
    let held_path = format!("/proc/self/fd/{}", directory.as_raw_fd());
    match fs::read_dir(held_path) {
        Ok(entries) => {
            for entry in entries {
                match entry {
                    Ok(entry) => {
                        let result = match entry.file_type() {
                            Ok(kind) if kind.is_dir() => fs::remove_dir_all(entry.path()),
                            Ok(_) => fs::remove_file(entry.path()),
                            Err(error) => Err(error),
                        };
                        if let Err(error) = result {
                            failed |= error.kind() != ErrorKind::NotFound;
                        }
                    }
                    Err(error) => failed |= error.kind() != ErrorKind::NotFound,
                }
            }
        }
        Err(error) => failed |= error.kind() != ErrorKind::NotFound,
    }
    if let Err(error) = fs::remove_dir(path) {
        failed |= error.kind() != ErrorKind::NotFound;
    }
    failed
}

fn remove_remainders() {
    // Remainders: /var/lib/caduceus/backups and receipts/log-maintenance-<n>-<n>.json.
    let mut failed = remove_remainder_tree(&crate::shared::config::path("/var/lib/caduceus/backups"));
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
    match hyalos::prune_expired() {
        Ok(0) => {}
        Ok(deleted) => {
            if let Err(error) = hyalos::record_prune(deleted, 0) {
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

fn bounded_error(error: &str) -> String {
    error.chars().take(240).collect()
}
