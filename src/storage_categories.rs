use chrono::Utc;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

const SCHEMA: &str = "caduceus.storage.categories.v1";
const RECEIPT_SCHEMA: &str = "caduceus.storage.categories.scan.receipt.v1";
const MAX_DIAGNOSTICS: usize = 64;
const MAX_DIAGNOSTIC_BYTES: usize = 256;

fn scan_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn categories() -> Vec<(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)> {
    vec![
        (
            "games",
            "gba",
            "Game Boy Advance",
            "/home/arcadia/Games/roms/gba",
            "ROMs",
        ),
        (
            "games",
            "genesis",
            "Sega Genesis",
            "/home/arcadia/Games/roms/genesis",
            "ROMs",
        ),
        (
            "games",
            "snes",
            "Super Nintendo",
            "/home/arcadia/Games/roms/snes",
            "ROMs",
        ),
        (
            "games",
            "nes",
            "Nintendo Entertainment System",
            "/home/arcadia/Games/roms/nes",
            "ROMs",
        ),
        (
            "games",
            "ps1",
            "PlayStation",
            "/home/arcadia/Games/roms/ps1",
            "ROMs",
        ),
        (
            "games",
            "n64",
            "Nintendo 64",
            "/home/arcadia/Games/roms/n64",
            "ROMs",
        ),
        (
            "games",
            "ps2",
            "PlayStation 2",
            "/home/arcadia/Games/isos/ps2",
            "ISOs",
        ),
        (
            "games",
            "sega-cd",
            "Sega CD",
            "/home/arcadia/Games/isos/sega-cd",
            "ISOs",
        ),
        (
            "games",
            "psp",
            "PlayStation Portable",
            "/home/arcadia/Games/isos/psp",
            "ISOs",
        ),
        (
            "games",
            "gamecube",
            "Nintendo GameCube",
            "/home/arcadia/Games/isos/gamecube",
            "ISOs",
        ),
        (
            "games",
            "wii",
            "Nintendo Wii",
            "/home/arcadia/Games/isos/wii",
            "ISOs",
        ),
        (
            "games",
            "dos",
            "DOS",
            "/home/arcadia/Games/pc/dos",
            "PC games",
        ),
        (
            "games",
            "arcade",
            "Arcade",
            "/home/arcadia/Games/roms/arcade",
            "ROMs",
        ),
        (
            "artwork",
            "artwork-covers",
            "Covers",
            "/home/arcadia/Games/artwork/covers",
            "covers",
        ),
        (
            "artwork",
            "artwork-metadata",
            "Metadata",
            "/home/arcadia/Games/artwork/metadata",
            "metadata",
        ),
        (
            "artwork",
            "artwork-generated",
            "Generated",
            "/home/arcadia/Games/artwork/generated",
            "generated",
        ),
        (
            "artwork",
            "artwork-cache",
            "Scraper Cache",
            "/home/arcadia/Games/artwork",
            "cache",
        ),
        (
            "aiModels",
            "ai-installed-models-0",
            "Installed Models",
            "/home/arcadia",
            "installed-models",
        ),
        (
            "aiModels",
            "ai-installed-models-1",
            "Installed Models",
            "/opt",
            "installed-models",
        ),
        (
            "aiModels",
            "ai-installed-models-2",
            "Installed Models",
            "/var/lib",
            "installed-models",
        ),
        (
            "aiModels",
            "ai-installed-models-3",
            "Installed Models",
            "/var/lib/arcadia/model-library/models",
            "installed-models",
        ),
        (
            "aiModels",
            "ai-downloads",
            "Downloads",
            "/var/lib/arcadia/model-downloads",
            "downloads",
        ),
        (
            "aiModels",
            "ai-partial-downloads",
            "Partial Downloads",
            "/var/lib/arcadia/model-downloads/partial",
            "partial-downloads",
        ),
        (
            "aiModels",
            "ai-catalog-cache",
            "Catalog Cache",
            "/var/lib/arcadia/model-catalog",
            "catalog-cache",
        ),
        (
            "updates",
            "updates-0",
            "Update Cache",
            "/var/cache/pacman/pkg",
            "cache",
        ),
        (
            "updates",
            "updates-1",
            "Update Cache",
            "/var/lib/harmonia/cache",
            "cache",
        ),
        (
            "updates",
            "updates-2",
            "Update Cache",
            "/var/lib/harmonia/artifacts",
            "cache",
        ),
        ("logs", "logs-0", "Logs", "/var/log/arcadia", "logs"),
        (
            "logs",
            "logs-1",
            "Logs",
            "/var/log/homeconsole-sync",
            "logs",
        ),
        (
            "logs",
            "logs-2",
            "Logs",
            "/var/lib/harmonia/receipts",
            "logs",
        ),
        ("temporary", "temporary-0", "Temporary", "/tmp", "temporary"),
        (
            "temporary",
            "temporary-1",
            "Temporary",
            "/var/tmp",
            "temporary",
        ),
        ("system", "system-root", "System", "/usr", "system"),
        (
            "system",
            "system-var-lib",
            "Runtime State",
            "/var/lib",
            "system",
        ),
    ]
}
fn bounded_diagnostic(diagnostics: &mut Vec<String>, text: String) {
    if diagnostics.len() < MAX_DIAGNOSTICS {
        diagnostics.push(text.chars().take(MAX_DIAGNOSTIC_BYTES).collect());
    }
}

fn walk(path: &Path, diagnostics: &mut Vec<String>) -> (u64, u64) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(value) => value,
        Err(error) => {
            bounded_diagnostic(
                diagnostics,
                format!(
                    "{}:{}: {}",
                    if error.kind() == ErrorKind::NotFound {
                        "missingRoots"
                    } else if error.kind() == ErrorKind::PermissionDenied {
                        "permissionErrors"
                    } else {
                        "scanErrors"
                    },
                    path.display(),
                    error
                ),
            );
            return (0, 0);
        }
    };
    if metadata.file_type().is_symlink() {
        return (0, 0);
    }
    if metadata.is_file() {
        return (metadata.len(), 1);
    }
    if !metadata.is_dir() {
        return (0, 0);
    }
    let mut bytes: u64 = 0;
    let mut files: u64 = 0;
    let entries = match fs::read_dir(path) {
        Ok(value) => value,
        Err(error) => {
            bounded_diagnostic(
                diagnostics,
                format!(
                    "{}:{}: {}",
                    if error.kind() == ErrorKind::NotFound {
                        "missingRoots"
                    } else if error.kind() == ErrorKind::PermissionDenied {
                        "permissionErrors"
                    } else {
                        "scanErrors"
                    },
                    path.display(),
                    error
                ),
            );
            return (0, 0);
        }
    };
    for entry in entries {
        match entry {
            Ok(entry) => {
                let (b, f) = walk(&entry.path(), diagnostics);
                bytes = bytes.saturating_add(b);
                files = files.saturating_add(f);
            }
            Err(error) => bounded_diagnostic(diagnostics, error.to_string()),
        }
    }
    (bytes, files)
}

fn run_id() -> String {
    format!(
        "storage-categories-{}-{}",
        Utc::now().format("%Y%m%dT%H%M%S%9fZ"),
        std::process::id()
    )
}
fn state_path() -> PathBuf {
    crate::shared::config::path("var/lib/caduceus/state/storage-categories.json")
}
fn receipt_path(run_id: &str) -> PathBuf {
    crate::shared::config::path(&format!("var/lib/caduceus/receipts/{run_id}/run.json"))
}
fn ensure_parent(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "caduceus-storage-categories-parent-missing".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|_| "caduceus-storage-categories-directory-failed".to_string())?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o750))
        .map_err(|_| "caduceus-storage-categories-directory-failed".to_string())
}
fn write_json(path: &Path, value: &Value) -> Result<(), String> {
    ensure_parent(path)?;
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| "caduceus-storage-categories-serialize-failed".to_string())?;
    bytes.push(b'\n');
    crate::shared::config::atomic_write_owned(path, &bytes, 0o640)
        .map_err(|_| "caduceus-storage-categories-write-failed".to_string())
}
fn manifest_matches() -> (Option<String>, Vec<String>) {
    let candidates = [
        "/var/lib/homeconsole-sync/manifest.json",
        "/var/lib/arch-game-sync/manifest.json",
        "/var/lib/harmonia/state/homeconsole-sync-manifest.json",
    ];
    for candidate in candidates {
        let path = crate::shared::config::path(candidate);
        let Ok(text) = fs::read_to_string(path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let Some(entries) = value
            .as_array()
            .or_else(|| value.get("entries").and_then(Value::as_array))
        else {
            continue;
        };
        let mut paths = Vec::new();
        for entry in entries {
            let candidate = entry
                .as_str()
                .or_else(|| entry.get("normalizedRomPath").and_then(Value::as_str))
                .or_else(|| entry.get("romPath").and_then(Value::as_str));
            if let Some(path) = candidate {
                paths.push(path.to_ascii_lowercase());
            }
        }
        return (Some(candidate.to_string()), paths);
    }
    (None, Vec::new())
}

fn build_snapshot(run_id: &str) -> Value {
    let (manifest_path, manifest) = manifest_matches();
    let mut diagnostics = Vec::new();
    let mut cache: HashMap<PathBuf, (u64, u64)> = HashMap::new();
    let mut roots = Vec::new();
    for (category, id, display, path, purpose) in categories() {
        let key = crate::shared::config::path(path);
        let (bytes, files) = *cache
            .entry(key)
            .or_insert_with(|| walk(&crate::shared::config::path(path), &mut diagnostics));
        let state = if !crate::shared::config::path(path).exists() {
            "missing"
        } else {
            "present"
        };
        let matches = if category == "games" {
            manifest
                .iter()
                .filter(|p| p.contains(&format!("/{id}/")))
                .count() as u64
        } else {
            0
        };
        let mut root = json!({"id":id,"displayName":display,"path":path,"purpose":purpose,"bytes":bytes,"fileCount":files,"state":state});
        if category == "games" {
            root["platform"] = json!(id.to_ascii_uppercase());
            root["syncManifestEntries"] = json!(matches)
        }
        roots.push((category, root));
    }
    let labels = [
        ("games", "Games"),
        ("artwork", "Artwork"),
        ("aiModels", "AI Models"),
        ("updates", "Updates"),
        ("logs", "Logs"),
        ("temporary", "Temporary Files"),
        ("system", "System"),
    ];
    let mut groups = Vec::new();
    for (id, label) in labels {
        let rs: Vec<Value> = roots
            .iter()
            .filter(|(c, _)| *c == id)
            .map(|(_, v)| v.clone())
            .collect();
        let bytes = rs
            .iter()
            .map(|v| v["bytes"].as_u64().unwrap_or(0))
            .fold(0, u64::saturating_add);
        let files = rs
            .iter()
            .map(|v| v["fileCount"].as_u64().unwrap_or(0))
            .fold(0, u64::saturating_add);
        groups.push(json!({"id":id,"category":id,"displayName":label,"label":label,"bytes":bytes,"fileCount":files,"roots":rs}));
    }
    let total_bytes = groups
        .iter()
        .map(|v| v["bytes"].as_u64().unwrap_or(0))
        .fold(0, u64::saturating_add);
    let file_count = groups
        .iter()
        .map(|v| v["fileCount"].as_u64().unwrap_or(0))
        .fold(0, u64::saturating_add);
    let mut missing = Vec::new();
    let mut permission = Vec::new();
    let mut errors = Vec::new();
    for x in diagnostics {
        if let Some((k, v)) = x.split_once(":") {
            match k {
                "missingRoots" => bounded_diagnostic(&mut missing, v.to_string()),
                "permissionErrors" => bounded_diagnostic(&mut permission, v.to_string()),
                _ => bounded_diagnostic(&mut errors, v.to_string()),
            }
        }
    }
    json!({"schema":SCHEMA,"ok":true,"capturedAt":Utc::now().to_rfc3339(),"runId":run_id,"receiptPath":format!("/var/lib/caduceus/receipts/{run_id}/run.json"),"categoryCount":groups.len(),"rootCount":roots.len(),"totalBytes":total_bytes,"fileCount":file_count,"categories":groups,"syncManifest":{"available":manifest_path.is_some(),"path":manifest_path,"entries":manifest},"diagnostics":{"missingRoots":missing,"permissionErrors":permission,"scanErrors":errors},"firstMissingSignal":"none"})
}
fn receipt(
    run_id: &str,
    started: &str,
    status: &str,
    snapshot: Option<&Value>,
    error: Option<&str>,
) -> Value {
    let summary=snapshot.map(|v|json!({"schema":v["schema"],"categoryCount":v["categoryCount"],"rootCount":v["rootCount"],"totalBytes":v["totalBytes"],"fileCount":v["fileCount"]})).unwrap_or(Value::Null);
    json!({"schema":RECEIPT_SCHEMA,"ok":status=="completed","command":"storage categories scan","runId":run_id,"state":status,"startedAt":started,"finishedAt":if status=="started"{Value::Null}else{json!(Utc::now().to_rfc3339())},"receiptPath":format!("/var/lib/caduceus/receipts/{run_id}/run.json"),"snapshotPath":"/var/lib/caduceus/state/storage-categories.json","snapshotSchema":SCHEMA,"categoryCount":summary.get("categoryCount").cloned().unwrap_or(Value::Null),"rootCount":summary.get("rootCount").cloned().unwrap_or(Value::Null),"totalBytes":summary.get("totalBytes").cloned().unwrap_or(Value::Null),"fileCount":summary.get("fileCount").cloned().unwrap_or(Value::Null),"mutationPerformed":status=="completed","error":error,"firstMissingSignal":if status=="completed"{"none"}else{"caduceus-storage-categories-scan-failed"}})
}

pub fn scan_json() -> Result<Value, String> {
    let _guard = scan_lock()
        .lock()
        .map_err(|_| "caduceus-storage-categories-lock-poisoned".to_string())?;
    let run_id = run_id();
    let receipt_file = receipt_path(&run_id);
    let started_at = Utc::now().to_rfc3339();
    write_json(
        &receipt_file,
        &receipt(&run_id, &started_at, "started", None, None),
    )?;
    let snapshot = build_snapshot(&run_id);
    if let Err(error) = write_json(&state_path(), &snapshot) {
        let _ = write_json(
            &receipt_file,
            &receipt(
                &run_id,
                &started_at,
                "failed",
                Some(&snapshot),
                Some(&error),
            ),
        );
        return Err(error);
    }
    write_json(
        &receipt_file,
        &receipt(&run_id, &started_at, "completed", Some(&snapshot), None),
    )?;
    Ok(snapshot)
}
pub fn cached_json() -> Result<Value, String> {
    let text = fs::read_to_string(state_path())
        .map_err(|_| "caduceus-storage-categories-cache-missing".to_string())?;
    {
        let value: Value = serde_json::from_str(&text)
            .map_err(|_| "caduceus-storage-categories-cache-invalid".to_string())?;
        if value.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
            return Err("caduceus-storage-categories-cache-invalid-schema".into());
        }
        Ok(value)
    }
}
pub fn scan_command() -> i32 {
    match scan_json() {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}
