// Hard-drive test control and readback.
//
// The start door crosses the storage/disk/test staff band. Dry-run resolves the
// requested identifier and returns the exact argv and JSON stdin without spawning.

use serde_json::{json, Value};
use std::{fs, path::Path, process::Command};

const RESULTS_FILE: &str = "/var/harddriveTest.txt";
const TEST_TYPES: &[&str] = &["quick", "full", "ultimate"];

fn test_band_payload(device: &str, test_type: &str) -> Value {
    json!({
        "device": device,
        "test_type": test_type,
    })
}

pub fn resolve_device_identifier(identifier: &str) -> Result<String, String> {
    let identifier = identifier.trim();
    if identifier.is_empty() || identifier.contains('\0') {
        return Err("caduceus-hard-drive-test-device-invalid".into());
    }
    if identifier.starts_with("/dev/") && Path::new(identifier).exists() {
        return Ok(identifier.to_string());
    }

    let output = Command::new("lsblk")
        .args(["--json", "--output", "NAME,KNAME,PATH,LABEL,PARTLABEL"])
        .output()
        .map_err(|err| format!("caduceus-hard-drive-test-device-resolve-unavailable:{err}"))?;
    if !output.status.success() {
        return Err("caduceus-hard-drive-test-device-resolve-failed".into());
    }
    let tree: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("caduceus-hard-drive-test-device-resolve-invalid:{err}"))?;
    let mut matches = Vec::new();
    collect_matches(&tree, identifier, &mut matches);
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [device] => Ok(device.clone()),
        [] => Err("caduceus-hard-drive-test-device-not-found".into()),
        _ => Err("caduceus-hard-drive-test-device-ambiguous".into()),
    }
}

fn collect_matches(entry: &Value, identifier: &str, matches: &mut Vec<String>) {
    if let Some(entries) = entry.get("blockdevices").and_then(Value::as_array) {
        for child in entries {
            collect_matches(child, identifier, matches);
        }
        return;
    }
    let matches_identifier = ["name", "kname", "path", "label", "partlabel"]
        .iter()
        .filter_map(|key| entry.get(*key).and_then(Value::as_str))
        .any(|value| value == identifier);
    if matches_identifier {
        if let Some(path) = entry.get("path").and_then(Value::as_str) {
            matches.push(path.to_string());
        } else if let Some(name) = entry.get("name").and_then(Value::as_str) {
            matches.push(format!("/dev/{name}"));
        }
    }
    if let Some(children) = entry.get("children").and_then(Value::as_array) {
        for child in children {
            collect_matches(child, identifier, matches);
        }
    }
}

fn validate_test_type(test_type: &str) -> Result<(), String> {
    if TEST_TYPES.contains(&test_type) {
        Ok(())
    } else {
        Err("caduceus-hard-drive-test-type-invalid".into())
    }
}

pub fn start_json(device: &str, test_type: &str, dry_run: bool) -> Result<Value, String> {
    validate_test_type(test_type)?;
    let device = resolve_device_identifier(device)?;
    let argv = crate::gate::snake::crossing_argv("storage/disk/test")?;
    let stdin_json = test_band_payload(&device, test_type);
    if dry_run {
        return Ok(json!({
            "schema": "caduceus.hard-drive-test.start.v1",
            "ok": true,
            "dryRun": true,
            "planned": true,
            "started": false,
            "device": device,
            "testType": test_type,
            "argv": argv,
            "command": argv.join(" "),
            "stdinJson": stdin_json,
            "firstMissingSignal": "none"
        }));
    }

    crate::gate::snake::crossing_path("storage/disk/test", &stdin_json)
        .map_err(|error| format!("caduceus-hard-drive-test-start-failed:{error}"))?;
    Ok(json!({
        "schema": "caduceus.hard-drive-test.start.v1",
        "ok": true,
        "dryRun": false,
        "planned": false,
        "started": true,
        "device": device,
        "testType": test_type,
        "argv": argv,
        "command": argv.join(" "),
        "stdinJson": stdin_json,
        "firstMissingSignal": "none"
    }))
}

pub fn progress_json() -> Result<Value, String> {
    Ok(json!({
        "schema": "caduceus.hard-drive-test.progress.v1",
        "ok": true,
        "testing": false,
        "device": null,
        "label": null,
        "testType": null,
        "progress": null,
        "firstMissingSignal": "none"
    }))
}

pub fn results_json() -> Result<Value, String> {
    match fs::read_to_string(RESULTS_FILE) {
        Ok(results) => Ok(json!({
            "schema": "caduceus.hard-drive-test.results.v1",
            "ok": true,
            "success": true,
            "message": "Test results retrieved successfully",
            "results": results,
            "firstMissingSignal": "none"
        })),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(json!({
            "schema": "caduceus.hard-drive-test.results.v1",
            "ok": true,
            "success": false,
            "message": "No test results available",
            "results": null,
            "firstMissingSignal": "caduceus-hard-drive-test-results-unavailable"
        })),
        Err(err) => Err(format!(
            "caduceus-hard-drive-test-results-read-failed:{err}"
        )),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/storage/disk/test/progress",
        axum::routing::get(crate::routes::storage_support::hard_drive_test_progress_route),
    )
}
