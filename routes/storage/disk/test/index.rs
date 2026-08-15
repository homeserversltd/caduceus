// Hard-drive test control and readback.
//
// The start door retains the OG tester command, but dry-run is a plan only: it
// resolves the requested identifier and returns the exact argv without spawning
// the destructive external tester.

use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Child, Command},
    sync::{Mutex, OnceLock},
};

const TESTER: &str = "/usr/local/sbin/harddrive_test.sh";
const RESULTS_FILE: &str = "/var/harddriveTest.txt";
const TEST_TYPES: &[&str] = &["quick", "full", "ultimate"];

struct ActiveTest {
    child: Child,
    device: String,
    test_type: String,
}

fn active_test() -> &'static Mutex<Option<ActiveTest>> {
    static ACTIVE: OnceLock<Mutex<Option<ActiveTest>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(None))
}

fn tester_argv(device: &str, test_type: &str) -> Vec<String> {
    vec![
        "/usr/bin/sudo".into(),
        TESTER.into(),
        device.into(),
        test_type.into(),
    ]
}

fn command_text(argv: &[String]) -> String {
    argv.join(" ")
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
    let argv = tester_argv(&device, test_type);
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
            "command": command_text(&argv),
            "firstMissingSignal": "none"
        }));
    }

    let mut active = active_test()
        .lock()
        .map_err(|_| "caduceus-hard-drive-test-state-poisoned".to_string())?;
    if active
        .as_mut()
        .is_some_and(|running| running.child.try_wait().ok().flatten().is_none())
    {
        return Err("caduceus-hard-drive-test-already-running".into());
    }
    *active = None;
    let child = Command::new("/usr/bin/sudo")
        .args([TESTER, &device, test_type])
        .spawn()
        .map_err(|err| format!("caduceus-hard-drive-test-start-failed:{err}"))?;
    *active = Some(ActiveTest {
        child,
        device: device.clone(),
        test_type: test_type.to_string(),
    });
    Ok(json!({
        "schema": "caduceus.hard-drive-test.start.v1",
        "ok": true,
        "dryRun": false,
        "planned": false,
        "started": true,
        "device": device,
        "testType": test_type,
        "argv": argv,
        "command": command_text(&argv),
        "firstMissingSignal": "none"
    }))
}

pub fn progress_json() -> Result<Value, String> {
    let mut active = active_test()
        .lock()
        .map_err(|_| "caduceus-hard-drive-test-state-poisoned".to_string())?;
    let finished = active
        .as_mut()
        .is_some_and(|running| running.child.try_wait().ok().flatten().is_some());
    if finished {
        *active = None;
    }
    match active.as_ref() {
        Some(running) => Ok(json!({
            "schema": "caduceus.hard-drive-test.progress.v1",
            "ok": true,
            "testing": true,
            "device": running.device,
            "label": null,
            "testType": running.test_type,
            "progress": null,
            "firstMissingSignal": "none"
        })),
        None => Ok(json!({
            "schema": "caduceus.hard-drive-test.progress.v1",
            "ok": true,
            "testing": false,
            "device": null,
            "label": null,
            "testType": null,
            "progress": null,
            "firstMissingSignal": "none"
        })),
    }
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
    router
        .route(
            "/api/v1/storage/disk/test/progress",
            axum::routing::get(crate::routes::storage_support::hard_drive_test_progress_route),
        )
}
