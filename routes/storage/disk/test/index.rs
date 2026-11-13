// Hard-drive test control and readback.
//
// The start door crosses the storage/disk/test staff band. Dry-run resolves the
// requested identifier and returns the exact argv and JSON stdin without spawning.

use axum::{extract::Json, http::StatusCode};
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Child, Command},
    sync::{Mutex, OnceLock},
    time::Duration,
};

const RESULTS_FILE: &str = "/var/harddriveTest.txt";
const TEST_TYPES: &[&str] = &["quick", "full"];

struct ActiveTest {
    child: Child,
    device: String,
    test_type: String,
}

fn active_test() -> &'static Mutex<Option<ActiveTest>> {
    static ACTIVE: OnceLock<Mutex<Option<ActiveTest>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(None))
}

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
        Err("caduceus-hard-drive-test-mode-invalid".into())
    }
}

fn native_refusal(signal: &str, could_change_to: Value) -> Value {
    json!({
        "schema": "caduceus.staff.receipt.v1",
        "stop": {"noun": "storage/disk", "verb": "test"},
        "ok": false,
        "firstMissingSignal": signal,
        "observed": {"payloadFields": ["device", "mode"]},
        "could_change_to": could_change_to,
        "attempt": {"attempted": false},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    })
}

fn mounted(node: &Value) -> bool {
    node.get("mountpoints").and_then(Value::as_array).is_some_and(|points| {
        points.iter().any(|point| point.as_str().is_some_and(|s| !s.is_empty()))
    }) || node.get("children").and_then(Value::as_array).is_some_and(|children| {
        children.iter().any(mounted)
    })
}

fn find_device<'a>(nodes: &'a [Value], device: &str) -> Option<&'a Value> {
    for node in nodes {
        if node.get("path").and_then(Value::as_str) == Some(device) {
            return Some(node);
        }
        if let Some(found) = node.get("children").and_then(Value::as_array)
            .and_then(|children| find_device(children, device)) {
            return Some(found);
        }
    }
    None
}

fn preflight(device: &str) -> Result<(), String> {
    let output = Command::new("lsblk")
        .args(["--json", "--output", "NAME,PATH,MOUNTPOINTS"])
        .output().map_err(|_| "caduceus-hard-drive-test-preflight-unavailable".to_string())?;
    if !output.status.success() {
        return Err("caduceus-hard-drive-test-preflight-failed".into());
    }
    let tree: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "caduceus-hard-drive-test-preflight-invalid".to_string())?;
    let nodes = tree.get("blockdevices").and_then(Value::as_array)
        .ok_or_else(|| "caduceus-hard-drive-test-preflight-invalid".to_string())?;
    let node = find_device(nodes, device)
        .ok_or_else(|| "caduceus-hard-drive-test-device-not-found".to_string())?;
    if mounted(node) {
        return Err("caduceus-hard-drive-test-device-mounted".into());
    }
    Ok(())
}

pub fn start_json(device: &str, test_type: &str, dry_run: bool) -> Result<Value, String> {
    if let Err(signal) = validate_test_type(test_type) {
        return Ok(native_refusal(&signal, json!({"mode": TEST_TYPES})));
    }
    let device = match resolve_device_identifier(device) {
        Ok(device) => device,
        Err(signal) => return Ok(native_refusal(&signal, Value::Null)),
    };
    if let Err(signal) = preflight(&device) {
        return Ok(native_refusal(&signal, Value::Null));
    }
    let stdin_json = test_band_payload(&device, test_type);
    if dry_run {
        let argv = match crate::gate::snake::crossing_argv("storage/disk/test") {
            Ok(argv) => argv,
            Err(signal) => return Ok(native_refusal(&signal, Value::Null)),
        };
        return Ok(json!({
            "schema": "caduceus.staff.receipt.v1",
            "stop": {"noun": "storage/disk", "verb": "test"},
            "ok": true, "dryRun": true, "planned": true, "started": false,
            "observed": {"device": device},
            "could_change_to": {"mode": TEST_TYPES},
            "attempt": {"attempted": false, "argv": argv},
            "final_receipt": {"ok": true, "firstMissingSignal": "none"},
            "device": device, "testType": test_type, "argv": argv,
            "command": argv.join(" "), "stdinJson": stdin_json,
            "firstMissingSignal": "none"
        }));
    }
    let walked = match crate::gate::snake::crossing_path_with_timeout(
        "storage/disk/test", &stdin_json, Duration::from_secs(600),
    ) {
        Ok(value) => value,
        Err(signal) => return Ok(native_refusal(&signal, Value::Null)),
    };
    let Some(mut receipt) = walked.get("receiptPayload").cloned().filter(Value::is_object) else {
        let signal = walked.get("firstMissingSignal").and_then(Value::as_str)
            .filter(|s| !s.is_empty() && *s != "none")
            .unwrap_or("caduceus-staff-invalid-receipt");
        return Ok(native_refusal(signal, Value::Null));
    };
    if !crate::routes::leaf_schema::bound(&receipt, "storage/disk/test") {
        if let Some(object) = receipt.as_object_mut() {
            object.insert("doorSignal".into(), json!("caduceus-schema-desync"));
            object.entry("crossedStop").or_insert_with(|| json!("storage/disk/test"));
        }
    } else if walked.get("ok").and_then(Value::as_bool) != Some(true)
        && receipt.get("ok").and_then(Value::as_bool) != Some(false) {
        if let Some(object) = receipt.as_object_mut() {
            object.entry("doorSignal").or_insert_with(|| json!("caduceus-agathodaimon-refused"));
        }
    }
    Ok(receipt)
}

fn valid_device(device: &str) -> bool {
    let Some(name) = device.strip_prefix("/dev/") else { return false; };
    let mut bytes = name.bytes();
    name.len() <= 128 && bytes.next().is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}

async fn start_route(Json(payload): Json<Value>) -> (StatusCode, Json<Value>) {
    if crate::shared::config::resolved_profile().ok().as_deref() != Some("homeserver") {
        return (StatusCode::FORBIDDEN, Json(native_refusal("caduceus-hard-drive-test-profile-invalid", Value::Null)));
    }
    if !matches!(crate::shared::policy::allows_command("disk test start"), Ok(true)) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(native_refusal("caduceus-carapace-desync", Value::Null)));
    }
    let Some(device) = payload.get("device").and_then(Value::as_str).filter(|s| valid_device(s)) else {
        return (StatusCode::BAD_REQUEST, Json(native_refusal("caduceus-hard-drive-test-device-invalid", json!({"device":"/dev/<name>"}))));
    };
    let device = device.to_string();
    let mode = payload.get("mode").and_then(Value::as_str).unwrap_or("").to_string();
    let dry_run = match payload.get("dry_run") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => return (StatusCode::BAD_REQUEST, Json(native_refusal("caduceus-hard-drive-test-dry-run-invalid", Value::Null))),
    };
    let receipt = match crate::gate::blocking_task("disk test start", move || start_json(&device, &mode, dry_run)).await {
        Ok(Ok(receipt)) => receipt,
        Ok(Err(signal)) => native_refusal(&signal, Value::Null),
        Err(_) => native_refusal("caduceus-blocking-task-join-failed", Value::Null),
    };
    (crate::gate::mutation_status(&receipt), Json(receipt))
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
    router.route("/api/v1/storage/disk/test", axum::routing::post(start_route)).route(
        "/api/v1/storage/disk/test/progress",
        axum::routing::get(crate::routes::storage_support::hard_drive_test_progress_route),
    )
}
