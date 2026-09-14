use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
fn shelf_root() -> PathBuf {
    PathBuf::from(crate::protocol::SERPENTS_SHELF_PATH).join("agathodaimon")
}
fn cli_path() -> PathBuf {
    std::env::var_os("CADUCEUS_AGATHODAIMON_CLI")
        .map(PathBuf::from)
        .unwrap_or_else(|| shelf_root().join("cli.py"))
}
pub fn safe_band_path(value: &str) -> Result<String, String> {
    let value = value.trim_matches('/');
    if value.is_empty()
        || value.split('/').any(|p| {
            p.is_empty()
                || p == "."
                || p == ".."
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    {
        return Err("caduceus-snake-band-path-invalid".into());
    }
    Ok(value.into())
}
/// Walk only children named by the authoritative recursive index chain.
pub fn index_entries(root: &Path) -> Result<Vec<Value>, String> {
    let root_path = root.join("index.json");
    let text = fs::read_to_string(&root_path)
        .map_err(|_| "caduceus-agathodaimon-index-missing".to_string())?;
    let root_index: Value = serde_json::from_str(&text)
        .map_err(|_| "caduceus-agathodaimon-index-invalid".to_string())?;
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), String::new(), root_index, false)];
    while let Some((dir, prefix, index, terminal_ok)) = stack.pop() {
        let children = if let Some(value) = index.get("children") {
            value
                .as_array()
                .ok_or_else(|| "caduceus-agathodaimon-index-children-invalid".to_string())?
                .as_slice()
        } else if let Some(value) = index.get("entries") {
            value
                .as_array()
                .ok_or_else(|| "caduceus-agathodaimon-index-children-invalid".to_string())?
                .as_slice()
        } else if terminal_ok {
            &[][..]
        } else {
            return Err("caduceus-agathodaimon-index-children-missing".to_string());
        };
        for child in children {
            let (name, parent_meta) = match child {
                Value::String(s) => (s.clone(), Value::Object(Default::default())),
                Value::Object(m) => {
                    let name = m
                        .get("path")
                        .or_else(|| m.get("name"))
                        .and_then(Value::as_str)
                        .ok_or_else(|| "caduceus-index-child-invalid".to_string())?
                        .to_owned();
                    (name, Value::Object(m.clone()))
                }
                _ => return Err("caduceus-index-child-invalid".into()),
            };
            if name.is_empty()
                || name
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
            {
                return Err("caduceus-index-child-invalid".into());
            }
            let child_dir = dir.join(&name);
            let index_path = child_dir.join("index.json");
            let child_index: Value = if index_path.is_file() {
                let child_text = fs::read_to_string(&index_path)
                    .map_err(|_| format!("caduceus-index-child-missing:{name}"))?;
                serde_json::from_str(&child_text)
                    .map_err(|_| format!("caduceus-index-child-invalid:{name}"))?
            } else if child_dir.join("index.py").is_file() {
                json!({})
            } else {
                return Err(format!("caduceus-index-child-missing:{name}"));
            };
            let mut meta = child_index.clone();
            if let (Some(parent), Some(child)) = (parent_meta.as_object(), meta.as_object_mut()) {
                for (key, value) in parent {
                    child.entry(key.clone()).or_insert_with(|| value.clone());
                }
            }
            let band = if prefix.is_empty() {
                name.clone()
            } else {
                format!("{prefix}/{name}")
            };
            if let Some(m) = meta.as_object_mut() {
                m.insert("bandPath".into(), band.clone().into());
                m.insert(
                    "indexPath".into(),
                    index_path.to_string_lossy().into_owned().into(),
                );
                let face = child_index
                    .get("face")
                    .and_then(Value::as_str)
                    .unwrap_or("index.py");
                m.insert("face".into(), face.into());
                m.insert(
                    "facePath".into(),
                    child_dir.join(face).to_string_lossy().into_owned().into(),
                );
                if let Some(p) = child_index.get("profiles") {
                    m.insert("profiles".into(), p.clone());
                }
            }
            out.push(meta);
            if index_path.is_file() {
                stack.push((child_dir, band, child_index, true));
            }
        }
    }
    Ok(out)
}
fn profile_allows(v: &Value, p: &str) -> bool {
    v.get("profiles")
        .and_then(Value::as_array)
        .map(|a| a.iter().any(|x| x.as_str() == Some(p)))
        .unwrap_or(true)
}
fn active_profile() -> &'static str {
    crate::routes::profile_routes::ACTIVE_PROFILE
}
pub fn list() -> Result<Value, String> {
    let p = active_profile();
    let mut bands = index_entries(&shelf_root())?;
    bands.retain(|v| profile_allows(v, p));
    Ok(
        json!({"schema":"caduceus.staff.library.list.v1","ok":true,"profile":p,"bands":bands,"count":bands.len(),"firstMissingSignal":"none"}),
    )
}
pub fn status(band: Option<&str>) -> Value {
    let root = shelf_root();
    let cli = cli_path();
    let mut body = json!({"schema":"caduceus.staff.library.status.v1","ok":true,"profile":active_profile(),"shelfRoot":root,"shelfPresent":root.is_dir(),"cliEntry":cli,"cliEntryResolved":cli.is_file(),"firstMissingSignal":"none"});
    if let Ok(es) = index_entries(&root) {
        body["indexedBands"] = json!(es);
        if let Some(b) = band.and_then(|b| safe_band_path(b).ok()) {
            if let Some(e) = es.iter().find(|v| {
                v.get("bandPath").and_then(Value::as_str) == Some(&b)
                    && profile_allows(v, active_profile())
            }) {
                body["bandPath"] = b.into();
                body["facePath"] = e.get("facePath").cloned().unwrap_or(Value::Null);
                body["bandPresent"] = Value::Bool(
                    e.get("facePath")
                        .and_then(Value::as_str)
                        .is_some_and(|p| Path::new(p).is_file()),
                );
            }
        }
    } else {
        body["firstMissingSignal"] = json!("caduceus-agathodaimon-index-missing");
    }
    body
}
fn execute_command(
    band: &str,
    outer_envelope: &Value,
    mut command: Command,
    timeout: Duration,
    face_path: Value,
    timeout_error: &str,
    spawn_error: &str,
) -> Result<Value, String> {
    let outer = crate::protocol::Envelope::parse(outer_envelope.clone())?;
    let raw = serde_json::to_string(outer.raw())
        .map_err(|_| "caduceus-snake-envelope-invalid".to_string())?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| spawn_error.to_string())?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "caduceus-agathodaimon-cli-stdin-unavailable".to_string())?;
    let writer = std::thread::spawn(move || stdin.write_all(raw.as_bytes()));
    // Keep stdin writing and both output readers off the waiter thread so a
    // guest that blocks or fills a pipe remains subject to the deadline.
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "caduceus-agathodaimon-cli-stdout-unavailable".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "caduceus-agathodaimon-cli-stderr-unavailable".to_string())?;
    let stdout_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take((MAX_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stderr_reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take((MAX_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let stdin_ok = writer.join().ok().is_some_and(|result| result.is_ok());
    let stdout = stdout_reader.join().ok().and_then(std::result::Result::ok);
    let stderr = stderr_reader.join().ok().and_then(std::result::Result::ok);
    if status.is_none() {
        return Err(timeout_error.to_string());
    }
    if !stdin_ok {
        return Err("caduceus-agathodaimon-cli-stdin-write-failed".into());
    }
    let stdout =
        stdout.ok_or_else(|| "caduceus-agathodaimon-cli-stdout-read-failed".to_string())?;
    let stderr =
        stderr.ok_or_else(|| "caduceus-agathodaimon-cli-stderr-read-failed".to_string())?;
    if stdout.len() > MAX_OUTPUT_BYTES {
        return Err("caduceus-agathodaimon-output-too-large".into());
    }
    let stdout = String::from_utf8_lossy(&stdout).into_owned();
    let stderr = String::from_utf8_lossy(&stderr)
        .chars()
        .take(MAX_OUTPUT_BYTES)
        .collect::<String>();
    let status = status.expect("checked above");
    let payload = serde_json::from_str::<Value>(stdout.trim())
        .unwrap_or_else(|_| Value::String(stdout.clone()));
    let ok = status.success();
    #[cfg(leaf_storage_disk_census)]
    let disk_action = (band == "storage/disk"
        || band.starts_with("storage/disk/")
        || band == "storage/disk-doors"
        || band.starts_with("storage/disk-doors/"))
        && band != "storage/disk/census"
        && !band.starts_with("storage/disk/census/");
    // Receipt success controls refresh only, never the generic snake response.
    #[cfg(leaf_storage_disk_census)]
    if disk_action
        && ok
        && payload.is_object()
        && payload.get("ok").and_then(Value::as_bool) != Some(false)
        && payload.get("converged").and_then(Value::as_bool) != Some(false)
    {
        // Invalidate before the success can reach a caller. Refresh failure cannot
        // turn this completed action into failure; the census stays unavailable.
        crate::stats::disk_census::request_refresh();
    }
    let refusal = if ok {
        Value::Null
    } else {
        json!({"exitCode":status.code(),"signal":status.code().is_none(),"payload":payload.clone()})
    };
    let first_missing = if ok {
        "none"
    } else {
        "caduceus-agathodaimon-refused"
    };
    let mut stamped = outer.raw().clone();
    let object = stamped
        .as_object_mut()
        .ok_or_else(|| "protocol-envelope-not-object".to_string())?;
    if object.contains_key("caduceusReceipt") {
        return Err("caduceus-envelope-stamp-collision".into());
    }
    object.insert(
        "caduceusReceipt".into(),
        json!({
            "schema":"caduceus.staff.v1",
            "stepReceipt":payload,
            "rawChildStdout":stdout,
            "ok":ok,
            "bandPath":band,
            "firstMissingSignal":first_missing,
        }),
    );
    Ok(json!({
        "ok":ok,
        "profile":active_profile(),
        "bandPath":band,
        "facePath":face_path,
        "receiptPayload":payload,
        "rawChildStdout":stdout,
        "rawChildStderr":stderr,
        "rawEnvelope":outer.raw(),
        "envelope":stamped,
        "refusal":refusal,
        "firstMissingSignal":first_missing
    }))
}

fn execute(band: &str, outer_envelope: &Value) -> Result<Value, String> {
    let override_cli = std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some();
    let cli = cli_path();
    if !cli.is_file() {
        return Err("caduceus-agathodaimon-cli-missing".into());
    }
    let e = if override_cli {
        json!({"bandPath": band, "facePath": cli})
    } else {
        let es = index_entries(&shelf_root())?;
        es.iter()
            .find(|v| {
                v.get("bandPath").and_then(Value::as_str) == Some(band)
                    && profile_allows(v, active_profile())
            })
            .cloned()
            .ok_or_else(|| "caduceus-snake-band-not-profile-lit".to_string())?
    };
    let mut command = if override_cli {
        let mut command = Command::new(&cli);
        command.args(band.split('/'));
        command
    } else {
        let mut command = Command::new("/usr/bin/python3");
        command.arg(&cli).arg(band);
        command
    };
    execute_command(
        band,
        outer_envelope,
        command,
        Duration::from_secs(30),
        e.get("facePath").cloned().unwrap_or(Value::Null),
        "caduceus-agathodaimon-timeout",
        "caduceus-agathodaimon-cli-unavailable",
    )
}

pub fn run_launcher(argv: &[String], envelope: &Value, timeout: Duration) -> Result<Value, String> {
    const LAUNCHER: &str = "/usr/local/sbin/agathodaimon/caduceus-xenos-run";
    if argv.first().map(String::as_str) != Some(LAUNCHER) || !Path::new(LAUNCHER).is_file() {
        return Err("xenos-launcher-absent".into());
    }
    let mut command = Command::new(LAUNCHER);
    command.args(&argv[1..]);
    execute_command(
        argv.get(3).map(String::as_str).unwrap_or("xenia/run"),
        envelope,
        command,
        timeout,
        Value::Null,
        "xenos-run-timeout",
        "xenos-launcher-absent",
    )
}
pub fn run(band: &str, envelope: &Value) -> Result<Value, String> {
    let band = safe_band_path(band)?;
    let envelope = crate::protocol::Envelope::parse(envelope.clone())?;
    execute(&band, envelope.raw())
}
pub fn crossing_path(path: &str, input: &Value) -> Result<Value, String> {
    let env = json!({"schema":crate::protocol::SCHEMA_ID,"intent_id":format!("caduceus-{path}"),"transition":path,"origin_of_intent":"near","payload":input});
    let v = execute(path, &env)?;
    if v.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(v.get("receiptPayload").cloned().unwrap_or(v))
    } else {
        Err(v
            .get("receiptPayload")
            .and_then(|payload| {
                payload
                    .get("error")
                    .or_else(|| payload.get("firstMissingSignal"))
                    .and_then(Value::as_str)
            })
            .or_else(|| v.get("firstMissingSignal").and_then(Value::as_str))
            .unwrap_or("caduceus-agathodaimon-refused")
            .into())
    }
}
