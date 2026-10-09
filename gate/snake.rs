use serde_json::{json, Value};
use std::{
    fs,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};
const MAX_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_CROSSING_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_STREAMED_CROSSING_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);
pub const XENOS_LAUNCHER_PATH: &str = "/usr/local/sbin/agathodaimon/caduceus-xenos-run";
const CROSSING_SENTINEL: &str = "__caduceus_crossing_probe_nonexistent__";
fn shelf_root() -> PathBuf {
    PathBuf::from(crate::protocol::SERPENTS_SHELF_PATH).join("agathodaimon")
}
pub fn cli_path() -> PathBuf {
    std::env::var_os("CADUCEUS_AGATHODAIMON_CLI")
        .map(PathBuf::from)
        .unwrap_or_else(|| shelf_root().join("cli.py"))
}

fn command_argv(executable: &Path, args: &[String], privileged: bool) -> Vec<std::ffi::OsString> {
    let mut argv = Vec::with_capacity(args.len() + 3);
    if privileged {
        argv.push("/usr/bin/sudo".into());
        argv.push("-n".into());
    }
    argv.push(executable.as_os_str().to_owned());
    argv.extend(
        args.iter()
            .map(|arg| std::ffi::OsString::from(arg.as_str())),
    );
    argv
}

fn command_from_argv(argv: &[std::ffi::OsString]) -> Command {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command
}

fn cli_argv(path: &Path, args: &[String]) -> Vec<std::ffi::OsString> {
    let privileged = std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_none();
    command_argv(path, args, privileged)
}

pub fn crossing_argv(path: &str) -> Result<Vec<String>, String> {
    let band = safe_band_path(path)?;
    Ok(cli_argv(&cli_path(), &[band])
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect())
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
fn prepare_envelope(outer_envelope: &Value) -> Result<(Value, String), String> {
    let mut forwarded = outer_envelope.clone();
    let fields = forwarded
        .as_object_mut()
        .ok_or_else(|| "protocol-envelope-not-object".to_string())?;
    fields
        .entry("version")
        .or_insert_with(|| json!(env!("CARGO_PKG_VERSION")));
    fields.entry("timestamp").or_insert_with(|| {
        json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
    });
    let outer = crate::protocol::Envelope::parse(forwarded)?;
    let forwarded = outer.into_raw();
    let raw = serde_json::to_string(&forwarded)
        .map_err(|_| "caduceus-snake-envelope-invalid".to_string())?;
    Ok((forwarded, raw))
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
    let (forwarded, raw) = prepare_envelope(outer_envelope)?;
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
    let mut stamped = forwarded.clone();
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
        "rawEnvelope":forwarded,
        "envelope":stamped,
        "refusal":refusal,
        "firstMissingSignal":first_missing
    }))
}

fn band_invocation(band: &str) -> Result<(Command, Value), String> {
    let override_cli = std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some();
    let cli = cli_path();
    if !cli.is_file() {
        return Err("caduceus-agathodaimon-cli-missing".into());
    }
    let entry = if override_cli {
        json!({"bandPath": band, "facePath": cli})
    } else {
        let entries = index_entries(&shelf_root())?;
        entries
            .iter()
            .find(|value| {
                value.get("bandPath").and_then(Value::as_str) == Some(band)
                    && profile_allows(value, active_profile())
            })
            .cloned()
            .ok_or_else(|| "caduceus-snake-band-not-profile-lit".to_string())?
    };
    let argv = cli_argv(&cli, &[band.to_string()]);
    Ok((
        command_from_argv(&argv),
        entry.get("facePath").cloned().unwrap_or(Value::Null),
    ))
}

fn execute_with_timeout(
    band: &str,
    outer_envelope: &Value,
    timeout: Duration,
) -> Result<Value, String> {
    let (command, face_path) = band_invocation(band)?;
    execute_command(
        band,
        outer_envelope,
        command,
        timeout,
        face_path,
        "caduceus-agathodaimon-timeout",
        "caduceus-agathodaimon-cli-unavailable",
    )
}
fn execute(band: &str, outer_envelope: &Value) -> Result<Value, String> {
    execute_with_timeout(band, outer_envelope, Duration::from_secs(30))
}

fn executable(path: &Path) -> bool {
    path.is_file()
        && fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

fn resolve_cli_program(program: &Path) -> Option<PathBuf> {
    if program.is_absolute() || program.as_os_str().to_string_lossy().contains('/') {
        return executable(program).then(|| program.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|directory| directory.join(program))
            .find(|candidate| executable(candidate))
    })
}

/// Exercise the raw nonexistent-noun CLI sentinel, not a declared band.
pub fn probe_cli() -> Value {
    let requested = cli_path();
    let Some(cli) = resolve_cli_program(&requested) else {
        return json!({
            "ok":false,
            "class":"resolve",
            "exit":null,
            "stderr":format!("agathodaimon cli unavailable: {}", requested.display())
        });
    };
    let argv = cli_argv(&cli, &[CROSSING_SENTINEL.to_string()]);
    let output = match command_from_argv(&argv).output() {
        Ok(output) => output,
        Err(error) => {
            return json!({"ok":false,"class":"spawn","exit":null,"stderr":error.to_string()});
        }
    };
    let exit = output.status.code();
    let stderr = match String::from_utf8(output.stderr) {
        Ok(stderr) => stderr,
        Err(error) => {
            return json!({"ok":false,"class":"parse","exit":exit,"stderr":error.to_string()});
        }
    };
    let expected = format!("unknown noun: {CROSSING_SENTINEL}");
    if exit != Some(2) {
        return json!({"ok":false,"class":"exit","exit":exit,"stderr":stderr});
    }
    if stderr != expected && stderr != format!("{expected}{}", char::from(10)) {
        return json!({"ok":false,"class":"parse","exit":exit,"stderr":stderr});
    }
    json!({"ok":true,"class":Value::Null,"exit":exit,"stderr":stderr})
}

pub fn run_launcher(argv: &[String], envelope: &Value, timeout: Duration) -> Result<Value, String> {
    if argv.first().map(String::as_str) != Some(XENOS_LAUNCHER_PATH)
        || !Path::new(XENOS_LAUNCHER_PATH).is_file()
    {
        return Err("xenos-launcher-absent".into());
    }
    let command_argv = command_argv(Path::new(XENOS_LAUNCHER_PATH), &argv[1..], true);
    execute_command(
        argv.get(3).map(String::as_str).unwrap_or("xenia/run"),
        envelope,
        command_from_argv(&command_argv),
        timeout,
        Value::Null,
        "xenos-run-timeout",
        "xenos-launcher-absent",
    )
}
pub fn run(band: &str, envelope: &Value) -> Result<Value, String> {
    let band = safe_band_path(band)?;
    execute(&band, envelope)
}
fn crossing_envelope(path: &str, input: &Value) -> Value {
    json!({"schema":crate::protocol::SCHEMA_ID,"intent_id":format!("caduceus-{path}"),"transition":path,"origin_of_intent":"near","payload":input})
}

/// Produce the shared public route envelope for a caller-owned transition.
pub fn route_envelope(path: &str, input: &Value) -> Value {
    crossing_envelope(path, input)
}

/// Run a staff crossing with direct transcript sinks and a press-bounded deadline.
pub fn crossing_path_with_streamed_output(
    path: &str,
    input: &Value,
    timeout: Duration,
    stdout_file: &std::fs::File,
    stderr_file: &std::fs::File,
) -> io::Result<ExitStatus> {
    if timeout.is_zero() || timeout > MAX_STREAMED_CROSSING_TIMEOUT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "caduceus-snake-timeout-out-of-range",
        ));
    }
    let band = safe_band_path(path)
        .map_err(|signal| io::Error::new(io::ErrorKind::InvalidInput, signal))?;
    let envelope = crossing_envelope(&band, input);
    let (_forwarded, raw) = prepare_envelope(&envelope)
        .map_err(|signal| io::Error::new(io::ErrorKind::InvalidInput, signal))?;
    let (mut command, _face_path) =
        band_invocation(&band).map_err(|signal| io::Error::new(io::ErrorKind::NotFound, signal))?;
    let started = Instant::now();
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::from(stdout_file.try_clone()?))
        .stderr(Stdio::from(stderr_file.try_clone()?))
        .spawn()?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "caduceus-agathodaimon-cli-stdin-unavailable",
        ));
    };
    let writer = std::thread::spawn(move || stdin.write_all(raw.as_bytes()));
    let deadline = started + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "caduceus-agathodaimon-timeout",
                ));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = writer.join();
                return Err(error);
            }
        }
    };
    writer.join().map_err(|_| {
        io::Error::new(io::ErrorKind::Other, "caduceus-snake-stdin-writer-failed")
    })??;
    Ok(status)
}

/// Run a shared staff crossing with a bounded deadline while retaining the
/// executor result, including the band's structured refusal receiptPayload.
pub fn crossing_path_with_timeout(
    path: &str,
    input: &Value,
    timeout: Duration,
) -> Result<Value, String> {
    if timeout.is_zero() || timeout > MAX_CROSSING_TIMEOUT {
        return Err("caduceus-snake-timeout-out-of-range".to_string());
    }
    let band = safe_band_path(path)?;
    let envelope = crossing_envelope(&band, input);
    execute_with_timeout(&band, &envelope, timeout)
}

pub fn crossing_path(path: &str, input: &Value) -> Result<Value, String> {
    let env = crossing_envelope(path, input);
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
