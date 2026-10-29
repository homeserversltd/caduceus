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
    if let Some(context) = crate::shared::load_trace::current() {
        crate::shared::load_trace::attach_to_envelope(&mut forwarded, &context, None);
    }
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
    command: Command,
    timeout: Duration,
    face_path: Value,
    timeout_error: &str,
    spawn_error: &str,
) -> Result<Value, String> {
    let Some(context) = crate::shared::load_trace::current() else {
        let mut appended_staff_stamps = 0;
        return execute_command_raw(
            band,
            outer_envelope,
            command,
            timeout,
            face_path,
            timeout_error,
            spawn_error,
            None,
            &mut appended_staff_stamps,
        );
    };
    let invocation = crate::shared::load_trace::begin_invocation(&context);
    let mut forwarded = outer_envelope.clone();
    crate::shared::load_trace::attach_to_envelope(
        &mut forwarded,
        &context,
        Some(crate::shared::load_trace::invocation_id(&invocation)),
    );
    let mut appended_staff_stamps = 0;
    let result = execute_command_raw(
        band,
        &forwarded,
        command,
        timeout,
        face_path,
        timeout_error,
        spawn_error,
        Some(&context),
        &mut appended_staff_stamps,
    );
    let staff_instrumented = appended_staff_stamps > 0;
    let outcome = match result.as_ref() {
        Err(_) => "failed",
        Ok(value) if value.get("ok").and_then(Value::as_bool) == Some(true) => "ok",
        Ok(_) => "refused",
    };
    let operation = format!("caduceus.staff.{}", band.replace('/', "."));
    let detailed = crate::protocol::benchmark_enabled(&forwarded);
    crate::shared::load_trace::finish_invocation(
        &context,
        invocation,
        &operation,
        "staff",
        "agathodaimon-crossing",
        "not-applicable",
        outcome,
        Some(staff_instrumented),
        detailed,
    );
    result
}

fn execute_command_raw(
    band: &str,
    outer_envelope: &Value,
    mut command: Command,
    timeout: Duration,
    face_path: Value,
    timeout_error: &str,
    spawn_error: &str,
    trace_context: Option<&crate::shared::load_trace::ContextHandle>,
    appended_staff_stamps: &mut usize,
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
    *appended_staff_stamps = trace_context.map_or(0, |context| {
        let mut appended = 0;
        if let Some(returned) = payload.get("load_context") {
            appended += crate::shared::load_trace::merge_returned_context(context, returned);
        }
        if let Some(returned) = payload.pointer("/envelope/flags/load_context") {
            appended += crate::shared::load_trace::merge_returned_context(context, returned);
        }
        appended
    });
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

fn rust_step_stamp(
    base_envelope: &Value,
    primitive: &str,
    payload: &Value,
) -> Result<Value, String> {
    let mut stamped = base_envelope.clone();
    let object = stamped
        .as_object_mut()
        .ok_or_else(|| "protocol-envelope-not-object".to_string())?;
    if object.contains_key("caduceusReceipt") {
        return Err("caduceus-envelope-stamp-collision".into());
    }
    let ok = payload.get("ok").and_then(Value::as_bool) == Some(true);
    let first_missing = payload
        .get("firstMissingSignal")
        .and_then(Value::as_str)
        .unwrap_or(if ok { "none" } else { "caduceus-rust-primitive-refused" });
    let stamp = json!({
        "schema":"caduceus.staff.v1",
        "stepReceipt":payload,
        "ok":ok,
        "primitive":primitive,
        "firstMissingSignal":first_missing
    });
    object.insert("caduceusReceipt".into(), stamp);
    stamped
        .get("caduceusReceipt")
        .cloned()
        .ok_or_else(|| "caduceus-snake-step-stamp-missing".to_string())
}

/// Execute an ordered snake/Rust serve chord against one raw envelope.
/// Each step gets a fresh execution stamp; prior stamps never enter the next hop.
pub async fn execute_ordered_serve(
    route_set: &[Value],
    base_envelope: &Value,
) -> Result<Value, String> {
    execute_ordered_serve_with_timeout(route_set, base_envelope, None).await
}

pub async fn execute_ordered_serve_with_timeout(
    route_set: &[Value],
    base_envelope: &Value,
    timeout: Option<Duration>,
) -> Result<Value, String> {
    if timeout.is_some_and(|timeout| timeout.is_zero() || timeout > MAX_CROSSING_TIMEOUT) {
        return Err("caduceus-snake-timeout-out-of-range".to_string());
    }
    let steps = crate::gate::discovery::walk_compiled_route_set(route_set)?;
    if steps.is_empty() {
        return Err("gate-route-set-empty".into());
    }

    let mut step_receipts = Vec::with_capacity(steps.len());
    let mut receipt_payload = None;
    let mut all_ok = true;
    let benchmark = crate::protocol::benchmark_enabled(base_envelope);
    let mut benchmark_timings = if benchmark { Some(Vec::new()) } else { None };
    let mut staff_reports = if benchmark { Some(Vec::new()) } else { None };
    for (ordinal, step) in steps.into_iter().enumerate() {
        let started = benchmark.then(Instant::now);
        let (label, stamp, payload) = if let Some(band) = step.snake {
            let band = safe_band_path(&band)?;
            let execution_band = band.clone();
            let envelope = base_envelope.clone();
            let context = crate::shared::load_trace::current();
            let result = tokio::task::spawn_blocking(move || {
                crate::shared::load_trace::with_blocking_context(context, || match timeout {
                    Some(timeout) => execute_with_timeout(&execution_band, &envelope, timeout),
                    None => execute(&execution_band, &envelope),
                })
            })
            .await
            .map_err(|_| "caduceus-blocking-task-join-failed".to_string())??;
            let stamp = result
                .get("envelope")
                .and_then(|envelope| envelope.get("caduceusReceipt"))
                .cloned()
                .ok_or_else(|| "caduceus-snake-step-stamp-missing".to_string())?;
            let payload = result
                .get("receiptPayload")
                .cloned()
                .ok_or_else(|| "caduceus-snake-step-receipt-missing".to_string())?;
            (band, stamp, payload)
        } else if let Some(primitive) = step.rust {
            let payload = crate::shared::primitives::execute(&primitive, base_envelope).await?;
            let stamp = rust_step_stamp(base_envelope, &primitive, &payload)?;
            (primitive, stamp, payload)
        } else {
            return Err("gate-route-step-must-name-one-band".into());
        };
        let elapsed = started.map(|started| started.elapsed());
        let child_ok = stamp.get("ok").and_then(Value::as_bool) == Some(true);
        let staff_ok = payload.get("ok").and_then(Value::as_bool) == Some(true);
        all_ok &= child_ok && staff_ok;
        if let (Some(elapsed), Some(timings)) = (elapsed, benchmark_timings.as_mut()) {
            timings.push(crate::protocol::benchmark_timing_row(
                crate::protocol::benchmark_serve_locus(ordinal, &label),
                elapsed,
                child_ok && staff_ok,
            ));
        }
        if let Some(reports) = staff_reports.as_mut() {
            for field in ["benchmark", "benchmarkStamp"] {
                if let Some(report) = payload.get(field) {
                    reports.push(report.clone());
                }
            }
        }
        step_receipts.push(stamp);
        receipt_payload = Some(payload);
        if !child_ok || !staff_ok {
            break;
        }
    }

    let receipt_payload =
        receipt_payload.ok_or_else(|| "caduceus-snake-step-receipt-missing".to_string())?;
    let mut aggregate = json!({
        "ok": all_ok,
        "receiptPayload": receipt_payload,
        "stepReceipts": step_receipts,
        "rawEnvelope": base_envelope,
    });
    if let Some(timings) = benchmark_timings {
        let mut stamp = json!({
            "schema": crate::protocol::BENCHMARK_REPORT_SCHEMA,
            "timings": timings
        });
        if let Some(reports) = staff_reports.filter(|reports| !reports.is_empty()) {
            stamp["staff_reports"] = json!(reports);
        }
        aggregate["benchmarkStamp"] = stamp;
    }
    Ok(aggregate)
}

fn crossing_envelope(path: &str, input: &Value) -> Value {
    let context = crate::shared::load_trace::current();
    let mut payload = input.clone();
    let flags = if context.is_some() {
        payload
            .as_object_mut()
            .and_then(|object| object.remove("flags"))
    } else {
        None
    };
    let mut envelope = json!({"schema":crate::protocol::SCHEMA_ID,"intent_id":format!("caduceus-{path}"),"transition":path,"origin_of_intent":"near","payload":payload});
    if let Some(flags) = flags {
        envelope["flags"] = flags;
    }
    if let Some(context) = context {
        crate::shared::load_trace::attach_to_envelope(&mut envelope, &context, None);
    }
    envelope
}

/// Produce the shared public route envelope for a caller-owned transition.
pub fn route_envelope(path: &str, input: &Value) -> Value {
    let Some(flags) = input
        .as_object()
        .and_then(|object| object.get("flags"))
        .cloned()
    else {
        return crossing_envelope(path, input);
    };
    let mut payload = input.clone();
    if let Some(object) = payload.as_object_mut() {
        object.remove("flags");
    }
    let mut envelope = crossing_envelope(path, &payload);
    if let Some(object) = envelope.as_object_mut() {
        object.insert("flags".into(), flags);
    }
    if let Some(context) = crate::shared::load_trace::current() {
        crate::shared::load_trace::attach_to_envelope(&mut envelope, &context, None);
    }
    envelope
}

/// Spawn a staff crossing and return its running child after forwarding the envelope.
pub fn crossing_spawn(path: &str, input: &Value) -> Result<std::process::Child, String> {
    let band = safe_band_path(path)?;
    let (mut command, _face_path) = band_invocation(&band)?;
    let envelope = crossing_envelope(&band, input);
    let (_forwarded, raw) = prepare_envelope(&envelope)?;
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "caduceus-agathodaimon-cli-unavailable".to_string())?;
    let Some(mut stdin) = child.stdin.take() else {
        let _ = child.kill();
        let _ = child.wait();
        return Err("caduceus-agathodaimon-cli-stdin-unavailable".into());
    };
    if stdin.write_all(raw.as_bytes()).is_err() {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err("caduceus-agathodaimon-cli-stdin-write-failed".into());
    }
    drop(stdin);
    Ok(child)
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

struct NativeChordState {
    stages: Vec<Value>,
    completed: std::collections::HashMap<String, Value>,
    seen: std::collections::HashSet<String>,
    failed_stage: Option<String>,
    first_missing_signal: Option<String>,
    skip_serve: bool,
    // None means at least one mutator did not report whether it changed.
    changed: Option<bool>,
    next_ordinal: usize,
}

fn native_chord_mark_failed(state: &mut NativeChordState, stage_id: &str, signal: &str) {
    if state.failed_stage.is_none() {
        state.failed_stage = Some(stage_id.to_owned());
        state.first_missing_signal = Some(signal.to_owned());
    }
}

fn native_chord_stage_row(
    stage_id: &str,
    transition: &str,
    outcome: &str,
    arguments: Value,
    receipt: Value,
) -> Value {
    json!({
        "stage_id": stage_id,
        "transition": transition,
        "outcome": outcome,
        "arguments": arguments,
        "receipt": receipt
    })
}

fn native_chord_dotted_lookup(value: &Value, path: &str) -> Option<Value> {
    if path.is_empty() {
        return None;
    }
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            return None;
        }
        current = current.get(segment)?;
    }
    Some(current.clone())
}

fn native_chord_resolve_reference(
    reference: &str,
    request_payload: &Value,
    completed: &std::collections::HashMap<String, Value>,
) -> Option<Value> {
    if let Some(path) = reference.strip_prefix("request.payload.") {
        return native_chord_dotted_lookup(request_payload, path);
    }
    let rest = reference.strip_prefix("stages.")?;
    let (stage_id, path) = rest.split_once(".receipt.")?;
    if stage_id.is_empty() {
        return None;
    }
    native_chord_dotted_lookup(completed.get(stage_id)?, path)
}

fn native_chord_resolve_arguments(
    value: &Value,
    request_payload: &Value,
    completed: &std::collections::HashMap<String, Value>,
) -> Result<Value, String> {
    if let Some(object) = value.as_object() {
        if object.len() == 1 {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                return native_chord_resolve_reference(reference, request_payload, completed)
                    .ok_or_else(|| "caduceus-chord-ref-unresolved".to_string());
            }
        }
        let mut resolved = serde_json::Map::new();
        for (key, entry) in object {
            resolved.insert(
                key.clone(),
                native_chord_resolve_arguments(entry, request_payload, completed)?,
            );
        }
        return Ok(Value::Object(resolved));
    }
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .map(|entry| native_chord_resolve_arguments(entry, request_payload, completed))
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array);
    }
    Ok(value.clone())
}

fn native_chord_request_envelope(
    base_envelope: &Value,
    routine_id: &str,
    stage_id: &str,
    arguments: &Value,
) -> Result<Value, String> {
    let mut envelope = base_envelope.clone();
    let object = envelope
        .as_object_mut()
        .ok_or_else(|| "protocol-envelope-not-object".to_string())?;

    let mut payload = match object.get("payload") {
        Some(Value::Object(payload)) => payload.clone(),
        Some(Value::Null) => return Err("caduceus-chord-request-payload-not-object".into()),
        Some(_) => return Err("caduceus-chord-request-payload-not-object".into()),
        None => serde_json::Map::new(),
    };
    let stage_arguments = arguments
        .as_object()
        .ok_or_else(|| "caduceus-chord-stage-arguments-invalid".to_string())?;
    for (key, value) in stage_arguments {
        payload.insert(key.clone(), value.clone());
    }
    object.insert("payload".into(), Value::Object(payload));

    let mut routine = match object.get("routine") {
        Some(Value::Object(routine)) => routine.clone(),
        Some(Value::Null) | None => serde_json::Map::new(),
        Some(_) => return Err("caduceus-chord-routine-not-object".into()),
    };
    let mut stage = match routine.get("stage") {
        Some(Value::Object(stage)) => stage.clone(),
        Some(Value::Null) | None => serde_json::Map::new(),
        Some(_) => return Err("caduceus-chord-stage-not-object".into()),
    };
    stage.insert("stage_id".into(), json!(stage_id));
    stage.insert("arguments".into(), arguments.clone());
    routine.insert("request".into(), base_envelope.clone());
    routine.insert("routine_id".into(), json!(routine_id));
    routine.insert("stage".into(), Value::Object(stage));
    object.insert("routine".into(), Value::Object(routine));
    Ok(envelope)
}

async fn native_chord_run_steps(
    routine_id: &str,
    route_steps: &[Value],
    base_envelope: &Value,
    request_payload: &Value,
    total_started: Instant,
    total_deadline: Duration,
    is_finally: bool,
    state: &mut NativeChordState,
) {
    for raw_step in route_steps {
        let ordinal = state.next_ordinal;
        state.next_ordinal += 1;
        let step_id = raw_step
            .get("stage_id")
            .and_then(Value::as_str)
            .filter(|stage_id| !stage_id.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("step-{ordinal}"));
        let transition = raw_step
            .get("snake")
            .or_else(|| raw_step.get("rust"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        let required = raw_step
            .get("required")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        let declared_arguments = raw_step
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let unique_stage_id = state.seen.insert(step_id.clone());

        if !is_finally && state.skip_serve {
            let signal = if state.failed_stage.is_none() && required {
                "caduceus-chord-total-deadline-exceeded"
            } else {
                "caduceus-chord-required-stage-refused"
            };
            if required && state.failed_stage.is_none() {
                native_chord_mark_failed(state, &step_id, signal);
            }
            state.stages.push(native_chord_stage_row(
                &step_id,
                &transition,
                "stage-skipped",
                declared_arguments,
                json!({"ok":false,"firstMissingSignal":signal}),
            ));
            continue;
        }

        let parsed_step = crate::gate::discovery::RouteStep::from_value(raw_step);
        let step = match parsed_step {
            Ok(step) => step,
            Err(signal) => {
                state.stages.push(native_chord_stage_row(
                    &step_id,
                    &transition,
                    "stage-refused",
                    declared_arguments,
                    json!({"ok":false,"firstMissingSignal":signal}),
                ));
                if is_finally || required { native_chord_mark_failed(state, &step_id, &signal); }
                if !is_finally && required {
                    state.skip_serve = true;
                }
                continue;
            }
        };

        if !unique_stage_id {
            let signal = "caduceus-chord-stage-id-duplicate";
            state.stages.push(native_chord_stage_row(
                &step_id,
                &transition,
                "stage-refused",
                declared_arguments,
                json!({"ok":false,"firstMissingSignal":signal}),
            ));
            if is_finally || required { native_chord_mark_failed(state, &step_id, signal); }
            if !is_finally && step.required {
                state.skip_serve = true;
            }
            continue;
        }

        if let Some(dependency) = step
            .depends_on
            .iter()
            .find(|dependency| !is_finally && !state.completed.contains_key(*dependency))
        {
            let signal = "caduceus-chord-dependency-unresolved";
            state.stages.push(native_chord_stage_row(
                &step_id,
                &transition,
                "stage-refused",
                declared_arguments,
                json!({"ok":false,"dependency":dependency,"firstMissingSignal":signal}),
            ));
            if is_finally || required { native_chord_mark_failed(state, &step_id, signal); }
            if !is_finally && step.required {
                state.skip_serve = true;
            }
            continue;
        }

        if raw_step.get("arguments").is_some() && !declared_arguments.is_object() {
            let signal = "caduceus-chord-stage-arguments-invalid";
            state.stages.push(native_chord_stage_row(
                &step_id,
                &transition,
                "stage-refused",
                declared_arguments,
                json!({"ok":false,"firstMissingSignal":signal}),
            ));
            if is_finally || required { native_chord_mark_failed(state, &step_id, signal); }
            if !is_finally && step.required {
                state.skip_serve = true;
            }
            continue;
        }

        let resolved_arguments = match native_chord_resolve_arguments(
            &declared_arguments,
            request_payload,
            &state.completed,
        ) {
            Ok(arguments) => arguments,
            Err(signal) => {
                state.stages.push(native_chord_stage_row(
                    &step_id,
                    &transition,
                    "stage-refused",
                    declared_arguments,
                    json!({"ok":false,"firstMissingSignal":signal}),
                ));
                if is_finally || required { native_chord_mark_failed(state, &step_id, &signal); }
                if !is_finally && step.required {
                    state.skip_serve = true;
                }
                continue;
            }
        };

        let snake = match step.snake.as_deref().map(safe_band_path).transpose() {
            Ok(snake) => snake,
            Err(signal) => {
                state.stages.push(native_chord_stage_row(
                    &step_id,
                    &transition,
                    "stage-refused",
                    resolved_arguments,
                    json!({"ok":false,"firstMissingSignal":signal}),
                ));
                if is_finally || required { native_chord_mark_failed(state, &step_id, &signal); }
                if !is_finally && step.required {
                    state.skip_serve = true;
                }
                continue;
            }
        };

        let remaining = total_deadline.saturating_sub(total_started.elapsed());
        if remaining.is_zero() && !is_finally {
            let signal = "caduceus-chord-total-deadline-exceeded";
            state.stages.push(native_chord_stage_row(
                &step_id,
                &transition,
                "stage-skipped",
                resolved_arguments,
                json!({"ok":false,"firstMissingSignal":signal}),
            ));
            if is_finally || required { native_chord_mark_failed(state, &step_id, signal); }
            if !is_finally {
                state.skip_serve = true;
            }
            continue;
        }

        let stage_timeout = match step.deadline_seconds {
            Some(0) | Some(601..) => {
                let signal = "caduceus-snake-timeout-out-of-range";
                state.stages.push(native_chord_stage_row(
                    &step_id,
                    &transition,
                    "stage-refused",
                    resolved_arguments,
                    json!({"ok":false,"firstMissingSignal":signal}),
                ));
                if is_finally || required { native_chord_mark_failed(state, &step_id, signal); }
                if !is_finally && step.required {
                    state.skip_serve = true;
                }
                continue;
            }
            Some(seconds) => Duration::from_secs(seconds),
            None => Duration::from_secs(30),
        }
        .min(if is_finally { remaining.max(Duration::from_millis(1)) } else { remaining });

        let stage_envelope = match native_chord_request_envelope(
            base_envelope,
            routine_id,
            &step_id,
            &resolved_arguments,
        ) {
            Ok(envelope) => envelope,
            Err(signal) => {
                state.stages.push(native_chord_stage_row(
                    &step_id,
                    &transition,
                    "stage-refused",
                    resolved_arguments,
                    json!({"ok":false,"firstMissingSignal":signal}),
                ));
                if is_finally || required { native_chord_mark_failed(state, &step_id, &signal); }
                if !is_finally && step.required {
                    state.skip_serve = true;
                }
                continue;
            }
        };

        let result = if let Some(stage_snake) = snake {
            let context = crate::shared::load_trace::current();
            tokio::task::spawn_blocking(move || {
                crate::shared::load_trace::with_blocking_context(context, || {
                    execute_with_timeout(&stage_snake, &stage_envelope, stage_timeout)
                })
            }).await.map_err(|_| "caduceus-blocking-task-join-failed".to_string())
                .and_then(|result| result)
        } else if let Some(primitive) = step.rust.as_deref() {
            match tokio::time::timeout(stage_timeout, crate::shared::primitives::execute(primitive, &stage_envelope)).await {
                Ok(Ok(receipt)) => Ok(json!({"ok":receipt.get("ok").and_then(Value::as_bool)==Some(true), "receiptPayload":receipt})),
                Ok(Err(signal)) => Err(signal),
                Err(_) => Err("caduceus-rust-primitive-timeout".into()),
            }
        } else { Err("gate-route-step-must-name-one-band".into()) };

        let (outcome, receipt, failure_signal) = match result {
            Err(signal) => {
                // A timed-out or broken crossing cannot prove it changed nothing.
                state.changed = None;
                (
                    "stage-refused",
                    json!({"ok":false,"firstMissingSignal":signal}),
                    Some(signal),
                )
            },
            Ok(result) => {
                let receipt = result
                    .get("receiptPayload")
                    .cloned()
                    .unwrap_or(Value::Null);
                let crossing_ok = result.get("ok").and_then(Value::as_bool) == Some(true);
                let receipt_ok = receipt.get("ok").and_then(Value::as_bool) == Some(true);
                let stage_declaration = crate::routes::selected_declaration(&transition)
                    .and_then(|source| serde_json::from_str::<Value>(source).ok());
                let expected_schema = raw_step.get("receipt").and_then(Value::as_str).map(ToOwned::to_owned)
                    .or_else(|| stage_declaration.as_ref().and_then(|d| d.get("receipt").and_then(Value::as_str)
                        .or_else(|| d.pointer("/flags/receiptSchema").and_then(Value::as_str))).map(ToOwned::to_owned));
                let schema_ok = expected_schema.as_deref().is_none_or(|schema| crate::routes::leaf_schema::accepts(schema, &receipt));
                if !schema_ok {
                    state.changed = None;
                    ("stage-refused", receipt, Some("caduceus-schema-desync".to_owned()))
                } else {
                    let is_read = stage_declaration.as_ref().and_then(|d| d.get("mutation_allowed")).and_then(Value::as_bool) == Some(false);
                    if !is_read {
                        state.changed = match (state.changed, crate::gate::door::declared_receipt_change(expected_schema.as_deref(), &receipt)) {
                            (Some(previous), Some(current)) => Some(previous || current),
                            _ => None,
                        };
                    }
                    if crossing_ok && receipt_ok {
                        state.completed.insert(step_id.clone(), receipt.clone());
                        ("stage-completed", receipt, None)
                    } else {
                        let signal = receipt
                            .get("firstMissingSignal")
                            .and_then(Value::as_str)
                            .filter(|signal| *signal != "none")
                            .or_else(|| result.get("firstMissingSignal").and_then(Value::as_str))
                            .filter(|signal| *signal != "none")
                            .unwrap_or("caduceus-agathodaimon-refused")
                            .to_owned();
                        ("stage-refused", receipt, Some(signal))
                    }
                }
            }
        };

        if let Some(signal) = failure_signal.as_deref() {
            if is_finally || required { native_chord_mark_failed(state, &step_id, signal); }
            if !is_finally && step.required {
                state.skip_serve = true;
            }
        }
        state.stages.push(native_chord_stage_row(
            &step_id,
            &transition,
            outcome,
            resolved_arguments,
            receipt,
        ));
    }
}

/// Execute the declaration's serve chord and unconditional finally chord.
/// `routine_id` is the declaration namespace, independent of request values.
pub async fn execute_native_chord(
    namespace: &str,
    serve: &[Value],
    finally: &[Value],
    base_envelope: &Value,
    receipt_schema: &str,
    total_deadline: Duration,
) -> Result<Value, String> {
    if namespace.is_empty() {
        return Err("caduceus-chord-namespace-missing".into());
    }
    if receipt_schema.is_empty() {
        return Err("caduceus-chord-receipt-schema-missing".into());
    }
    if total_deadline.is_zero() {
        return Err("caduceus-chord-total-deadline-out-of-range".into());
    }
    if serve.is_empty() && finally.is_empty() {
        return Err("caduceus-chord-empty".into());
    }
    let routine_id = namespace;
    let empty_payload = Value::Object(serde_json::Map::new());
    let request_payload = base_envelope.get("payload").unwrap_or(&empty_payload);
    let total_started = Instant::now();
    let mut state = NativeChordState {
        stages: Vec::with_capacity(serve.len() + finally.len()),
        completed: std::collections::HashMap::new(),
        seen: std::collections::HashSet::new(),
        failed_stage: None,
        first_missing_signal: None,
        skip_serve: false,
        changed: Some(false),
        next_ordinal: 0,
    };

    // Reserve each finalizer's declared bound, capped at the whole budget.
    let reserve_seconds = finally.iter().fold(0u64, |sum, step| {
        sum.saturating_add(step.get("deadline_seconds").and_then(Value::as_u64).unwrap_or(30).clamp(1, 600))
    });
    let reserve = Duration::from_secs(reserve_seconds).min(total_deadline);
    native_chord_run_steps(
        routine_id,
        serve,
        base_envelope,
        request_payload,
        total_started,
        total_deadline.saturating_sub(reserve),
        false,
        &mut state,
    )
    .await;
    native_chord_run_steps(
        routine_id,
        finally,
        base_envelope,
        request_payload,
        total_started,
        total_deadline,
        true,
        &mut state,
    )
    .await;

    let ok = state.failed_stage.is_none();
    let mut aggregate = json!({
        "schema": receipt_schema,
        "namespace": namespace,
        "ok": ok,
        "routine_id": routine_id,
        "stages": state.stages,
        "failedStage": state.failed_stage,
        "firstMissingSignal": state.first_missing_signal.unwrap_or_else(|| "none".into())
    });
    if let Some(changed) = state.changed { aggregate["changed"] = json!(changed); }
    Ok(aggregate)
}
