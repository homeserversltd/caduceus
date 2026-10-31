use crate::shared::config;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const DEFAULT_HARMONIA_BIN: &str = "/usr/local/bin/harmonia";
const HARMONIA_PRESS_BAND: &str = "appliance/harmonia-press";
const HARMONIA_PRESS_LONG_DEADLINE: std::time::Duration =
    std::time::Duration::from_secs(24 * 60 * 60);

pub fn load_profile_value() -> Result<Value, String> {
    Ok(config::carapace().clone())
}

pub fn route(route_key: &str) -> Result<Value, String> {
    let profile = load_profile_value()?;
    profile
        .get("harmonia_routes")
        .and_then(|routes| routes.get(route_key))
        .cloned()
        .ok_or_else(|| format!("caduceus-harmonia-route-missing:{route_key}"))
}

pub fn build_argv(route: &Value, rest: &[String]) -> Result<Vec<String>, String> {
    let bin = route
        .get("bin")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_HARMONIA_BIN)
        .to_string();
    let mut args = route
        .get("args")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if let Some(flags) = route.get("flags").and_then(Value::as_object) {
        for flag in rest {
            if let Some(extra) = flags.get(flag).and_then(Value::as_array) {
                for item in extra {
                    if let Some(arg) = item.as_str() {
                        args.push(arg.to_string());
                    }
                }
            }
        }
    }
    if route
        .get("positional")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        args.extend(rest.iter().cloned());
    }
    let mut argv = vec![bin];
    argv.extend(args);
    Ok(argv)
}

const HARMONIA_TRANSCRIPT_DIR: &str = "var/lib/caduceus/harmonia-transcripts";

struct InvocationOutput {
    stdout: String,
    stderr: String,
    success: bool,
    exit_code: i32,
}

fn create_transcripts() -> io::Result<(String, File, File)> {
    let directory = config::path(HARMONIA_TRANSCRIPT_DIR);
    fs::create_dir_all(&directory)?;

    for _ in 0..3 {
        let invocation_id = uuid::Uuid::new_v4().to_string();
        let stdout_path = directory.join(format!("{invocation_id}.stdout"));
        let stderr_path = directory.join(format!("{invocation_id}.stderr"));
        let open_transcript = |path: &std::path::Path| {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path)
        };
        let stdout = match open_transcript(&stdout_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        let stderr = match open_transcript(&stderr_path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        };
        return Ok((invocation_id, stdout, stderr));
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate unique Harmonia transcript files",
    ))
}

fn strip_manager_footer(stderr: &mut String, invocation_id: &str) -> Option<(i32, bool)> {
    let without_final_newline = stderr.strip_suffix('\n')?;
    let (body, footer) = without_final_newline.rsplit_once('\n')?;
    let marker = format!("__CADUCEUS_HARMONIA_EXIT_V1_{invocation_id}__|");
    let values = footer.strip_prefix(&marker)?;
    let (exit_kind, exit_status) = values.split_once('|')?;
    if exit_status.contains('|') {
        return None;
    }

    let completion = match exit_kind {
        "exited" => {
            let code = exit_status.parse::<i32>().ok()?;
            (code, code == 0)
        }
        "killed" | "dumped" => (-1, false),
        _ => return None,
    };
    stderr.truncate(body.len());
    Some(completion)
}

// The staff band owns systemd-run and its dollar escaping. Caduceus sends the
// original program argv and transcript correlation id; the transient service
// itself remains systemd-owned if this caller is restarted.
fn invoke_harmonia_press_band(
    invocation_id: &str,
    argv: &[String],
    stdout_file: &File,
    stderr_file: &File,
) -> io::Result<std::process::ExitStatus> {
    let input = json!({
        "argv": argv,
        "invocation_id": invocation_id,
    });
    crate::gate::snake::crossing_path_with_streamed_output(
        HARMONIA_PRESS_BAND,
        &input,
        HARMONIA_PRESS_LONG_DEADLINE,
        stdout_file,
        stderr_file,
    )
}

fn invoke_in_transient_service(argv: &[String]) -> io::Result<InvocationOutput> {
    let (invocation_id, mut stdout_file, mut stderr_file) = create_transcripts()?;
    let manager_status =
        invoke_harmonia_press_band(&invocation_id, argv, &stdout_file, &stderr_file)?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    stdout_file.seek(SeekFrom::Start(0))?;
    stdout_file.read_to_end(&mut stdout_bytes)?;
    stderr_file.seek(SeekFrom::Start(0))?;
    stderr_file.read_to_end(&mut stderr_bytes)?;

    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let mut stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    let completion = strip_manager_footer(&mut stderr, &invocation_id);
    // A signal-terminated systemd-run can wake the still-alive waiter before the
    // detached child finishes; don't unlink incomplete streams.
    if completion.is_some() || manager_status.code().is_some() {
        let transcript_directory = config::path(HARMONIA_TRANSCRIPT_DIR);
        for stream in ["stdout", "stderr"] {
            let filename = format!("{invocation_id}.{stream}");
            if let Err(error) = fs::remove_file(transcript_directory.join(&filename)) {
                eprintln!("failed to remove Harmonia transcript {filename}: {error}");
            }
        }
    }
    let (exit_code, success) = completion.unwrap_or((
        manager_status.code().unwrap_or(-1),
        manager_status.success(),
    ));
    Ok(InvocationOutput {
        stdout,
        stderr,
        success,
        exit_code,
    })
}

fn bounded_line(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).find(|line| !line.is_empty())?;
    let end = line.char_indices().map(|(i, _)| i).take_while(|i| *i <= 256).last().unwrap_or(0);
    let end = if line.len() <= 256 { line.len() } else { end };
    Some(line[..end].to_string())
}

fn child_reported_failure(stdout: &str) -> bool {
    match serde_json::from_str::<Value>(stdout.trim()) {
        Ok(value) => value.get("ok").and_then(Value::as_bool) == Some(false),
        Err(_) => stdout.lines().any(|line| line.trim() == "ok=false"),
    }
}

fn child_signal(stdout: &str, stderr: &str, ok: bool) -> String {
    let json = serde_json::from_str::<Value>(stdout.trim()).ok();
    let declared = json.as_ref().and_then(|v| v.get("first_missing_signal")).and_then(Value::as_str)
        .and_then(bounded_line)
        .or_else(|| stdout.lines().filter_map(|line| line.strip_prefix("first_missing_signal=")).find_map(bounded_line));

    if let Some(signal) = declared {
        return signal;
    }
    if ok && !child_reported_failure(stdout) {
        return "none".to_string();
    }
    bounded_line(stderr).or_else(|| bounded_line(stdout))
        .unwrap_or_else(|| "caduceus-harmonia-command-failed".to_string())
}

pub fn invoke_body_to_json(route_key: &str, code: i32, body: &str) -> Value {
    let mut fields = serde_json::Map::new();
    for line in body.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        fields.insert(key.to_string(), Value::String(value.to_string()));
    }
    let json_fields = serde_json::from_str::<Value>(body.trim()).ok();
    let typed_string = |key: &str| {
        json_fields
            .as_ref()
            .and_then(|value| value.get(key))
            .and_then(Value::as_str)
            .or_else(|| fields.get(key).and_then(Value::as_str))
    };
    let ok = code == 0 && json_fields
        .as_ref()
        .and_then(|value| value.get("ok"))
        .and_then(Value::as_bool)
        .or_else(|| {
            fields
                .get("ok")
                .and_then(Value::as_str)
                .map(|value| value == "true")
        })
        .unwrap_or(true);
    json!({
        "schema": typed_string("schema").unwrap_or("caduceus.harmonia.invoke.v1"),
        "route": route_key,
        "ok": ok,
        "exitCode": code,
        "body": body,
        "firstMissingSignal": typed_string("first_missing_signal").and_then(bounded_line).unwrap_or_else(|| child_signal(body, "", ok))
    })
}

fn invoke_argv(route_key: &str, route_value: &Value, argv: &[String]) -> (i32, String) {
    let bin = argv.first().unwrap();
    let output = invoke_in_transient_service(argv);
    match output {
        Ok(result) => {
            let ok = result.success && !child_reported_failure(&result.stdout);
            if route_value
                .get("raw_json")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                // Harmonia receipts are authoritative even when the process refuses.
                // The refusal receipt is emitted on stdout by contract and must not
                // be replaced with sudo/stderr text.
                let signal = child_signal(&result.stdout, &result.stderr, ok);
                let body = if result.stdout.is_empty() {
                    signal
                } else if let Ok(mut value) = serde_json::from_str::<Value>(&result.stdout) {
                    if let Some(object) = value.as_object_mut() {
                        if object.get("first_missing_signal").and_then(Value::as_str).and_then(bounded_line).is_some() {
                            result.stdout
                        } else {
                            object.insert("first_missing_signal".to_string(), json!(signal));
                            value.to_string()
                        }
                    } else { format!("{}\nfirst_missing_signal={signal}\n", result.stdout) }
                } else if result.stdout.lines().filter_map(|line| line.strip_prefix("first_missing_signal=")).any(|value| bounded_line(value).is_some()) {
                    result.stdout
                } else {
                    format!("{}\nfirst_missing_signal={signal}\n", result.stdout)
                };
                return (result.exit_code, body);
            }
            let body = format!(
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute={route_key}\nok={ok}\nexit_code={}\ncommand={}\nfirst_missing_signal={}\n",
                result.exit_code,
                bin,
                child_signal(&result.stdout, &result.stderr, ok)
            );
            (result.exit_code, body)
        }
        Err(err) => {
            let body = format!(
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute={route_key}\nok=false\nfirst_missing_signal=caduceus-harmonia-command-failed:{err}\n"
            );
            (1, body)
        }
    }
}

pub fn invoke(route_key: &str, rest: &[String], dry_run: bool) -> (i32, String) {
    if dry_run {
        let body = format!(
            "schema=caduceus.harmonia.invoke.v1\nmutation=false\nroute={route_key}\nfirst_missing_signal=none\n"
        );
        return (0, body);
    }
    let route_value = match route(route_key) {
        Ok(value) => value,
        Err(err) => {
            let body = format!(
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute={route_key}\nok=false\nfirst_missing_signal={err}\n"
            );
            return (1, body);
        }
    };
    let argv = match build_argv(&route_value, rest) {
        Ok(value) => value,
        Err(err) => {
            let body = format!(
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute={route_key}\nok=false\nfirst_missing_signal={err}\n"
            );
            return (1, body);
        }
    };
    invoke_argv(route_key, &route_value, &argv)
}

pub fn invoke_with_args(route_key: &str, args: &[String]) -> (i32, String) {
    let route_value = match route(route_key) {
        Ok(value) => value,
        Err(err) => {
            let body = format!(
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute={route_key}\nok=false\nfirst_missing_signal={err}\n"
            );
            return (1, body);
        }
    };
    let bin = route_value
        .get("bin")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_HARMONIA_BIN)
        .to_string();
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(bin);
    argv.extend(args.iter().cloned());
    invoke_argv(route_key, &route_value, &argv)
}

pub fn invoke_update_module(module_id: &str, apply: bool) -> (i32, String) {
    let profile_ref = match config::harmonia_profile_index_path() {
        Ok(profile_ref) => profile_ref,
        Err(err) => {
            return (
                1,
                format!("schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute=update_module\nok=false\nfirst_missing_signal={err}\n"),
            )
        }
    };
    let mut args = vec![
        "update-module".to_string(),
        profile_ref,
        "--module".to_string(),
        module_id.to_string(),
    ];
    if apply {
        args.push("--apply".to_string());
    }
    invoke_with_args("update_module", &args)
}

const HARMONIA_ENGINE_LOCK: &str = "var/lib/harmonia/engine-run.lock";
const UPDATE_NOW_HANDOFF_LOCK: &str = "run/caduceus/harmonia-update-now-launch.lock";
const UPDATE_NOW_HISTORY: &str = "/api/v1/update/history";
const UPDATE_NOW_HANDOFF_WAIT: Duration = Duration::from_millis(1_000);
const UPDATE_NOW_START_WAIT: Duration = Duration::from_millis(1_800);
const UPDATE_NOW_SYSTEMCTL_WAIT: Duration = Duration::from_millis(150);
const UPDATE_NOW_POLL: Duration = Duration::from_millis(25);
const HARMONIA_EXIT_MARKER: &str = "__CADUCEUS_HARMONIA_EXIT_V1_";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EngineLockObservation {
    Idle,
    Live(u32),
}

fn live_harmonia_engine_pid() -> Result<EngineLockObservation, &'static str> {
    let path = config::path(HARMONIA_ENGINE_LOCK);
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(EngineLockObservation::Idle);
        }
        Err(_) => return Err("harmonia-update-lock-unreadable"),
    };
    if !file
        .metadata()
        .map_err(|_| "harmonia-update-lock-unreadable")?
        .is_file()
    {
        return Err("harmonia-update-lock-invalid");
    }
    let mut contents = String::new();
    file.take(128)
        .read_to_string(&mut contents)
        .map_err(|_| "harmonia-update-lock-unreadable")?;
    let pid = contents
        .trim()
        .strip_prefix("pid=")
        .ok_or("harmonia-update-lock-invalid")?
        .parse::<u32>()
        .map_err(|_| "harmonia-update-lock-invalid")?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err("harmonia-update-lock-invalid");
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return Ok(EngineLockObservation::Live(pid));
    }
    match io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(EngineLockObservation::Idle),
        Some(libc::EPERM) => Ok(EngineLockObservation::Live(pid)),
        _ => Err("harmonia-update-lock-pid-unavailable"),
    }
}

fn try_update_now_handoff_lock() -> Result<Option<File>, &'static str> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(config::path(UPDATE_NOW_HANDOFF_LOCK))
        .map_err(|_| "caduceus-update-handoff-lock-unavailable")?;
    if !file
        .metadata()
        .map_err(|_| "caduceus-update-handoff-lock-unavailable")?
        .is_file()
    {
        return Err("caduceus-update-handoff-lock-invalid");
    }
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        return Ok(Some(file));
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::WouldBlock
        || error.raw_os_error() == Some(libc::EWOULDBLOCK)
        || error.raw_os_error() == Some(libc::EAGAIN)
    {
        Ok(None)
    } else {
        Err("caduceus-update-handoff-lock-unavailable")
    }
}

fn cgroup_for_process(pid: Option<u32>) -> Result<String, &'static str> {
    let path = match pid {
        Some(pid) => format!("/proc/{pid}/cgroup"),
        None => "/proc/self/cgroup".to_string(),
    };
    let contents = fs::read_to_string(path).map_err(|_| "caduceus-update-cgroup-unavailable")?;
    let cgroup = contents.lines().find_map(|line| {
        if let Some((_, path)) = line.split_once("::") {
            return Some(path);
        }
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        controllers
            .split(',')
            .any(|controller| controller == "name=systemd")
            .then_some(path)
    });
    cgroup
        .filter(|path| path.starts_with('/') && !path.contains('\0'))
        .map(str::to_owned)
        .ok_or("caduceus-update-cgroup-unavailable")
}

fn transient_unit(cgroup: &str) -> Option<&str> {
    let unit = cgroup.rsplit('/').next()?;
    (unit.starts_with("run-")
        && unit.ends_with(".service")
        && unit.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'@' | b'.')
        }))
    .then_some(unit)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransientOwner {
    ThisInvocation,
    OtherInvocation,
    Unproven,
}

fn marker_invocation_id(text: &str) -> Option<String> {
    let remainder = text.split_once(HARMONIA_EXIT_MARKER)?.1;
    let candidate = remainder.split_once("__|")?.0;
    uuid::Uuid::parse_str(candidate)
        .ok()
        .map(|value| value.to_string())
}

// This is a read-only manager readback. Launch remains exclusively on the
// existing harmonia-press staff crossing above.
fn transient_owner(
    unit: &str,
    expected_cgroup: &str,
    invocation_id: &str,
) -> TransientOwner {
    let mut child = match Command::new("/usr/bin/systemctl")
        .arg("show")
        .arg("--no-pager")
        .arg("--property=ControlGroup")
        .arg("--property=ExecStopPost")
        .arg(unit)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return TransientOwner::Unproven,
    };
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < UPDATE_NOW_SYSTEMCTL_WAIT => {
                std::thread::sleep(UPDATE_NOW_POLL);
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return TransientOwner::Unproven;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return TransientOwner::Unproven;
            }
        }
    };
    if !status.success() {
        return TransientOwner::Unproven;
    }
    let Some(stdout) = child.stdout.take() else {
        return TransientOwner::Unproven;
    };
    let mut properties = String::new();
    if stdout
        .take(16 * 1024)
        .read_to_string(&mut properties)
        .is_err()
    {
        return TransientOwner::Unproven;
    }
    let observed_cgroup = properties
        .lines()
        .find_map(|line| line.strip_prefix("ControlGroup="));
    if observed_cgroup != Some(expected_cgroup) {
        return TransientOwner::Unproven;
    }
    match marker_invocation_id(&properties).as_deref() {
        Some(owner) if owner == invocation_id => TransientOwner::ThisInvocation,
        Some(_) => TransientOwner::OtherInvocation,
        None => TransientOwner::Unproven,
    }
}

fn update_engine_owner(
    pid: u32,
    caduceus_cgroup: &str,
    invocation_id: &str,
) -> TransientOwner {
    let Ok(engine_cgroup) = cgroup_for_process(Some(pid)) else {
        return TransientOwner::Unproven;
    };
    let within_caduceus = engine_cgroup == caduceus_cgroup
        || engine_cgroup.starts_with(&format!("{caduceus_cgroup}/"));
    if within_caduceus {
        return TransientOwner::Unproven;
    }
    let Some(unit) = transient_unit(&engine_cgroup) else {
        return TransientOwner::Unproven;
    };
    let owner = transient_owner(unit, &engine_cgroup, invocation_id);
    match (owner, live_harmonia_engine_pid()) {
        (TransientOwner::ThisInvocation, Ok(EngineLockObservation::Live(current)))
            if current == pid => TransientOwner::ThisInvocation,
        (TransientOwner::OtherInvocation, Ok(EngineLockObservation::Live(current)))
            if current == pid => TransientOwner::OtherInvocation,
        _ => TransientOwner::Unproven,
    }
}

fn update_now_response(
    code: i32,
    ok: bool,
    state: &str,
    signal: &str,
    started_at: Option<&str>,
    invocation_id: Option<&str>,
) -> Value {
    let dispatch = match (state, ok, invocation_id.is_some()) {
        ("started", _, _) => "initiated",
        ("unknown", true, _) => "accepted",
        ("busy", _, true) => "refused-busy",
        ("busy", _, false) => "not-dispatched",
        (_, true, _) => "accepted",
        _ => "not-dispatched",
    };
    let mut body = format!(
        "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute=update_now\nok={ok}\nexit_code={code}\nstate={state}\ndispatch={dispatch}\noutcome=null\nfirst_missing_signal={signal}\n"
    );
    if let Some(started_at) = started_at {
        body.push_str(&format!("started_at={started_at}\n"));
    }
    if let Some(invocation_id) = invocation_id {
        body.push_str(&format!("invocation_id={invocation_id}\ncorrelation_id={invocation_id}\n"));
    }
    body.push_str(&format!("history={UPDATE_NOW_HISTORY}\n"));
    let mut response = invoke_body_to_json("update_now", code, &body);
    response["state"] = json!(state);
    response["outcome"] = Value::Null;
    response["startedAt"] = json!(started_at);
    response["runId"] = Value::Null;
    response["invocationId"] = json!(invocation_id);
    response["history"] = json!(UPDATE_NOW_HISTORY);
    response
}

fn reap_harmonia_waiter(child: Child) {
    let _ = std::thread::Builder::new()
        .name("caduceus-harmonia-waiter".to_string())
        .spawn(move || {
            let mut child = child;
            let _ = child.wait();
        });
}

pub fn start_update_now_json() -> Value {
    let route_value = match route("update_now") {
        Ok(value) => value,
        Err(error) => {
            let signal = error.replace('\n', " ").replace('\r', " ");
            return update_now_response(1, false, "failed", &signal, None, None);
        }
    };
    let argv = match build_argv(&route_value, &[]) {
        Ok(argv) => argv,
        Err(error) => {
            let signal = error.replace('\n', " ").replace('\r', " ");
            return update_now_response(1, false, "failed", &signal, None, None);
        }
    };
    if argv.len() != 3
        || argv[0] != DEFAULT_HARMONIA_BIN
        || argv[1] != "update"
        || argv[2] != "--apply"
    {
        return update_now_response(
            1,
            false,
            "failed",
            "caduceus-harmonia-update-argv-invalid",
            None,
            None,
        );
    }
    let caduceus_cgroup = match cgroup_for_process(None) {
        Ok(cgroup) => cgroup,
        Err(signal) => return update_now_response(1, false, "failed", signal, None, None),
    };

    let handoff_deadline = Instant::now() + UPDATE_NOW_HANDOFF_WAIT;
    let handoff_guard = loop {
        match try_update_now_handoff_lock() {
            Ok(Some(guard)) => break guard,
            Ok(None) => match live_harmonia_engine_pid() {
                Ok(EngineLockObservation::Live(_)) => {
                    return update_now_response(
                        1,
                        false,
                        "busy",
                        "harmonia-update-busy",
                        None,
                        None,
                    );
                }
                Err(signal) => {
                    return update_now_response(1, false, "unknown", signal, None, None);
                }
                Ok(EngineLockObservation::Idle) => {
                    if Instant::now() >= handoff_deadline {
                        return update_now_response(
                            1,
                            false,
                            "unknown",
                            "caduceus-update-launch-handoff-unconfirmed",
                            None,
                            None,
                        );
                    }
                    std::thread::sleep(UPDATE_NOW_POLL);
                }
            },
            Err(signal) => return update_now_response(1, false, "failed", signal, None, None),
        }
    };

    match live_harmonia_engine_pid() {
        Ok(EngineLockObservation::Live(_)) => {
            return update_now_response(
                1,
                false,
                "busy",
                "harmonia-update-busy",
                None,
                None,
            );
        }
        Err(signal) => return update_now_response(1, false, "unknown", signal, None, None),
        Ok(EngineLockObservation::Idle) => {}
    }

    let invocation_id = uuid::Uuid::new_v4().to_string();
    let payload = json!({"argv": argv, "invocation_id": invocation_id});
    let started_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let child = match crate::gate::snake::crossing_spawn(HARMONIA_PRESS_BAND, &payload) {
        Ok(child) => child,
        Err(signal) => {
            return update_now_response(
                1,
                false,
                "failed",
                &signal.replace('\n', " ").replace('\r', " "),
                None,
                None,
            );
        }
    };
    reap_harmonia_waiter(child);

    let start_deadline = Instant::now() + UPDATE_NOW_START_WAIT;
    loop {
        match live_harmonia_engine_pid() {
            Ok(EngineLockObservation::Live(pid)) => {
                match update_engine_owner(pid, &caduceus_cgroup, &invocation_id) {
                    TransientOwner::ThisInvocation => {
                        drop(handoff_guard);
                        return update_now_response(
                            0,
                            true,
                            "started",
                            "none",
                            Some(&started_at),
                            Some(&invocation_id),
                        );
                    }
                    TransientOwner::OtherInvocation => {
                        drop(handoff_guard);
                        return update_now_response(
                            1,
                            false,
                            "busy",
                            "harmonia-update-busy",
                            None,
                            Some(&invocation_id),
                        );
                    }
                    TransientOwner::Unproven => {}
                }
            }
            Ok(EngineLockObservation::Idle) | Err(_) => {}
        }
        if Instant::now() >= start_deadline {
            drop(handoff_guard);
            return update_now_response(
                0,
                true,
                "unknown",
                "harmonia-update-start-unconfirmed",
                Some(&started_at),
                Some(&invocation_id),
            );
        }
        std::thread::sleep(UPDATE_NOW_POLL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_argv_keeps_harmonia_route_order() {
        let route = json!({
            "bin": "/usr/local/bin/harmonia",
            "args": ["run-profile", "/etc/harmonia/profiles/homeserver/index.json", "--apply"]
        });
        let argv = build_argv(&route, &[]).unwrap();
        assert_eq!(argv[0], "/usr/local/bin/harmonia");
        assert_eq!(argv[1], "run-profile");
        assert_eq!(argv[2], "/etc/harmonia/profiles/homeserver/index.json");
        assert_eq!(argv[3], "--apply");
    }

    #[test]
    fn privileged_command_uses_noninteractive_sudo_and_preserves_harmonia_argv() {
        let args = vec![
            "homeserver-update".to_string(),
            "/etc/harmonia/profiles/homeserver/index.json".to_string(),
            "--apply".to_string(),
        ];
        let command = privileged_command("/usr/local/bin/harmonia", &args);
        assert_eq!(command.get_program(), "sudo");
        assert_eq!(
            command
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec![
                "-n",
                "/usr/local/bin/harmonia",
                "homeserver-update",
                "/etc/harmonia/profiles/homeserver/index.json",
                "--apply",
            ]
        );
    }
}
