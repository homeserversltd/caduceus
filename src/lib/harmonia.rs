use crate::shared::config;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};

pub const DEFAULT_HARMONIA_BIN: &str = "/usr/local/bin/harmonia";

pub fn load_profile_value() -> Result<Value, String> {
    config::read_public_profile_value()
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

// D-Bus-created transient command arguments do not expand '%' specifiers, but
// systemd still expands '$' in command arguments. Double only '$' so literal
// application arguments survive while percent bytes remain unchanged.
fn escaped_systemd_argument(argument: &str) -> String {
    argument.replace('$', "$$")
}

// The transient D-Bus property leaves '%' alone; printf needs real %s
// conversions in its format string. Double '$' so the shell receives variables.
fn exec_stop_post_property(invocation_id: &str) -> String {
    format!(
        "ExecStopPost=/bin/sh -c 'printf \"\\n__CADUCEUS_HARMONIA_EXIT_V1_{invocation_id}__|%s|%s\\n\" \"$$EXIT_CODE\" \"$$EXIT_STATUS\" >&2'"
    )
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

fn invoke_in_transient_service(argv: &[String]) -> io::Result<InvocationOutput> {
    let (invocation_id, mut stdout_file, mut stderr_file) = create_transcripts()?;
    let mut command = Command::new("sudo");
    command
        .arg("-n")
        .arg("/usr/bin/systemd-run")
        .args(["--quiet", "--wait", "--pipe", "--collect"])
        .arg("--property")
        .arg(exec_stop_post_property(&invocation_id))
        .arg("--")
        .args(
            argv.iter()
                .map(|argument| escaped_systemd_argument(argument)),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file.try_clone()?))
        .stderr(Stdio::from(stderr_file.try_clone()?));

    let manager_status = command.status()?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    stdout_file.seek(SeekFrom::Start(0))?;
    stdout_file.read_to_end(&mut stdout_bytes)?;
    stderr_file.seek(SeekFrom::Start(0))?;
    stderr_file.read_to_end(&mut stderr_bytes)?;

    let stdout = String::from_utf8_lossy(&stdout_bytes).into_owned();
    let mut stderr = String::from_utf8_lossy(&stderr_bytes).into_owned();
    let completion = strip_manager_footer(&mut stderr, &invocation_id);
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
    let ok = json_fields
        .as_ref()
        .and_then(|value| value.get("ok"))
        .and_then(Value::as_bool)
        .or_else(|| {
            fields
                .get("ok")
                .and_then(Value::as_str)
                .map(|value| value == "true")
        })
        .unwrap_or(code == 0);
    json!({
        "schema": typed_string("schema").unwrap_or("caduceus.harmonia.invoke.v1"),
        "route": route_key,
        "ok": ok,
        "exitCode": code,
        "body": body,
        "firstMissingSignal": typed_string("first_missing_signal").unwrap_or(if ok { "none" } else { "caduceus-harmonia-command-failed" })
    })
}

fn invoke_argv(route_key: &str, route_value: &Value, argv: &[String]) -> (i32, String) {
    let bin = argv.first().unwrap();
    let output = invoke_in_transient_service(argv);
    match output {
        Ok(result) => {
            let ok = result.success;
            if route_value
                .get("raw_json")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                // Harmonia receipts are authoritative even when the process refuses.
                // The refusal receipt is emitted on stdout by contract and must not
                // be replaced with sudo/stderr text.
                let body = if result.stdout.is_empty() {
                    result.stderr
                } else {
                    result.stdout
                };
                return (if ok { 0 } else { 1 }, body);
            }
            let body = format!(
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute={route_key}\nok={ok}\nexit_code={}\ncommand={}\nfirst_missing_signal={}\n",
                result.exit_code,
                bin,
                if ok { "none" } else { "caduceus-harmonia-command-failed" }
            );
            (if ok { 0 } else { 1 }, body)
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
    let profile_ref = match load_profile_value()
        .ok()
        .and_then(|profile| profile.get("harmonia_profile").and_then(Value::as_str).map(str::to_owned))
    {
        Some(profile_ref) => profile_ref,
        None => {
            return (
                1,
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute=update_module\nok=false\nfirst_missing_signal=caduceus-harmonia-profile-missing\n".to_string(),
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
