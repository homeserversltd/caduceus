use crate::shared::config;
use serde_json::{json, Value};
use std::process::Command;

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

fn privileged_command(bin: &str, run_args: &[String]) -> Command {
    let mut command = Command::new("sudo");
    command.arg("-n").arg(bin).args(run_args);
    command
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
    let (bin, run_args) = argv.split_first().unwrap();
    let output = privileged_command(bin, run_args).output();
    match output {
        Ok(result) => {
            let ok = result.status.success();
            if route_value
                .get("raw_json")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                // Harmonia receipts are authoritative even when the process refuses.
                // The refusal receipt is emitted on stdout by contract and must not
                // be replaced with sudo/stderr text.
                let body = String::from_utf8_lossy(if result.stdout.is_empty() {
                    &result.stderr
                } else {
                    &result.stdout
                })
                .into_owned();
                return (if ok { 0 } else { 1 }, body);
            }
            let body = format!(
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute={route_key}\nok={ok}\nexit_code={}\ncommand={}\nfirst_missing_signal={}\n",
                result.status.code().unwrap_or(-1),
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
