use crate::tools::config;
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
    let ok = fields
        .get("ok")
        .and_then(Value::as_str)
        .map(|value| value == "true")
        .unwrap_or(code == 0);
    json!({
        "schema": fields.get("schema").and_then(Value::as_str).unwrap_or("caduceus.harmonia.invoke.v1"),
        "route": route_key,
        "ok": ok,
        "exitCode": code,
        "body": body,
        "firstMissingSignal": fields.get("first_missing_signal").and_then(Value::as_str).unwrap_or(if ok { "none" } else { "caduceus-harmonia-command-failed" })
    })
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
    let (bin, run_args) = argv.split_first().unwrap();
    let output = privileged_command(bin, run_args).output();
    match output {
        Ok(result) => {
            let ok = result.status.success();
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
