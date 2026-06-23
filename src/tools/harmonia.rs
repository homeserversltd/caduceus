use crate::tools::config;
use serde_json::Value;
use std::process::Command;

pub const DEFAULT_HARMONIA_BIN: &str = "/usr/local/bin/harmonia";

pub fn load_profile_value() -> Result<Value, String> {
    let raw = config::read_public_file("etc/caduceus/profile.json")?;
    serde_json::from_str(&raw).map_err(|err| format!("caduceus-profile-invalid: {err}"))
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
    let output = Command::new(bin).args(run_args).output();
    match output {
        Ok(result) => {
            let ok = result.status.success();
            let body = format!(
                "schema=caduceus.harmonia.invoke.v1\nmutation=true\nroute={route_key}\nok={ok}\nexit_code={}\ncommand={bin}\nfirst_missing_signal={}\n",
                result.status.code().unwrap_or(-1),
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
