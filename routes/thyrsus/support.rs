//! Thyrsus speaks the staff's bare noun/verb CLI, not its envelope-band API.
use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Map, Value};
use std::{
    io::{Read, Write},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

const OUTPUT_LIMIT: u64 = 64 * 1024;
const DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy)]
pub(crate) enum Verb {
    Propose,
    Admit,
    ForgeToken,
    Forge,
}

impl Verb {
    fn name(self) -> &'static str {
        match self {
            Self::Propose => "propose",
            Self::Admit => "admit",
            Self::ForgeToken => "forge-token",
            Self::Forge => "forge",
        }
    }
    fn schema(self) -> &'static str {
        match self {
            Self::Propose => "caduceus.thyrsus.propose.v1",
            Self::Admit => "caduceus.thyrsus.admit.v1",
            Self::ForgeToken => "caduceus.thyrsus.forge-token.v1",
            Self::Forge => "caduceus.thyrsus.forge.v1",
        }
    }
    fn writes(self) -> bool {
        !matches!(self, Self::Forge)
    }
}

// The only secret buffer owned by the CLI crossing; never included in Debug or argv.
struct Secret(Vec<u8>);
impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
    }
}

fn refusal(verb: Verb, signal: &str) -> Value {
    json!({"schema": verb.schema(), "ok": false, "firstMissingSignal": signal})
}

fn text<'a>(body: &'a Value, field: &str) -> Result<&'a str, &'static str> {
    body.get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && !value.contains('\0'))
        .ok_or("thyrsus-request-invalid")
}

fn request(verb: Verb, mut body: Value) -> Result<(Vec<String>, Secret), &'static str> {
    let seat =
        crate::routes::leaf_schema::declaration(verb.schema()).ok_or("thyrsus-schema-desync")?;
    if body
        .get("schema")
        .is_some_and(|id| id.as_str() != Some(verb.schema()))
    {
        return Err("thyrsus-schema-desync");
    }
    let fields = seat["forms"]["request"]["required"]
        .as_array()
        .ok_or("thyrsus-schema-desync")?;
    if !body.is_object()
        || fields
            .iter()
            .any(|field| !field.as_str().is_some_and(|name| body.get(name).is_some()))
    {
        return Err("thyrsus-request-kernel-missing");
    }
    let mut args = vec!["thyrsus".into(), verb.name().into()];
    let mut secret = Secret(Vec::new());
    match verb {
        Verb::Propose | Verb::Admit => {
            let repo = text(&body, "repo")?;
            // A positional repository is never allowed to become a CLI option.
            if repo.starts_with('-') {
                return Err("thyrsus-request-invalid");
            }
            args.push(repo.into());
            if matches!(verb, Verb::Propose) {
                args.push("-m".into());
                args.push(text(&body, "message")?.into());
                match body.get("branch") {
                    None | Some(Value::Null) => {}
                    Some(Value::String(branch))
                        if !branch.is_empty()
                            && !branch.starts_with('-')
                            && !branch.contains('\0') =>
                    {
                        args.push("--branch".into());
                        args.push(branch.clone());
                    }
                    Some(_) => return Err("thyrsus-request-invalid"),
                }
            } else {
                let pr = body
                    .get("pr")
                    .and_then(|value| {
                        value
                            .as_u64()
                            .or_else(|| value.as_str().and_then(|value| value.parse::<u64>().ok()))
                    })
                    .filter(|pr| *pr > 0)
                    .ok_or("thyrsus-request-invalid")?;
                args.push(pr.to_string());
            }
        }
        Verb::ForgeToken => {
            let token = body
                .as_object_mut()
                .and_then(|object| object.remove("token"));
            let Some(Value::String(token)) = token else {
                return Err("thyrsus-request-invalid");
            };
            secret.0 = token.into_bytes();
            if secret.0.is_empty()
                || secret.0.len() > OUTPUT_LIMIT as usize
                || secret.0.iter().any(|byte| byte.is_ascii_control())
            {
                return Err("thyrsus-request-invalid");
            }
        }
        Verb::Forge => {}
    }
    // Additive request fields are skipped, never reinterpreted as flags or argv.
    Ok((args, secret))
}

fn named_signal(value: &Value) -> bool {
    value.as_str().is_some_and(|signal| {
        signal.len() <= 160
            && (signal == "none" || signal.starts_with("thyrsus-"))
            && signal.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
    })
}

fn receipt(
    verb: Verb,
    value: Value,
    exited_ok: bool,
    secret: &Secret,
) -> Result<Value, &'static str> {
    let object = value.as_object().ok_or("thyrsus-staff-receipt-invalid")?;
    let mut result = Map::new();
    result.insert("schema".into(), json!(verb.schema()));
    // Typed receipt projections skip unknown fields, especially child diagnostics
    // and envelopes. The setter can never echo a token supplied by a faulty staff.
    let fields: &[&str] = match verb {
        Verb::Propose => &["ok", "branch", "pr_url", "firstMissingSignal"],
        Verb::Admit => &["ok", "merged_sha", "firstMissingSignal"],
        Verb::ForgeToken => &["ok", "firstMissingSignal"],
        Verb::Forge => &[
            "ok",
            "forge",
            "token_present",
            "reachable",
            "firstMissingSignal",
        ],
    };
    for field in fields {
        if let Some(value) = object.get(*field) {
            let valid = match *field {
                "ok" | "token_present" | "reachable" => value.is_boolean(),
                "firstMissingSignal" => named_signal(value),
                _ => value.is_string() || value.is_null(),
            };
            if !valid {
                return Err("thyrsus-staff-receipt-invalid");
            }
            if !secret.0.is_empty()
                && value.as_str().is_some_and(|value| {
                    value
                        .as_bytes()
                        .windows(secret.0.len())
                        .any(|window| window == secret.0)
                })
            {
                return Err("thyrsus-staff-receipt-invalid");
            }
            result.insert((*field).into(), value.clone());
        }
    }
    let expected_ok = if matches!(verb, Verb::Forge) {
        object.get("ok").and_then(Value::as_bool) != Some(false)
            && ["forge", "token_present", "reachable"]
                .iter()
                .all(|field| result.contains_key(*field))
    } else {
        object.get("ok").and_then(Value::as_bool) == Some(true)
    };
    if !exited_ok || !expected_ok {
        result.insert("ok".into(), json!(false));
        if !result
            .get("firstMissingSignal")
            .is_some_and(|signal| signal.as_str() != Some("none"))
        {
            result.insert("firstMissingSignal".into(), json!("thyrsus-staff-refused"));
        }
    }
    Ok(Value::Object(result))
}

fn invoke(verb: Verb, args: Vec<String>, secret: Secret) -> Result<Value, &'static str> {
    let cli = crate::gate::snake::cli_path();
    let mut command = if std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some() {
        Command::new(&cli)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("-n").arg(&cli);
        command
    };
    let mut child = command
        .args(args)
        .stdin(if matches!(verb, Verb::ForgeToken) {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "thyrsus-staff-unavailable")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("thyrsus-staff-output-unavailable")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(OUTPUT_LIMIT + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let stdin = child.stdin.take();
    let writer = std::thread::spawn(move || {
        let written = stdin.map_or(Ok(()), |mut stdin| stdin.write_all(&secret.0));
        (written, secret)
    });
    let deadline = Instant::now() + DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let (written, secret) = writer.join().map_err(|_| "thyrsus-staff-stdin-failed")?;
    let bytes = reader
        .join()
        .map_err(|_| "thyrsus-staff-output-invalid")?
        .map_err(|_| "thyrsus-staff-output-invalid")?;
    let status = status.ok_or("thyrsus-staff-timeout")?;
    // Preserve a structured staff refusal even if it exits before reading stdin.
    if bytes.len() > OUTPUT_LIMIT as usize {
        return Err("thyrsus-staff-output-too-large");
    }
    let value = serde_json::from_slice(&bytes).map_err(|_| "thyrsus-staff-receipt-invalid")?;
    let value = receipt(verb, value, status.success(), &secret)?;
    if written.is_err() && status.success() {
        return Err("thyrsus-staff-stdin-failed");
    }
    Ok(value)
}

fn reflect(verb: Verb, value: &Value, started: Instant) {
    let ok = value.get("ok").and_then(Value::as_bool) != Some(false);
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ": "thyrsus", "kind": "deed", "level": if ok { "info" } else { "error" },
        "ok": ok, "message": "Thyrsus staff crossing",
        "attributes_redacted": {"who": "owner", "verb": verb.name(), "target": "thyrsus",
            "outcome": if ok { "complete" } else { "refused" },
            "duration_ms": started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "signal": value.get("firstMissingSignal").and_then(Value::as_str).unwrap_or("none")}
    }));
}

pub(crate) async fn handle(verb: Verb, body: Result<Json<Value>, JsonRejection>) -> Response {
    let started = Instant::now();
    let value = match body {
        Ok(Json(body)) => match request(verb, body) {
            Ok((args, secret)) => {
                match tokio::task::spawn_blocking(move || invoke(verb, args, secret)).await {
                    Ok(Ok(value)) => value,
                    Ok(Err(signal)) => refusal(verb, signal),
                    Err(_) => refusal(verb, "thyrsus-staff-task-failed"),
                }
            }
            Err(signal) => refusal(verb, signal),
        },
        Err(_) => refusal(verb, "thyrsus-request-invalid"),
    };
    if verb.writes() {
        reflect(verb, &value, started);
    }
    let status = if value.get("ok").and_then(Value::as_bool) == Some(false) {
        if value["firstMissingSignal"]
            .as_str()
            .is_some_and(|signal| signal.starts_with("thyrsus-request-"))
        {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        }
    } else {
        StatusCode::OK
    };
    (status, Json(value)).into_response()
}
