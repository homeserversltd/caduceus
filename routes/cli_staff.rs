//! Short-lived CLI client of the running actuator's existing staff socket.
use serde_json::{json, Value};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const INPUT_LIMIT: u64 = 1024 * 1024;
const RESPONSE_LIMIT: u64 = 32 * 1024 * 1024;

fn input(required: bool) -> Result<Option<Vec<u8>>, String> {
    let mut bytes = Vec::new();
    io::stdin().take(INPUT_LIMIT + 1).read_to_end(&mut bytes)
        .map_err(|_| "caduceus-cli-stdin-unreadable".to_string())?;
    if bytes.len() as u64 > INPUT_LIMIT { return Err("pid2-envelope-too-large".into()); }
    if bytes.is_empty() && !required { return Ok(None); }
    Ok(Some(bytes))
}

// The terminal mode guard restores echo on every ordinary error path.
struct EchoGuard { tty: std::fs::File, saved: libc::termios }
impl Drop for EchoGuard {
    fn drop(&mut self) { unsafe { libc::tcsetattr(self.tty.as_raw_fd(), libc::TCSANOW, &self.saved); } }
}
fn prompt_pin() -> Result<Option<String>, String> {
    let mut tty = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        Ok(tty) => tty,
        Err(_) => return Ok(None),
    };
    let mut saved = std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe { libc::tcgetattr(tty.as_raw_fd(), saved.as_mut_ptr()) } != 0 {
        return Err("caduceus-cli-terminal-unavailable".into());
    }
    let saved = unsafe { saved.assume_init() };
    let mut hidden = saved;
    hidden.c_lflag &= !libc::ECHO;
    let guard = EchoGuard { tty: tty.try_clone().map_err(|_| "caduceus-cli-terminal-unavailable")?, saved };
    if unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSANOW, &hidden) } != 0 {
        return Err("caduceus-cli-terminal-unavailable".into());
    }
    // Use a separate handle so the guard always restores this same tty.
    let mut reader = tty.try_clone().map_err(|_| "caduceus-cli-terminal-unavailable")?;
    tty.write_all(b"Appliance PIN: ").map_err(|_| "caduceus-cli-terminal-unavailable")?;
    tty.flush().map_err(|_| "caduceus-cli-terminal-unavailable")?;
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        if reader.read(&mut byte).map_err(|_| "caduceus-cli-terminal-unavailable")? == 0 { break; }
        if byte[0] == b'\n' || byte[0] == b'\r' { break; }
        if bytes.len() == 512 { return Err("exousia-pin-invalid".into()); }
        bytes.push(byte[0]);
    }
    drop(guard);
    let _ = tty.write_all(b"\n");
    String::from_utf8(bytes).map(Some).map_err(|_| "exousia-pin-invalid".into())
}

fn pin_required() -> bool {
    crate::shared::config::get_json("global.admin.pin_required").ok()
        .and_then(|value| value.get("value").and_then(Value::as_bool)).unwrap_or(false)
}
fn attendance_input() -> Result<Option<Vec<u8>>, String> {
    if pin_required() && std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty").is_err() {
        input(false)
    } else {
        Ok(None)
    }
}
fn attend(body: &mut Value) -> Result<bool, String> {
    if !pin_required() {
        return Ok(false);
    }
    let Some(pin) = prompt_pin()? else { return Ok(false); };
    let object = body.as_object_mut().ok_or("caduceus-cli-envelope-invalid")?;
    let flags = object.entry("flags").or_insert_with(|| json!({}));
    let flags = flags.as_object_mut().ok_or("caduceus-cli-envelope-invalid")?;
    let exousia = flags.entry("exousia").or_insert_with(|| json!({}));
    exousia.as_object_mut().ok_or("caduceus-cli-envelope-invalid")?.insert("pin".into(), Value::String(pin));
    Ok(true)
}
fn parse_input(bytes: Option<&[u8]>) -> Result<Value, String> {
    match bytes {
        None => Ok(json!({})),
        Some(bytes) => {
            let value: Value = serde_json::from_slice(bytes).map_err(|_| "caduceus-cli-envelope-invalid")?;
            if !value.is_object() { return Err("caduceus-cli-envelope-invalid".into()); }
            Ok(value)
        }
    }
}
fn escape_segment(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) { result.push(byte as char); }
        else { result.push_str(&format!("%{byte:02X}")); }
    }
    result
}
fn exchange(method: &str, path: &str, body: &[u8], timeout: Duration) -> Result<(u16, Vec<u8>), String> {
    let path_socket = std::env::var_os("CADUCEUS_STAFF_SOCKET")
        .unwrap_or_else(|| "/run/caduceus/staff.sock".into());
    let mut stream = UnixStream::connect(path_socket).map_err(|_| "caduceus-serve-unavailable")?;
    stream.set_read_timeout(Some(timeout)).map_err(|_| "caduceus-serve-unavailable")?;
    stream.set_write_timeout(Some(timeout)).map_err(|_| "caduceus-serve-unavailable")?;
    let header = format!("{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
    stream.write_all(header.as_bytes()).and_then(|_| stream.write_all(body)).map_err(|_| "caduceus-serve-unavailable")?;
    let mut response = Vec::new();
    stream.take(RESPONSE_LIMIT + 1).read_to_end(&mut response).map_err(|_| "caduceus-serve-unavailable")?;
    if response.len() as u64 > RESPONSE_LIMIT { return Err("caduceus-serve-response-too-large".into()); }
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").ok_or("caduceus-serve-response-invalid")?;
    let header = std::str::from_utf8(&response[..split]).map_err(|_| "caduceus-serve-response-invalid")?;
    let status = header.lines().next().and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok()).ok_or("caduceus-serve-response-invalid")?;
    Ok((status, response[split + 4..].to_vec()))
}
fn output(result: Result<(u16, Vec<u8>), String>, noun: &str, verb: &str, walked: &[&str]) -> i32 {
    match result {
        Err(signal) => {
            // The exchange was attempted; a missing reply cannot establish whether the act ran.
            println!("{}", json!({
                "schema": "caduceus.staff.receipt.v1", "ok": false,
                "firstMissingSignal": signal, "doorSignal": signal,
                "stop": {"noun": noun, "verb": verb},
                "observed": {"words": walked, "walked": walked, "stopped_at": "exchange"},
                "could_change_to": null,
                "attempt": {"attempted": true, "step": "exchange"},
                "final_receipt": {"ok": false, "firstMissingSignal": signal}
            }));
            1
        }
        Ok((status, body)) => {
            let receipt: Option<Value> = serde_json::from_slice(&body).ok();
            let ok = receipt.as_ref().map(|value| {
                value.get("ok").and_then(Value::as_bool)
                    .or_else(|| value.pointer("/receiptPayload/ok").and_then(Value::as_bool))
                    .unwrap_or(true)
                    && value.get("converged").and_then(Value::as_bool) != Some(false)
                    && value.pointer("/receiptPayload/converged").and_then(Value::as_bool) != Some(false)
            }).unwrap_or(false);
            if io::stdout().write_all(&body).is_err() { return 1; }
            if (200..300).contains(&status) && ok { 0 } else { 1 }
        }
    }
}
fn refusal(signal: &str, noun: &str, verb: &str, walked: &[&str], stopped_at: &str, step: &str, could_change_to: Value) -> i32 {
    let words: Vec<String> = walked.iter().map(|word| (*word).to_owned()).collect();
    eprintln!("{signal}");
    println!("{}", super::cli_refusal(signal, noun, verb, &words, walked, None, stopped_at, step, could_change_to));
    1
}
fn input_refusal(signal: &str, noun: &str, verb: &str, walked: &[&str], step: &str) -> i32 {
    let stopped_at = if step == "envelope-parse" { "envelope-parse" } else { "input" };
    refusal(signal, noun, verb, walked, stopped_at, step, json!({"stdin": "one JSON object, the request payload"}))
}
/// Speak the universal door's request without altering the legacy clients.
pub(crate) fn one_name(namespace: &str, path: &str, declaration: &Value, exousia: bool) -> i32 {
    use std::io::IsTerminal;
    let (noun, verb) = namespace.rsplit_once('/').unwrap_or((namespace, ""));
    let walked: Vec<&str> = namespace.split('/').collect();
    let no_body = matches!(declaration.get("body").and_then(Value::as_str), Some("none" | "forbidden"));
    if exousia && pin_required() && no_body {
        return refusal("caduceus-cli-pin-needs-body", noun, verb, &walked, "pin", "pin-prompt", Value::Null);
    }
    let mut raw = Vec::new();
    if !io::stdin().is_terminal() {
        if io::stdin().take(INPUT_LIMIT + 1).read_to_end(&mut raw).is_err() {
            return input_refusal("caduceus-cli-stdin-unreadable", noun, verb, &walked, "input-read");
        }
        if raw.len() as u64 > INPUT_LIMIT {
            return input_refusal("pid2-envelope-too-large", noun, verb, &walked, "input-read");
        }
    }
    if !no_body {
        let mut value = if raw.is_empty() { json!({}) } else {
            match serde_json::from_slice::<Value>(&raw) {
                Ok(value) if value.is_object() => value,
                _ => return input_refusal("caduceus-cli-envelope-invalid", noun, verb, &walked, "envelope-parse"),
            }
        };
        if exousia && pin_required() {
            match attend(&mut value) {
                Ok(true) => raw = value.to_string().into_bytes(),
                Ok(false) => {},
                Err(signal) => return refusal(&signal, noun, verb, &walked, "pin", "pin-prompt", Value::Null),
            }
        }
    }
    let mut seconds = declaration.get("deadline_seconds").and_then(Value::as_u64).unwrap_or(30).max(30);
    if let Some(stages) = declaration.get("serve").and_then(Value::as_array) {
        for stage in stages { seconds = seconds.max(stage.get("deadline_seconds").and_then(Value::as_u64).unwrap_or(0)); }
    }
    let method = declaration.get("http_method").and_then(Value::as_str).unwrap_or("POST").to_ascii_uppercase();
    output(exchange(&method, path, &raw, Duration::from_secs(seconds.saturating_add(30))), noun, verb, &walked)
}

fn mutation(path: &str, mut value: Value, original: Option<Vec<u8>>, timeout: Duration, noun: &str, verb: &str, walked: &[&str]) -> i32 {
    let changed = match attend(&mut value) { Ok(changed) => changed, Err(signal) => {
        if signal == "caduceus-cli-envelope-invalid" {
            return input_refusal(&signal, noun, verb, walked, "envelope-parse");
        }
        let could_change_to = if signal == "exousia-pin-invalid" { json!({"pin": "typed at the terminal prompt; UTF-8; at most 512 bytes"}) } else { Value::Null };
        return refusal(&signal, noun, verb, walked, "pin", "pin-prompt", could_change_to);
    } };
    let body = if !changed { original.unwrap_or_else(|| value.to_string().into_bytes()) } else { value.to_string().into_bytes() };
    output(exchange("POST", path, &body, timeout), noun, verb, walked)
}
pub(crate) fn swap() -> i32 {
    let walked = ["storage", "nas", "role", "swap"];
    let raw = match attendance_input() { Ok(raw) => raw, Err(signal) => return input_refusal(&signal, "storage/nas/role", "swap", &walked, "input-read") };
    let value = match parse_input(raw.as_deref()) { Ok(value) => value, Err(signal) => return input_refusal(&signal, "storage/nas/role", "swap", &walked, "envelope-parse") };
    mutation("/api/v1/storage/nas/role/swap", value, raw, Duration::from_secs(1900), "storage/nas/role", "swap", &walked)
}
#[cfg(leaf_pid2)]
pub(crate) fn pid2(args: &[String]) -> i32 {
    match args {
        [verb] if verb == "list" => output(exchange("GET", "/api/v1/pid2/list", &[], Duration::from_secs(300)), "pid2", "list", &["list"]),
        [verb, id] if verb == "status" => output(exchange("GET", &format!("/api/v1/pid2/status/{}", escape_segment(id)), &[], Duration::from_secs(300)), "pid2", "status", &["status"]),
        [verb] if verb == "enable" => {
            let walked = ["pid2", "enable"];
            let raw = match input(true) { Ok(raw) => raw, Err(signal) => return input_refusal(&signal, "pid2", verb, &walked, "input-read") };
            let value = match parse_input(raw.as_deref()) { Ok(value) => value, Err(signal) => return input_refusal(&signal, "pid2", verb, &walked, "envelope-parse") };
            mutation("/api/v1/pid2/enable", value, raw, Duration::from_secs(300), "pid2", verb, &walked)
        }
        [verb, id] if ["disable", "start", "stop", "restart", "hold", "release"].contains(&verb.as_str()) => {
            let walked = ["pid2", verb.as_str()];
            let raw = match attendance_input() { Ok(raw) => raw, Err(signal) => return input_refusal(&signal, "pid2", verb, &walked, "input-read") };
            let supplied = match parse_input(raw.as_deref()) { Ok(value) => value, Err(signal) => return input_refusal(&signal, "pid2", verb, &walked, "envelope-parse") };
            let mut body = json!({"schema":crate::protocol::SCHEMA_ID,"intent_id":format!("cli:pid2:{verb}"),"transition":format!("pid2-{verb}"),"origin_of_intent":"near","payload":{}});
            if let Some(object) = supplied.as_object() {
                for (key, value) in object { body[key] = value.clone(); }
            }
            if !body["payload"].is_object() { return input_refusal("caduceus-cli-envelope-invalid", "pid2", verb, &walked, "envelope-parse"); }
            let field = if ["start", "stop", "restart"].contains(&verb.as_str()) { "unit" } else { "routine_id" };
            body["payload"][field] = json!(id);
            mutation(&format!("/api/v1/pid2/{verb}"), body, None, Duration::from_secs(300), "pid2", verb, &walked)
        }
        _ => {
            // The native CLI has already resolved the verb, not the argument words.
            let verb = args.first().map(String::as_str).unwrap_or("front-door");
            println!("{}", super::cli_refusal(
                "pid2-arguments-invalid", "pid2", verb, args, &[verb], None,
                "arguments", "argument-walk", json!({"help": format!("caduceus {verb} --help")}),
            ));
            1
        }
    }
}
