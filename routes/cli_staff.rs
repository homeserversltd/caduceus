//! Short-lived CLI client of the running actuator's existing staff socket.
use serde_json::{json, Value};
use std::io::{self, IsTerminal, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::Duration;

const INPUT_LIMIT: u64 = 1024 * 1024;
const RESPONSE_LIMIT: u64 = 32 * 1024 * 1024;

fn input(required: bool) -> Result<Option<Vec<u8>>, String> {
    if !required && io::stdin().is_terminal() { return Ok(None); }
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
        if bytes.len() == 512 { return Err("caduceus-cli-pin-too-long".into()); }
        bytes.push(byte[0]);
    }
    drop(guard);
    let _ = tty.write_all(b"\n");
    String::from_utf8(bytes).map(Some).map_err(|_| "caduceus-cli-pin-invalid".into())
}

fn pin_required() -> bool {
    crate::shared::config::get_json("global.admin.pin_required").ok()
        .and_then(|value| value.get("value").and_then(Value::as_bool)).unwrap_or(false)
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
fn output(result: Result<(u16, Vec<u8>), String>) -> i32 {
    match result {
        Err(signal) => { eprintln!("{signal}"); 1 }
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
fn mutation(path: &str, mut value: Value, original: Option<Vec<u8>>, timeout: Duration) -> i32 {
    let changed = match attend(&mut value) { Ok(changed) => changed, Err(signal) => { eprintln!("{signal}"); return 1; } };
    let body = if !changed { original.unwrap_or_else(|| value.to_string().into_bytes()) } else { value.to_string().into_bytes() };
    output(exchange("POST", path, &body, timeout))
}
pub(crate) fn swap() -> i32 {
    let raw = match input(false) { Ok(raw) => raw, Err(signal) => { eprintln!("{signal}"); return 1; } };
    let value = match parse_input(raw.as_deref()) { Ok(value) => value, Err(signal) => { eprintln!("{signal}"); return 1; } };
    mutation("/api/v1/storage/nas/role/swap", value, raw, Duration::from_secs(1900))
}
#[cfg(leaf_pid2)]
pub(crate) fn pid2(args: &[String]) -> i32 {
    match args {
        [verb] if verb == "list" => output(exchange("GET", "/api/v1/pid2/list", &[], Duration::from_secs(300))),
        [verb, id] if verb == "status" => output(exchange("GET", &format!("/api/v1/pid2/status/{}", escape_segment(id)), &[], Duration::from_secs(300))),
        [verb] if verb == "enable" => {
            let raw = match input(true) { Ok(raw) => raw, Err(signal) => { eprintln!("{signal}"); return 1; } };
            let value = match parse_input(raw.as_deref()) { Ok(value) => value, Err(signal) => { eprintln!("{signal}"); return 1; } };
            mutation("/api/v1/pid2/enable", value, raw, Duration::from_secs(300))
        }
        [verb, id] if ["disable", "start", "stop", "restart", "hold", "release"].contains(&verb.as_str()) => {
            let raw = match input(false) { Ok(raw) => raw, Err(signal) => { eprintln!("{signal}"); return 1; } };
            let supplied = match parse_input(raw.as_deref()) { Ok(value) => value, Err(signal) => { eprintln!("{signal}"); return 1; } };
            let mut body = json!({"schema":crate::protocol::SCHEMA_ID,"intent_id":format!("cli:pid2:{verb}"),"transition":format!("pid2-{verb}"),"origin_of_intent":"near","payload":{}});
            if let Some(object) = supplied.as_object() {
                for (key, value) in object { body[key] = value.clone(); }
            }
            if !body["payload"].is_object() { eprintln!("caduceus-cli-envelope-invalid"); return 1; }
            let field = if ["start", "stop", "restart"].contains(&verb.as_str()) { "unit" } else { "routine_id" };
            body["payload"][field] = json!(id);
            mutation(&format!("/api/v1/pid2/{verb}"), body, None, Duration::from_secs(300))
        }
        _ => { eprintln!("pid2-arguments-invalid"); 1 }
    }
}
