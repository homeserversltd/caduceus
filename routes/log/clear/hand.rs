//! Native argument verbs are clients of the same Hyalos doors as the face.
use crate::shared::{attendance, hyalos};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const PIN_LIMIT: usize = 512;
const INPUT_LIMIT: u64 = 1024 * 1024;
const REPLY_LIMIT: u64 = 16 * 1024;
const SOCKET_UNAVAILABLE: &str = "caduceus-serve-unavailable";
const TERMINAL_UNAVAILABLE: &str = "caduceus-cli-terminal-unavailable";

struct HiddenInput(RawFd, libc::termios);
impl Drop for HiddenInput {
    fn drop(&mut self) {
        // The file outlives the guard, so restore this terminal even on a read error.
        unsafe { libc::tcsetattr(self.0, libc::TCSANOW, &self.1) };
    }
}

fn terminal_pin(mut tty: std::fs::File) -> Result<String, &'static str> {
    let mut saved = std::mem::MaybeUninit::uninit();
    let fd = tty.as_raw_fd();
    if unsafe { libc::tcgetattr(fd, saved.as_mut_ptr()) } != 0 {
        return Err(TERMINAL_UNAVAILABLE);
    }
    let saved = unsafe { saved.assume_init() };
    let mut hidden = saved;
    hidden.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(TERMINAL_UNAVAILABLE);
    }
    let guard = HiddenInput(fd, saved);
    tty.write_all(b"Appliance PIN: ").map_err(|_| TERMINAL_UNAVAILABLE)?;
    let mut bytes = Vec::new();
    BufReader::new((&tty).take((PIN_LIMIT + 2) as u64))
        .read_until(b'\n', &mut bytes)
        .map_err(|_| TERMINAL_UNAVAILABLE)?;
    drop(guard);
    let _ = tty.write_all(b"\n");
    if bytes.last() == Some(&b'\n') { bytes.pop(); }
    if bytes.last() == Some(&b'\r') { bytes.pop(); }
    if bytes.len() > PIN_LIMIT { return Err("exousia-pin-invalid"); }
    String::from_utf8(bytes).map_err(|_| "exousia-pin-invalid")
}

fn stdin_pin() -> Result<Option<Value>, &'static str> {
    let mut bytes = Vec::new();
    io::stdin().take(INPUT_LIMIT + 1).read_to_end(&mut bytes)
        .map_err(|_| "caduceus-cli-stdin-unreadable")?;
    if bytes.len() as u64 > INPUT_LIMIT { return Err("caduceus-cli-envelope-too-large"); }
    if bytes.is_empty() { return Ok(None); }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "caduceus-cli-envelope-invalid")?;
    if !value.is_object() { return Err("caduceus-cli-envelope-invalid"); }
    // Never accept action fields or a transport override from stdin.
    Ok(value.pointer("/flags/exousia/pin").cloned())
}

fn ask(path: &str, request: Option<Value>, dispatch_started: &mut bool) -> Result<bool, &'static str> {
    let (method, body) = match request {
        None => ("GET", String::new()),
        Some(mut body) => {
            // This read only chooses the input carrier: serve makes the
            // admission decision against its current config on every POST.
            if attendance::pin_mode_read().unwrap_or(false) {
                let pin = match std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
                    Ok(tty) => Some(Value::String(terminal_pin(tty)?)),
                    Err(_) => stdin_pin()?,
                };
                if let Some(pin) = pin { body["flags"] = json!({"exousia": {"pin": pin}}); }
            }
            ("POST", body.to_string())
        }
    };
    let socket = std::env::var_os("CADUCEUS_STAFF_SOCKET")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/run/caduceus/staff.sock"));
    let mut stream = UnixStream::connect(socket).map_err(|_| SOCKET_UNAVAILABLE)?;
    let timeout = Some(Duration::from_secs(300));
    stream.set_read_timeout(timeout).map_err(|_| SOCKET_UNAVAILABLE)?;
    stream.set_write_timeout(timeout).map_err(|_| SOCKET_UNAVAILABLE)?;
    // Once writing starts, a transport failure no longer proves that nothing ran.
    *dispatch_started = true;
    write!(stream, "{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len())
        .and_then(|_| stream.write_all(body.as_bytes()))
        .map_err(|_| SOCKET_UNAVAILABLE)?;
    drop(body);
    let mut response = Vec::new();
    stream.take(REPLY_LIMIT + 1).read_to_end(&mut response).map_err(|_| SOCKET_UNAVAILABLE)?;
    if response.len() as u64 > REPLY_LIMIT { return Err("caduceus-serve-response-too-large"); }
    let invalid = "caduceus-serve-response-invalid";
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").ok_or(invalid)?;
    let headers = std::str::from_utf8(&response[..split]).map_err(|_| invalid)?;
    let status: u16 = headers.lines().next().and_then(|line| line.split_whitespace().nth(1))
        .and_then(|word| word.parse().ok()).ok_or(invalid)?;
    let bytes = &response[split + 4..];
    let reply: Value = serde_json::from_slice(bytes).map_err(|_| invalid)?;
    let ok = reply["ok"].as_bool().ok_or(invalid)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(bytes).and_then(|_| stdout.write_all(b"\n"))
        .map_err(|_| "caduceus-cli-stdout-unavailable")?;
    Ok((200..300).contains(&status) && ok)
}

pub(crate) fn command(path: &str, request: Result<Option<Value>, &'static str>) -> i32 {
    let mut dispatch_started = false;
    match request.and_then(|body| ask(path, body, &mut dispatch_started)) {
        Ok(ok) => i32::from(!ok),
        Err(signal) => {
            let attempted = (!dispatch_started).then_some(false);
            let verb = if path == crate::routes::LEAF_LOG_LEVEL_CANONICAL {
                "level"
            } else {
                "clear"
            };
            println!(
                "{}",
                super::stamp_refusal(verb, hyalos::door_error(signal), attempted)
            );
            1
        }
    }
}
