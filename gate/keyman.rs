use serde_json::{json, Map, Value};
use std::{collections::HashSet, io::{Read, Write}, os::unix::process::CommandExt, process::{Command, Stdio}, time::{Duration, Instant}};

const LIMIT: usize = 1024 * 1024;
const INPUT_LIMIT: usize = 64 * 1024;
const REDACTED: &str = "[REDACTED]";

fn secret_name(name: &str) -> bool {
    let n: String = name.chars().filter(|c| c.is_ascii_alphanumeric()).map(|c| c.to_ascii_lowercase()).collect();
    n.contains("password") || n.ends_with("pin") || matches!(n.as_str(), "key" | "keymaterial" | "privatekey" | "secretkey" | "seed" | "seedphrase" | "token" | "credential" | "passphrase" | "keybytes" | "keydata" | "keyfilematerial")
}
fn collect_strings(value: &Value, secrets: &mut HashSet<String>) {
    match value {
        Value::String(s) if !s.is_empty() => { secrets.insert(s.clone()); },
        Value::Array(a) => for v in a { collect_strings(v, secrets); },
        Value::Object(o) => for v in o.values() { collect_strings(v, secrets); },
        _ => {}
    }
}
fn collect_secrets(value: &Value, secrets: &mut HashSet<String>) {
    match value {
        Value::Array(a) => for v in a { collect_secrets(v, secrets); },
        Value::Object(o) => for (k, v) in o { if secret_name(k) { collect_strings(v, secrets); } else { collect_secrets(v, secrets); } },
        _ => {}
    }
}
fn scrub(value: &Value, secrets: &[String]) -> Value {
    match value {
        Value::String(s) => Value::String(secrets.iter().fold(s.clone(), |v, secret| v.replace(secret, REDACTED))),
        Value::Array(a) => Value::Array(a.iter().map(|v| scrub(v, secrets)).collect()),
        Value::Object(o) => {
            let mut out = Map::new();
            for (k, v) in o {
                let mut key = scrub(&json!(k), secrets).as_str().unwrap_or("").to_owned();
                let marker = (0xe000..0xf8ff).filter_map(char::from_u32).find(|c| secrets.iter().all(|s| !s.contains(*c))).unwrap_or('_');
                while out.contains_key(&key) { key.push(marker); }
                out.insert(key, if secret_name(k) { json!(REDACTED) } else { scrub(v, secrets) });
            }
            Value::Object(out)
        },
        _ => value.clone(),
    }
}
fn failure(verb: &str, signal: &str, planned: bool, attempt: Value, changed: Value, dispatched: bool) -> Value {
    let mut value = json!({"schema":"caduceus.staff.v1", "ok":false, "firstMissingSignal":signal,
        "mutationPerformed":changed, "backend":"keyman-rust-crown", "operation":verb,
        "planned":planned, "changed":changed, "details":null, "observed":null,
        "could-change":[verb], "attempt":attempt,
        "final":if dispatched { json!({"ok":false,"state":"unknown","signal":signal}) } else { json!({"ok":false,"signal":signal}) }});
    if dispatched { value["attempted-operation"] = json!(verb); }
    value
}
fn valid_string<'a>(payload: &'a Value, name: &str) -> Result<&'a str, ()> {
    payload.get(name).and_then(Value::as_str).filter(|s| !s.trim().is_empty() && !s.contains('\0')).ok_or(())
}
fn device_valid(s: &str) -> bool {
    let first = |b: u8| b.is_ascii_alphanumeric();
    let token = |b: u8| b.is_ascii_alphanumeric() || b"_.:@-".contains(&b);
    let segment = |part: &str| !part.is_empty() && part.len() <= 255 && first(part.as_bytes()[0]) && part.bytes().all(|b| token(b) || b == b'+');
    (!s.is_empty() && s.len() <= 128 && first(s.as_bytes()[0]) && s.bytes().all(token)) || s.strip_prefix("/dev/").is_some_and(|p| p.split('/').all(segment))
}
fn plan(verb: &str, payload: &Value) -> Result<(Vec<String>, Option<Value>, bool), ()> {
    let planned = match payload.get("planned") { None | Some(Value::Null) => false, Some(Value::Bool(b)) => *b, _ => return Err(()) };
    let strategy = || -> Result<&str, ()> { let s = valid_string(payload, "strategy")?; if matches!(s, "safe_rotation" | "replace_primary" | "flexible_addition") { Ok(s) } else { Err(()) } };
    match verb {
        "key-status" => Ok((vec![], None, planned)),
        "create-key" => {
            let target = valid_string(payload, "target")?;
            if !matches!(target, "vault" | "external" | "both") { return Err(()); }
            let strategy = strategy()?; let password = valid_string(payload, "password")?;
            Ok((vec!["--target".into(),target.into(),"--strategy".into(),strategy.into()], Some(json!({"password":password,"planned":planned})), planned))
        },
        "update-key" => {
            let device = valid_string(payload, "device")?; if !device_valid(device) { return Err(()); }
            let strategy = strategy()?; let password = valid_string(payload, "current_password")?;
            Ok((vec!["--device".into(),device.into(),"--strategy".into(),strategy.into()], Some(json!({"current_password":password,"planned":planned})), planned))
        },
        "admin-password" => Ok((vec![], Some(json!({"old_password":valid_string(payload,"old_password")?,"new_password":valid_string(payload,"new_password")?,"planned":planned})),planned)),
        _ => Err(())
    }
}
fn finish(verb: &str, mut result: Value, payload: &Value, backend: Option<&Value>) -> Value {
    let mut secret_set = HashSet::new(); collect_secrets(payload, &mut secret_set);
    if let Some(backend) = backend { collect_secrets(backend, &mut secret_set); }
    let mut secrets: Vec<_> = secret_set.into_iter().collect(); secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
    let mut envelope = crate::gate::snake::crossing_envelope(&format!("keyman/{verb}"), payload);
    envelope["version"] = json!(env!("CARGO_PKG_VERSION"));
    envelope["timestamp"] = json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true));
    let stamp = json!({"verb":verb,"outcome":if result["ok"] == true {"ok"} else {"failed"},"timestamp":chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros,true)});
    let safe_without_stamps = scrub(&envelope, &secrets);
    let mut raw = serde_json::to_string(&safe_without_stamps).unwrap_or_default();
    if raw.ends_with('}') {
        raw.pop();
        raw.push_str(",\"stamps\":");
        raw.push_str(&format!("[{{\"verb\":{},\"outcome\":{},\"timestamp\":{}}}]", stamp["verb"], stamp["outcome"], stamp["timestamp"]));
        raw.push('}');
    }
    let mut safe_envelope = safe_without_stamps;
    safe_envelope["stamps"] = json!([stamp.clone()]);
    result["intent_id"] = safe_envelope["intent_id"].clone();
    result["raw_envelope"] = json!(raw);
    result["envelope"] = safe_envelope;
    result["stamps"] = json!([stamp.clone()]); result["staff"] = stamp;
    scrub(&result, &secrets)
}
fn valid_signal(s: &str) -> bool { !s.is_empty() && s.len() <= 128 && s.as_bytes()[0].is_ascii_lowercase_or_digit() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.:-".contains(&b)) }
trait LowerOrDigit { fn is_ascii_lowercase_or_digit(&self) -> bool; }
impl LowerOrDigit for u8 { fn is_ascii_lowercase_or_digit(&self) -> bool { self.is_ascii_lowercase() || self.is_ascii_digit() } }

pub fn execute(verb: &str, payload: &Value, timeout: Duration) -> Result<Value, String> {
    let (args, document, planned) = match plan(verb, payload) {
        Ok(p) => p,
        Err(()) => return Ok(finish(verb, failure(verb,"keyman-field-invalid",false,Value::Null,json!(false),false), payload,None)),
    };
    let input = document.map(|v| serde_json::to_vec(&v).unwrap_or_default()).unwrap_or_default();
    if input.len() > INPUT_LIMIT { return Ok(finish(verb, failure(verb,"keyman-request-too-large",planned,Value::Null,json!(false),false),payload,None)); }
    let override_bin = std::env::var_os("CADUCEUS_KEYMAN_BIN");
    let timeout = if override_bin.is_some() {
        std::env::var("CADUCEUS_KEYMAN_FAKE_TIMEOUT_MS").ok().and_then(|s| s.parse::<u64>().ok()).filter(|v| *v > 0 && *v <= timeout.as_millis() as u64).map(Duration::from_millis).unwrap_or(timeout)
    } else { timeout };
    let mut command = if let Some(path) = override_bin { Command::new(path) } else { let mut c = Command::new("/usr/bin/sudo"); c.arg("-n").arg("/vault/keyman/keyman"); c };
    command.arg(verb).args(&args).process_group(0).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = match command.spawn() { Ok(c) => c, Err(_) => return Ok(finish(verb,failure(verb,"keyman-crown-timeout-or-unavailable",planned,json!({"command":"not-started"}),json!(false),false),payload,None)) };
    let pid = child.id();
    let mut stdin = child.stdin.take().ok_or("caduceus-keyman-stdin-unavailable")?;
    let writer = std::thread::spawn(move || { let r = stdin.write_all(&input); drop(stdin); r });
    let mut stdout = child.stdout.take().ok_or("caduceus-keyman-stdout-unavailable")?;
    let reader = std::thread::spawn(move || { let mut out = Vec::new(); let r = stdout.by_ref().take((LIMIT+1) as u64).read_to_end(&mut out); (r,out) });
    let deadline = Instant::now() + timeout;
    let mut status = None;
    loop {
        if status.is_none() { status = child.try_wait().map_err(|_| "caduceus-keyman-wait-failed")?; }
        if status.is_some() && writer.is_finished() && reader.is_finished() { break; }
        if Instant::now() >= deadline { unsafe { libc::kill(-(pid as i32), libc::SIGKILL); } let _ = child.wait(); let _ = writer.join(); let _ = reader.join(); return Err("caduceus-agathodaimon-timeout".into()); }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = writer.join(); let output = reader.join().map_err(|_| "caduceus-keyman-stdout-read-failed")?;
    let stdout = output.1; let code = status.and_then(|s| s.code()).map(Value::from).unwrap_or(Value::Null);
    if stdout.len() > LIMIT { return Ok(finish(verb,failure(verb,"keyman-crown-output-too-large",planned,json!({"returnCode":code}),Value::Null,true),payload,None)); }
    let backend: Value = match serde_json::from_slice::<Value>(&stdout) { Ok(v) if v.is_object() => v, _ => return Ok(finish(verb,failure(verb,"keyman-crown-receipt-invalid",planned,json!({"returnCode":code}),Value::Null,true),payload,None)) };
    let changed = backend.get("changed").and_then(Value::as_bool);
    let signal = backend.get("firstMissingSignal");
    if backend.get("ok").and_then(Value::as_bool).is_none() || changed.is_none() || backend.get("operation").and_then(Value::as_str) != Some(verb) || backend.get("planned").and_then(Value::as_bool) != Some(planned) || !(signal.is_some_and(Value::is_string) || (backend["ok"] == true && signal == Some(&Value::Null))) {
        return Ok(finish(verb,failure(verb,"keyman-crown-receipt-invalid",planned,json!({"returnCode":code}),changed.map(Value::Bool).unwrap_or(Value::Null),true),payload,Some(&backend)));
    }
    let changed = changed.unwrap();
    let mut signal = signal.and_then(Value::as_str).filter(|s| valid_signal(s)).unwrap_or(if backend["ok"] == true && backend["firstMissingSignal"].is_null() {"none"} else {"keyman-crown-command-failed"}).to_string();
    let mut ok = code == json!(0) && backend["ok"] == true && signal == "none";
    if backend["ok"] == false && signal == "none" { signal = "keyman-crown-command-refused".into(); }
    if code != json!(0) && signal == "none" { signal = "keyman-crown-command-failed".into(); }
    if planned && changed { ok = false; signal = "keyman-planned-mutation-reported".into(); }
    if ok { signal = "none".into(); }
    let receipt = json!({"schema":"caduceus.staff.v1","ok":ok,"firstMissingSignal":signal,"mutationPerformed":changed,"backend":"keyman-rust-crown","operation":verb,"planned":planned,"changed":changed,"details":backend.get("details"),"observed":backend.get("observed"),"could-change":backend.get("could-change").cloned().unwrap_or(json!([verb])),"attempt":backend.get("attempt").cloned().unwrap_or(json!({"returnCode":code})),"final":backend.get("final").cloned().unwrap_or(json!({"ok":ok,"changed":changed})),"attempted-operation":verb});
    Ok(finish(verb,receipt,payload,Some(&backend)))
}
