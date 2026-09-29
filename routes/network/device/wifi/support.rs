use axum::{http::StatusCode, Json};
use serde_json::{json, Value};
use std::{
    env,
    io::Read,
    net::{IpAddr, Ipv4Addr},
    process::{Child, Command, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
const SCHEMA: &str = "caduceus.staff.v1";
const MAX_FIELD: usize = 128;
const MAX_DNS: usize = 256;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);
pub async fn execute(
    command: &'static str,
    action: &'static str,
    body: Value,
    declaration: &str,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let Some(object) = body.as_object() else {
        return refuse("wifi-body-not-object");
    };
    if object.contains_key("action") {
        return refuse("wifi-client-action-forbidden");
    };
    let plan = match build_plan(action, object, command) {
        Ok(v) => v,
        Err(e) => return refuse(e),
    };
    let allowed = match crate::shared::policy::allows_command(command) {
        Ok(v) => v,
        Err(_) => return refuse("caduceus-profile-missing"),
    };
    if !allowed {
        return refuse("caduceus-command-not-allowed");
    };
    let declaration_value: Value = match serde_json::from_str(declaration) {
        Ok(v) => v,
        Err(_) => return refuse("wifi-route-declaration-invalid"),
    };
    let route = declaration_value
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or(command);
    let intent_id = format!(
        "wifi-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        action
    );
    let envelope =
        json!({"schema":SCHEMA,"intent_id":intent_id,"transition":action,"origin_of_intent":route});
    let mut receipt = match crate::gate::receive(
        envelope,
        declaration_value
            .get("serve")
            .and_then(Value::as_array)
            .map_or(&[] as &[Value], Vec::as_slice),
        &declaration_value,
        false,
    ) {
        Ok(v) => v,
        Err(e) => return refuse(e),
    };
    let mutation = matches!(&plan, Plan::Mutation(_));
    let (success, result, failure) = match plan {
        Plan::Read(args) => match run_readonly_nmcli(&args) {
            Ok((stdout, _)) => (true, Some(parse_result(action, &stdout)), None),
            Err(error) => (false, None, Some(error)),
        },
        Plan::Mutation(payload) => {
            match crate::gate::snake::crossing_path("network/wifi", &payload) {
                Ok(receipt_payload) => {
                    let success = receipt_payload
                        .get("ok")
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let failure = if success {
                        None
                    } else {
                        Some(
                            receipt_payload
                                .get("firstMissingSignal")
                                .and_then(Value::as_str)
                                .unwrap_or("wifi-band-failed")
                                .to_string(),
                        )
                    };
                    let result = success.then(|| json!({"action":action,"completed":true}));
                    (success, result, failure)
                }
                Err(error) => (false, None, Some(error)),
            }
        }
    };
    if let Some(map) = receipt.as_object_mut() {
        map.insert("route".into(), Value::String(route.into()));
        map.insert("action".into(), Value::String(action.into()));
        map.insert("ok".into(), Value::Bool(success));
        map.insert(
            "mutationPerformed".into(),
            Value::Bool(mutation && success),
        );
        map.insert("planned".into(), Value::Bool(false));
        if let Some(v) = result {
            map.insert("result".into(), v);
        }
        if !success {
            map.insert(
                "first_missing_signal".into(),
                Value::String(failure.unwrap_or_else(|| "wifi-nmcli-failed".into())),
            );
        }
    }
    Ok((
        if success {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(receipt),
    ))
}
fn valid_text(v: &str, signal: &str, max: usize) -> Result<String, String> {
    if v.is_empty()
        || v.len() > max
        || v.bytes()
            .any(|b| b == 0 || b == b'\n' || b == b'\r' || b.is_ascii_control())
    {
        Err(signal.into())
    } else {
        Ok(v.into())
    }
}
fn text(o: &serde_json::Map<String, Value>, k: &str, max: usize) -> Result<String, String> {
    o.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("wifi-{k}-required"))
        .and_then(|v| valid_text(v, &format!("wifi-{k}-invalid"), max))
}
fn ip(v: &str, signal: &str) -> Result<Ipv4Addr, String> {
    match v.parse::<IpAddr>() {
        Ok(IpAddr::V4(x)) => Ok(x),
        _ => Err(signal.into()),
    }
}
fn cidr(v: &str) -> Result<String, String> {
    let (a, p) = v
        .split_once('/')
        .ok_or_else(|| "wifi-address-invalid".to_string())?;
    let a = ip(a, "wifi-address-invalid")?;
    let p: u8 = p.parse().map_err(|_| "wifi-address-invalid".to_string())?;
    if p > 32 {
        Err("wifi-address-invalid".into())
    } else {
        Ok(format!("{a}/{p}"))
    }
}
enum Plan {
    Read(Vec<String>),
    Mutation(Value),
}
fn build_plan(
    action: &str,
    o: &serde_json::Map<String, Value>,
    command: &str,
) -> Result<Plan, String> {
    match action {
        "scan" => Ok(Plan::Read(
            vec![
                "-t",
                "-f",
                "SSID,SECURITY,SIGNAL,DEVICE",
                "device",
                "wifi",
                "list",
                "--rescan",
                "yes",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        )),
        "status" => Ok(Plan::Read(
            vec![
                "-t",
                "-f",
                "NAME,UUID,TYPE,DEVICE",
                "connection",
                "show",
                "--active",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        )),
        "saved" => Ok(Plan::Read(
            vec!["-t", "-f", "NAME,UUID,TYPE", "connection", "show"]
                .into_iter()
                .map(String::from)
                .collect(),
        )),
        "connect" if command == "network device connect" => {
            Ok(Plan::Mutation(json!({
                "kind":"connect_device",
                "interface":text(o, "interface", MAX_FIELD)?
            })))
        }
        "connect" => {
            let password = match o.get("password") {
                Some(value) => {
                    let password = value
                        .as_str()
                        .ok_or_else(|| "wifi-password-invalid".to_string())?;
                    if password.len() > MAX_FIELD
                        || password
                            .bytes()
                            .any(|byte| matches!(byte, 0 | b'\n' | b'\r'))
                    {
                        return Err("wifi-password-invalid".into());
                    }
                    Some(password)
                }
                None => None,
            };
            let ssid = text(o, "ssid", MAX_FIELD)?;
            let mut payload = json!({"kind":"connect_wifi","ssid":ssid});
            if let Some(password) = password {
                payload["password"] = password.into();
            }
            Ok(Plan::Mutation(payload))
        }
        "radio" => match o.get("enabled").and_then(Value::as_bool) {
            Some(enabled) => Ok(Plan::Mutation(json!({"kind":"radio","enabled":enabled}))),
            None => Err("wifi-enabled-required".into()),
        },
        "disconnect" => Ok(Plan::Mutation(json!({
            "kind":"disconnect",
            "interface":text(o, "interface", MAX_FIELD)?
        }))),
        "forget" => Ok(Plan::Mutation(json!({
            "kind":"forget",
            "uuid":text(o, "uuid", MAX_FIELD)?
        }))),
        "ipv4" if command == "network device ipv4" => {
            ipv4_payload("ipv4_device", "interface", o)
        }
        "ipv4" => ipv4_payload("ipv4_wifi", "uuid", o),
        _ => Err("wifi-action-invalid".into()),
    }
}
fn ipv4_payload(
    kind: &str,
    target_field: &str,
    o: &serde_json::Map<String, Value>,
) -> Result<Plan, String> {
    let target = text(o, target_field, MAX_FIELD)?;
    let method = text(o, "method", 16)?;
    if method != "auto" && method != "static" {
        return Err("wifi-ipv4-method-invalid".into());
    }
    let is_static = method == "static";
    let mut payload = serde_json::Map::new();
    payload.insert("kind".into(), kind.into());
    payload.insert(target_field.into(), target.into());
    payload.insert("method".into(), method.into());
    if is_static {
        payload.insert("address".into(), cidr(&text(o, "address", MAX_FIELD)?)?.into());
        append_static_ipv4_options(&mut payload, o)?;
    }
    Ok(Plan::Mutation(Value::Object(payload)))
}

fn run_readonly_nmcli(args: &[String]) -> Result<(String, Vec<String>), String> {
    let fixture = env::var_os("CADUCEUS_ROOT").is_some();
    let executable = if fixture {
        env::var("CADUCEUS_NMCLI").unwrap_or_else(|_| "/usr/bin/nmcli".into())
    } else {
        "/usr/bin/nmcli".into()
    };
    let mut child = Command::new(executable)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "wifi-nmcli-unavailable".to_string())?;
    wait_child(&mut child)
}

fn wait_child(c: &mut Child) -> Result<(String, Vec<String>), String> {
    let start = std::time::Instant::now();
    loop {
        if let Some(s) = c.try_wait().map_err(|_| "wifi-nmcli-wait-failed")? {
            let mut b = Vec::new();
            c.stdout
                .take()
                .ok_or_else(|| "wifi-nmcli-output-failed".to_string())?
                .take(65536)
                .read_to_end(&mut b)
                .map_err(|_| "wifi-nmcli-output-failed")?;
            if !s.success() {
                return Err("wifi-nmcli-failed".into());
            }
            return Ok((String::from_utf8_lossy(&b).into(), Vec::new()));
        }
        if start.elapsed() >= COMMAND_TIMEOUT {
            let _ = c.kill();
            let _ = c.wait();
            return Err("wifi-nmcli-timeout".into());
        }
        std::thread::sleep(Duration::from_millis(10))
    }
}
fn parse_result(a: &str, s: &str) -> Value {
    let e = s
        .lines()
        .filter(|l| !l.trim().is_empty())
        .take(256)
        .filter_map(|l| {
            let f = l.split(':').map(str::trim).collect::<Vec<_>>();
            if matches!(a, "saved" | "status")
                && f.get(2).is_none_or(|v| {
                    !v.contains("802-11-wireless") && !v.eq_ignore_ascii_case("wifi")
                })
            {
                None
            } else {
                Some(f.into_iter().take(4).collect::<Vec<_>>())
            }
        })
        .collect::<Vec<_>>();
    json!({"action":a,"lineCount":e.len(),"entries":e})
}
fn append_static_ipv4_options(
    payload: &mut serde_json::Map<String, Value>,
    o: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    if let Some(gateway) = o.get("gateway") {
        let gateway = gateway
            .as_str()
            .ok_or_else(|| "wifi-gateway-required".to_string())?;
        if !gateway.is_empty() {
            payload.insert(
                "gateway".into(),
                ip(gateway, "wifi-gateway-invalid")?.to_string().into(),
            );
        }
    }
    if let Some(dns) = o.get("dns").and_then(Value::as_str) {
        if !dns.is_empty() {
            let dns = valid_text(dns, "wifi-dns-invalid", MAX_DNS)?;
            if dns
                .split(',')
                .any(|v| ip(v.trim(), "wifi-dns-invalid").is_err())
            {
                return Err("wifi-dns-invalid".into());
            }
            payload.insert("dns".into(), dns.into());
        }
    }
    Ok(())
}

fn refuse(s: impl Into<String>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    Err((
        StatusCode::FORBIDDEN,
        Json(
            json!({"schema":"caduceus.api.error.v1","ok":false,"command":"network device wifi","first_missing_signal":s.into()}),
        ),
    ))
}
