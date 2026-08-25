use axum::{http::StatusCode, Json};
use serde_json::{json, Value};
use std::{
    env,
    io::{Read, Write},
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
    let args = match build_args(action, object, command) {
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
        json!({"schema":SCHEMA,"intent_id":intent_id,"transition":action,"target":route});
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
    let password = object
        .get("password")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    let outcome = if action == "ipv4" && command == "network device ipv4" {
        run_ipv4_interface_sequence(object)
    } else if action == "ipv4" {
        run_ipv4_sequence(&args)
    } else {
        run_nmcli(&args, password)
    };
    let result = outcome.as_ref().ok().map(|(s, _)| parse_result(action, s));
    let success = outcome.is_ok();
    if let Some(map) = receipt.as_object_mut() {
        map.insert("route".into(), Value::String(route.into()));
        map.insert("action".into(), Value::String(action.into()));
        map.insert("ok".into(), Value::Bool(success));
        map.insert(
            "mutationPerformed".into(),
            Value::Bool(is_mutation(action) && success),
        );
        map.insert("planned".into(), Value::Bool(false));
        if let Some(v) = result {
            map.insert("result".into(), v);
        }
        if !success {
            map.insert(
                "first_missing_signal".into(),
                Value::String(outcome.err().unwrap_or_else(|| "wifi-nmcli-failed".into())),
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
fn build_args(
    a: &str,
    o: &serde_json::Map<String, Value>,
    command: &str,
) -> Result<Vec<String>, String> {
    match a {
        "scan" => Ok(vec![
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
        .collect()),
        "status" => Ok(vec![
            "-t",
            "-f",
            "NAME,UUID,TYPE,DEVICE",
            "connection",
            "show",
            "--active",
        ]
        .into_iter()
        .map(String::from)
        .collect()),
        "saved" => Ok(vec!["-t", "-f", "NAME,UUID,TYPE", "connection", "show"]
            .into_iter()
            .map(String::from)
            .collect()),
        "connect" if command == "network device connect" => Ok(vec![
            "device".into(),
            "connect".into(),
            text(o, "interface", MAX_FIELD)?,
        ]),
        "connect" => {
            if let Some(password) = o.get("password") {
                if !password.is_string() {
                    return Err("wifi-password-invalid".into());
                }
            }
            let mut x = vec![
                "device".into(),
                "wifi".into(),
                "connect".into(),
                text(o, "ssid", MAX_FIELD)?,
            ];
            if o.get("password")
                .and_then(Value::as_str)
                .is_some_and(|v| !v.is_empty())
            {
                x.insert(0, "--ask".into());
            }
            Ok(x)
        }
        "radio" => Ok(vec![
            "radio".into(),
            "wifi".into(),
            match o.get("enabled").and_then(Value::as_bool) {
                Some(true) => "on".into(),
                Some(false) => "off".into(),
                None => return Err("wifi-enabled-required".into()),
            },
        ]),
        "disconnect" => Ok(
            vec!["device", "disconnect", &text(o, "interface", MAX_FIELD)?]
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        "forget" => Ok(
            vec!["connection", "delete", "uuid", &text(o, "uuid", MAX_FIELD)?]
                .into_iter()
                .map(String::from)
                .collect(),
        ),
        "ipv4" if command == "network device ipv4" => {
            let _ = text(o, "interface", MAX_FIELD)?;
            let _ = build_ipv4_modify_args("validated", o)?;
            Ok(Vec::new())
        }
        "ipv4" => {
            let u = text(o, "uuid", MAX_FIELD)?;
            let m = text(o, "method", 16)?;
            if m != "auto" && m != "static" {
                return Err("wifi-ipv4-method-invalid".into());
            }
            let mut x = vec![
                "connection".into(),
                "modify".into(),
                "uuid".into(),
                u,
                "ipv4.method".into(),
                if m == "static" {
                    "manual".into()
                } else {
                    "auto".into()
                },
            ];
            if m == "static" {
                x.extend([
                    "ipv4.addresses".into(),
                    cidr(&text(o, "address", MAX_FIELD)?)?,
                    "ipv4.gateway".into(),
                    ip(&text(o, "gateway", MAX_FIELD)?, "wifi-gateway-invalid")?.to_string(),
                ]);
                if let Some(d) = o.get("dns").and_then(Value::as_str) {
                    let d = valid_text(d, "wifi-dns-invalid", MAX_DNS)?;
                    if d.split(',')
                        .any(|v| ip(v.trim(), "wifi-dns-invalid").is_err())
                    {
                        return Err("wifi-dns-invalid".into());
                    }
                    x.extend(["ipv4.dns".into(), d])
                }
            } else {
                x.extend([
                    "ipv4.addresses".into(),
                    "".into(),
                    "ipv4.gateway".into(),
                    "".into(),
                    "ipv4.dns".into(),
                    "".into(),
                ])
            }
            Ok(x)
        }
        _ => Err("wifi-action-invalid".into()),
    }
}
fn is_mutation(a: &str) -> bool {
    matches!(a, "radio" | "connect" | "disconnect" | "forget" | "ipv4")
}
fn run_nmcli(args: &[String], password: Option<&str>) -> Result<(String, Vec<String>), String> {
    let exe = env::var("CADUCEUS_NMCLI").unwrap_or_else(|_| "nmcli".into());
    let mut c = Command::new(exe)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "wifi-nmcli-unavailable".to_string())?;
    if let Some(s) = password {
        let mut i = c
            .stdin
            .take()
            .ok_or_else(|| "wifi-stdin-unavailable".to_string())?;
        i.write_all(s.as_bytes())
            .map_err(|_| "wifi-stdin-write-failed")?;
        i.write_all(b"\n").map_err(|_| "wifi-stdin-write-failed")?
    } else {
        drop(c.stdin.take())
    }
    wait_child(&mut c)
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
    if is_mutation(a) {
        json!({"action":a,"completed":true})
    } else {
        json!({"action":a,"lineCount":e.len(),"entries":e})
    }
}
fn run_ipv4_interface_sequence(
    o: &serde_json::Map<String, Value>,
) -> Result<(String, Vec<String>), String> {
    let interface = text(o, "interface", MAX_FIELD)?;
    let query = vec![
        "-t",
        "-f",
        "NAME,UUID,TYPE,DEVICE",
        "connection",
        "show",
        "--active",
    ]
    .into_iter()
    .map(String::from)
    .collect::<Vec<_>>();
    let (active, _) = run_nmcli(&query, None)?;
    let uuid = active
        .lines()
        .find_map(|line| {
            let fields = line.split(':').map(str::trim).collect::<Vec<_>>();
            let (uuid, device) = if fields.len() >= 4 {
                (fields.get(1)?, fields.get(3)?)
            } else {
                (fields.first()?, fields.get(1)?)
            };
            (*device == interface && !uuid.is_empty()).then(|| (*uuid).to_string())
        })
        .ok_or_else(|| "wifi-interface-active-connection-missing".to_string())?;
    let modify = build_ipv4_modify_args(&uuid, o)?;
    let (mut out, _) = run_nmcli(&modify, None)?;
    for args in [
        vec![
            "connection".into(),
            "down".into(),
            "uuid".into(),
            uuid.clone(),
        ],
        vec!["connection".into(), "up".into(), "uuid".into(), uuid],
    ] {
        let (chunk, _) = run_nmcli(&args, None)?;
        out.push_str(&chunk);
    }
    Ok((out, Vec::new()))
}
fn build_ipv4_modify_args(
    key: &str,
    o: &serde_json::Map<String, Value>,
) -> Result<Vec<String>, String> {
    let m = text(o, "method", 16)?;
    if m != "auto" && m != "static" {
        return Err("wifi-ipv4-method-invalid".into());
    }
    let mut x = vec![
        "connection".into(),
        "modify".into(),
        "uuid".into(),
        key.into(),
        "ipv4.method".into(),
        if m == "static" {
            "manual".into()
        } else {
            "auto".into()
        },
    ];
    if m == "static" {
        x.extend([
            "ipv4.addresses".into(),
            cidr(&text(o, "address", MAX_FIELD)?)?,
            "ipv4.gateway".into(),
            ip(&text(o, "gateway", MAX_FIELD)?, "wifi-gateway-invalid")?.to_string(),
        ]);
        if let Some(d) = o.get("dns").and_then(Value::as_str) {
            let d = valid_text(d, "wifi-dns-invalid", MAX_DNS)?;
            if d.split(',')
                .any(|v| ip(v.trim(), "wifi-dns-invalid").is_err())
            {
                return Err("wifi-dns-invalid".into());
            }
            x.extend(["ipv4.dns".into(), d]);
        }
    } else {
        x.extend([
            "ipv4.addresses".into(),
            "".into(),
            "ipv4.gateway".into(),
            "".into(),
            "ipv4.dns".into(),
            "".into(),
        ]);
    }
    Ok(x)
}
fn run_ipv4_sequence(m: &[String]) -> Result<(String, Vec<String>), String> {
    let u = m
        .get(3)
        .ok_or_else(|| "wifi-uuid-required".to_string())?
        .clone();
    let (mut s, _) = run_nmcli(m, None)?;
    for x in [
        vec!["connection".into(), "down".into(), "uuid".into(), u.clone()],
        vec!["connection".into(), "up".into(), "uuid".into(), u],
    ] {
        let (o, _) = run_nmcli(&x, None)?;
        s.push_str(&o)
    }
    Ok((s, Vec::new()))
}
fn refuse(s: impl Into<String>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    Err((
        StatusCode::FORBIDDEN,
        Json(
            json!({"schema":"caduceus.api.error.v1","ok":false,"command":"network device wifi","first_missing_signal":s.into()}),
        ),
    ))
}
