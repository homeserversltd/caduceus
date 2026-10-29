use super::{unavailable, Failure, MAX_BODY, SCHEMA};
use axum::http::StatusCode;
use serde_json::{json, Value};
use std::{fs, io::Read, net::Ipv4Addr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

fn read(relative: &str) -> Result<String, Failure> {
    let mut bytes = Vec::new();
    fs::File::open(crate::shared::config::path(relative))
        .and_then(|file| file.take(MAX_BODY as u64 + 1).read_to_end(&mut bytes))
        .map_err(|_| unavailable("link-up-name-observation-failed"))?;
    if bytes.len() > MAX_BODY {
        return Err(unavailable("link-up-name-observation-failed"));
    }
    String::from_utf8(bytes).map_err(|_| unavailable("link-up-name-observation-failed"))
}

fn gateway() -> Option<(Ipv4Addr, u16)> {
    // Match the existing Ruyi/internet reader: the current default route owns
    // the address; a remembered seat may supply a port only for that address.
    let ip = read("proc/net/route")
        .ok()?
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.get(1) != Some(&"00000000") || fields.get(7) != Some(&"00000000") {
                return None;
            }
            let flags = u32::from_str_radix(fields.get(3)?, 16).ok()?;
            let gateway = u32::from_str_radix(fields.get(2)?, 16).ok()?;
            let metric = fields.get(6)?.parse::<u32>().ok()?;
            (flags & 3 == 3 && gateway != 0)
                .then_some((metric, Ipv4Addr::from(gateway.to_le_bytes())))
        })
        .min_by_key(|(metric, _)| *metric)?
        .1;
    let perspective: Value = read("etc/appliance/ruyi.json")
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .filter(|value: &Value| value["schema"] == "harmonia.ruyi-perspective.v1")
        .unwrap_or(Value::Null);
    let seat = &perspective["gateway_seat"];
    let matched = seat["ipv4"]
        .as_str()
        .and_then(|value| value.parse::<Ipv4Addr>().ok())
        == Some(ip);
    let port = matched
        .then(|| seat["caduceus_port"].as_u64())
        .flatten()
        .or_else(|| {
            read("etc/appliance/config.json")
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .and_then(|value| value.pointer("/caduceus/seat_port").and_then(Value::as_u64))
        })
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .unwrap_or(8787);
    Some((ip, port))
}

pub(super) async fn gateway_post(body: &Value) -> Option<Value> {
    let (ip, port) = gateway()?;
    let data = serde_json::to_vec(body).ok()?;
    timeout(Duration::from_secs(3), async {
        let mut stream = TcpStream::connect((ip, port)).await.ok()?;
        let request = format!("POST /api/v1/notifications/forward HTTP/1.0\r\nHost: {ip}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", data.len());
        stream.write_all(request.as_bytes()).await.ok()?;
        stream.write_all(&data).await.ok()?;
        let mut bytes = Vec::new();
        stream.take(MAX_BODY as u64 + 1).read_to_end(&mut bytes).await.ok()?;
        if bytes.len() > MAX_BODY { return None; }
        let split = bytes.windows(4).position(|v| v == b"\r\n\r\n")?;
        let head = std::str::from_utf8(&bytes[..split]).ok()?;
        if head.lines().next()?.split_whitespace().nth(1) != Some("200") { return None; }
        serde_json::from_slice(&bytes[split + 4..]).ok()
    }).await.ok().flatten()
}

pub(super) async fn gateway_notifications() -> Option<Value> {
    let (ip, port) = gateway()?;
    timeout(Duration::from_secs(3), async {
        let mut stream = TcpStream::connect((ip, port)).await.ok()?;
        // HTTP/1.0 with close has no chunked response framing.
        let request = format!("GET /api/v1/notifications HTTP/1.0\r\nHost: {ip}\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut bytes = Vec::new();
        stream.take(MAX_BODY as u64 + 1).read_to_end(&mut bytes).await.ok()?;
        if bytes.len() > MAX_BODY { return None; }
        let split = bytes.windows(4).position(|v| v == b"\r\n\r\n")?;
        let head = std::str::from_utf8(&bytes[..split]).ok()?;
        if head.lines().next()?.split_whitespace().nth(1) != Some("200") { return None; }
        let value: Value = serde_json::from_slice(&bytes[split + 4..]).ok()?;
        if value["schema"] != SCHEMA || !value["notifications"].is_array() { return None; }
        Some(value)
    }).await.ok().flatten()
}

#[derive(serde::Deserialize)]
pub(super) struct ChildPortal {
    #[serde(rename = "localURL", default)]
    pub local_url: Value,
    #[serde(default)]
    pub port: Value,
}

#[derive(serde::Deserialize)]
struct ChildPortals {
    schema: String,
    entries: Vec<ChildPortal>,
}

// The response crosses a bounded streaming channel. Unrelated entry fields
// are skipped by the semantic reader rather than kept in a response buffer.
pub(super) async fn child_portals(ip: Ipv4Addr, port: u16) -> Result<Vec<ChildPortal>, Failure> {
    timeout(Duration::from_secs(3), async move {
        let mut stream = TcpStream::connect((ip, port)).await
            .map_err(|_| unavailable("link-up-child-portals-unavailable"))?;
        let request = format!("GET /api/v1/portals HTTP/1.0\r\nHost: {ip}\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await
            .map_err(|_| unavailable("link-up-child-portals-unavailable"))?;
        let mut head = Vec::new();
        loop {
            if head.len() >= 8192 { return Err(unavailable("link-up-child-portals-unavailable")); }
            let byte = stream.read_u8().await.map_err(|_| unavailable("link-up-child-portals-unavailable"))?;
            head.push(byte);
            if head.ends_with(b"\r\n\r\n") { break; }
        }
        let headers = std::str::from_utf8(&head).map_err(|_| unavailable("link-up-child-portals-unavailable"))?;
        if headers.lines().next().and_then(|line| line.split_whitespace().nth(1)) != Some("200") {
            return Err(unavailable("link-up-child-portals-unavailable"));
        }
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let parser = tokio::task::spawn_blocking(move || serde_json::from_reader::<_, ChildPortals>(super::RosterStream {
            receiver, current: axum::body::Bytes::new(),
        }));
        let mut total = 0usize;
        let mut bytes = [0u8; 8192];
        loop {
            let count = stream.read(&mut bytes).await.map_err(|_| unavailable("link-up-child-portals-unavailable"))?;
            if count == 0 { break; }
            total += count;
            if total > MAX_BODY { return Err(unavailable("link-up-child-portals-unavailable")); }
            sender.send(axum::body::Bytes::copy_from_slice(&bytes[..count])).await
                .map_err(|_| unavailable("link-up-child-portals-unavailable"))?;
        }
        drop(sender);
        let value = parser.await.map_err(|_| unavailable("link-up-child-portals-unavailable"))?
            .map_err(|_| unavailable("link-up-child-portals-unavailable"))?;
        if value.schema != "caduceus.portals.v2" { return Err(unavailable("link-up-child-portals-desync")); }
        Ok(value.entries)
    }).await.map_err(|_| unavailable("link-up-child-portals-unavailable"))?
}

pub(super) async fn portals() -> Result<Value, Failure> {
    match crate::shared::policy::allows_command("cert status") {
        Ok(true) => {}
        _ => return Err(unavailable("link-up-portal-status-unavailable")),
    }
    crate::gate::blocking_task("cert status", || {
        let value = crate::routes::issue_certificate::status_json()
            .map_err(|_| unavailable("link-up-portal-status-unavailable"))?;
        if value["ok"] != true || !value["portals"].is_array() {
            return Err(unavailable("link-up-portal-status-unavailable"));
        }
        Ok(value)
    })
    .await
    .map_err(|_| unavailable("link-up-portal-status-unavailable"))?
}

pub(super) fn valid_name(name: &str) -> bool {
    let Some(label) = name.strip_suffix(".home.arpa") else {
        return false;
    };
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

struct DnsRecord {
    name: String,
    address: String,
    alias_of: Option<String>,
}

fn dns_records() -> Result<Vec<DnsRecord>, Failure> {
    let root = crate::shared::config::path("etc/unbound");
    let mut paths = vec![root.join("unbound.conf")];
    let mut includes = fs::read_dir(root.join("unbound.conf.d"))
        .map_err(|_| unavailable("link-up-name-observation-failed"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| unavailable("link-up-name-observation-failed"))?;
    includes.sort_by_key(|entry| entry.file_name());
    paths.extend(
        includes
            .into_iter()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "conf")),
    );
    let mut records = Vec::new();
    for path in paths {
        let relative = path
            .strip_prefix(crate::shared::config::root())
            .map_err(|_| unavailable("link-up-name-observation-failed"))?;
        let text = read(
            relative
                .to_str()
                .ok_or_else(|| unavailable("link-up-name-observation-failed"))?,
        )?;
        for line in text.lines() {
            let Some((directive, tail)) = line.trim().split_once(':') else {
                continue;
            };
            if !directive.eq_ignore_ascii_case("local-data") {
                continue;
            }
            let tail = tail.trim();
            let record = if let Some(quoted) = tail.strip_prefix('"') {
                quoted
                    .split_once('"')
                    .map(|v| v.0)
                    .ok_or_else(|| unavailable("link-up-name-observation-failed"))?
            } else {
                tail.split('#').next().unwrap_or("").trim()
            };
            let parts: Vec<_> = record.split_whitespace().collect();
            if parts.len() < 3 {
                return Err(unavailable("link-up-name-observation-failed"));
            }
            let name = parts[0].trim_end_matches('.').to_ascii_lowercase();
            let address = parts.last().unwrap().to_string();
            let alias_of = line
                .split_once("# agathodaimon-alias ")
                .and_then(|(_, rest)| rest.split_whitespace().next())
                .map(|v| v.trim_end_matches('.').to_ascii_lowercase());
            records.push(DnsRecord {
                name,
                address,
                alias_of,
            });
        }
    }
    Ok(records)
}

pub(super) fn validate_names(
    names: &[String],
    candidate: &Value,
    roster: &Value,
    portals: &Value,
) -> Result<(), Failure> {
    let taken = (StatusCode::CONFLICT, "link-up-name-taken");
    let rows = roster["staves"]
        .as_array()
        .ok_or_else(|| unavailable("link-up-roster-unavailable"))?;
    let portal_rows = portals["portals"]
        .as_array()
        .ok_or_else(|| unavailable("link-up-portal-status-unavailable"))?;
    let existing = portal_rows.iter().find(|p| p["fqdn"] == names[0]);
    let same_portal = existing.is_some_and(|p| {
        p["upstream"] == candidate["upstream"] && p["lan_ip"] == candidate["from"]["ipv4"]
    });
    let gateway_ip = roster["seat"]["ipv4"]
        .as_str()
        .ok_or_else(|| unavailable("link-up-name-observation-failed"))?;
    let gateway_host = roster["seat"]["hostname"]
        .as_str()
        .ok_or_else(|| unavailable("link-up-name-observation-failed"))?;
    let gateway_canonical = if gateway_host == "home" {
        "home.arpa".to_owned()
    } else {
        format!("{gateway_host}.home.arpa")
    };
    let dns = dns_records()?;
    for name in names {
        if rows.iter().any(|row| {
            row["hostname"]
                .as_str()
                .is_some_and(|host| name == &format!("{}.home.arpa", host.to_ascii_lowercase()))
                || row["canonical_name"]
                    .as_str()
                    .is_some_and(|canonical| name.eq_ignore_ascii_case(canonical))
        }) {
            return Err(taken);
        }
        if portal_rows.iter().any(|portal| {
            let holds = portal["fqdn"] == *name
                || portal["aliases"]
                    .as_array()
                    .is_some_and(|aliases| aliases.iter().any(|v| v == name));
            holds && !(portal["fqdn"] == names[0] && same_portal)
        }) {
            return Err(taken);
        }
        for record in dns.iter().filter(|record| record.name == *name) {
            let known_name = name == &names[0]
                || existing.is_some_and(|p| {
                    p["aliases"]
                        .as_array()
                        .is_some_and(|aliases| aliases.iter().any(|v| v == name))
                });
            let gateway_alias = record.alias_of.as_deref().is_some_and(|target| {
                target == gateway_canonical
                    || dns.iter().any(|owner| {
                        owner.name == target
                            && owner.address == gateway_ip
                            && owner.alias_of.is_none()
                    })
            });
            if !(same_portal && known_name && record.address == gateway_ip && gateway_alias) {
                return Err(taken);
            }
        }
    }
    Ok(())
}

pub(super) async fn admit(args: Vec<String>) -> Result<Value, Failure> {
    if crate::shared::policy::allows_command("cert portal-admit").ok() != Some(true) {
        return Err((StatusCode::FORBIDDEN, "link-up-accept-on-homeserver"));
    }
    crate::gate::blocking_task("cert portal-admit", move || {
        crate::shared::agathodaimon::crossing_value_preserving_receipt(
            "cert",
            "house-ca",
            &json!({"args": args}),
            false,
        )
        // Structured staff refusals cross intact, including unknown fields.
        .unwrap_or_else(|value| value)
    })
    .await
    .map_err(|_| unavailable("link-up-portal-admit-unavailable"))
}
