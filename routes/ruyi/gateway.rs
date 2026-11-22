use serde_json::Value;
use std::{fs, io::Read, net::Ipv4Addr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Duration},
};

pub(crate) const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_BYTES: usize = 1024 * 1024;

fn read(relative: &str) -> Option<String> {
    let mut bytes = Vec::new();
    fs::File::open(crate::shared::config::path(relative))
        .and_then(|file| file.take(MAX_BYTES as u64 + 1).read_to_end(&mut bytes))
        .ok()?;
    if bytes.len() > MAX_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub(crate) fn resolve() -> Option<(Ipv4Addr, u16)> {
    // The current default route owns the address; a remembered seat may
    // supply a port only for that address.
    let ip = read("proc/net/route")?
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
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .and_then(|value| value.pointer("/caduceus/seat_port").and_then(Value::as_u64))
        })
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .unwrap_or(8787);
    Some((ip, port))
}

pub(crate) async fn get_json(
    (ip, port): (Ipv4Addr, u16),
    path: &'static str,
    budget: Duration,
) -> Option<Value> {
    if budget.is_zero() {
        return None;
    }
    timeout(budget.min(TIMEOUT), async {
        let mut stream = TcpStream::connect((ip, port)).await.ok()?;
        // HTTP/1.0 with close has no chunked response framing.
        let request = format!("GET {path} HTTP/1.0\r\nHost: {ip}\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await.ok()?;
        let mut bytes = Vec::new();
        stream
            .take(MAX_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .await
            .ok()?;
        if bytes.len() > MAX_BYTES {
            return None;
        }
        let split = bytes.windows(4).position(|v| v == b"\r\n\r\n")?;
        let head = std::str::from_utf8(&bytes[..split]).ok()?;
        if head.lines().next()?.split_whitespace().nth(1) != Some("200") {
            return None;
        }
        serde_json::from_slice(&bytes[split + 4..]).ok()
    })
    .await
    .ok()
    .flatten()
}
