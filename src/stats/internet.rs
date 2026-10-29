//! House-first internet observation. Only the independent internet worker does IO.
use super::{named_signal, now_ts, probe_internet, InternetObservation, INTERNET_CADENCE};
use crate::shared::{config, seat_identity};
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
    net::Ipv4Addr,
    time::{Duration, Instant},
};
#[path = "internet/flows.rs"]
mod flows;
#[path = "internet/gateway.rs"]
mod gateway;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const PEER_TIMEOUT: Duration = Duration::from_millis(500);
const PEER_MAX: usize = 64 * 1024;
const RECENT: Duration = Duration::from_secs(30);

fn read_text(relative: &str) -> Option<String> {
    let file = fs::File::open(config::path(relative)).ok()?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= 1024 * 1024)
        .then(|| String::from_utf8(bytes).ok())
        .flatten()
}

fn default_gateway() -> Option<Ipv4Addr> {
    read_text("proc/net/route")?
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
        .min_by_key(|(metric, _)| *metric)
        .map(|(_, gateway)| gateway)
}

fn perspective() -> Value {
    read_text("etc/appliance/ruyi.json")
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .filter(|value| value["schema"] == "harmonia.ruyi-perspective.v1")
        .unwrap_or(Value::Null)
}

fn declared_port(perspective: &Value, gateway: Ipv4Addr) -> u16 {
    // A remembered seat's port is used only for this current route's address.
    let seat = perspective.get("gateway_seat");
    let matched = seat
        .and_then(|seat| seat.get("ipv4"))
        .and_then(Value::as_str)
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok())
        == Some(gateway);
    let port = matched
        .then(|| seat.and_then(|seat| seat.get("caduceus_port")))
        .flatten()
        .and_then(Value::as_u64)
        .or_else(|| {
            read_text("etc/appliance/config.json")
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
                .and_then(|value| value.pointer("/caduceus/seat_port").and_then(Value::as_u64))
        });
    port.and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .unwrap_or(8787)
}

fn gateway_is_local(perspective: &Value, gateway: Option<Ipv4Addr>) -> bool {
    let interfaces = seat_identity::local_ipv4_interfaces();
    if gateway.is_some_and(|gateway| interfaces.iter().any(|local| local.address == gateway)) {
        return true;
    }
    // The house gateway itself normally has an upstream default route. Its
    // existing Ruyi seat is compared to the current interfaces, not a hostname
    // guess or a call to our own HTTP door. A stale foreign seat cannot elect us.
    let seat_ip = perspective
        .pointer("/gateway_seat/ipv4")
        .and_then(Value::as_str)
        .and_then(|ip| ip.parse::<Ipv4Addr>().ok());
    let seat_mac = perspective
        .pointer("/gateway_seat/mac")
        .and_then(Value::as_str);
    interfaces.iter().any(|local| {
        Some(local.address) == seat_ip
            && local
                .mac
                .as_deref()
                .zip(seat_mac)
                .is_some_and(|(local, seat)| local.eq_ignore_ascii_case(seat))
    })
}

pub(super) struct Sampler {
    runtime: Option<tokio::runtime::Runtime>,
    gateway: Option<gateway::Gateway>,
    next_role_check: Instant,
    echo_not_before: Option<Instant>,
}

impl Sampler {
    pub(super) fn new() -> Self {
        Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok(),
            gateway: None,
            next_role_check: Instant::now(),
            echo_not_before: None,
        }
    }

    pub(super) fn observe(&mut self) -> InternetObservation {
        if Instant::now() < self.next_role_check {
            if let Some(road) = self.gateway.as_mut() {
                return road.observe(&mut self.echo_not_before);
            }
        }
        self.next_role_check = Instant::now() + INTERNET_CADENCE;
        let gateway = default_gateway();
        let perspective = perspective();
        if gateway_is_local(&perspective, gateway) {
            return self
                .gateway
                .get_or_insert_with(gateway::Gateway::new)
                .observe(&mut self.echo_not_before);
        }
        // Role changes retire evidence/listeners, never the body's echo budget.
        self.gateway = None;
        let signal = match (gateway, self.runtime.as_ref()) {
            (None, _) => "caduceus-stats-internet-gateway-no-default-route".to_owned(),
            (_, None) => "caduceus-stats-internet-gateway-runtime-unavailable".to_owned(),
            (Some(gateway), Some(runtime)) => {
                let port = declared_port(&perspective, gateway);
                let (sample, signal) =
                    runtime.block_on(fetch_peer_stats(&gateway.to_string(), port));
                match sample.and_then(|value| gateway_answer(&value).ok()) {
                    Some(answer) => return answer,
                    None => format!(
                        "caduceus-stats-internet-gateway-{}",
                        signal.unwrap_or_else(|| "internet-unavailable".to_owned())
                    ),
                }
            }
        };
        let mut answer = probe_internet();
        answer.first_missing_signal = Some(signal);
        answer
    }

    pub(super) fn cadence(&self) -> Duration {
        self.gateway
            .as_ref()
            .map_or(INTERNET_CADENCE, |road| road.cadence(self.echo_not_before))
    }
}

// A one-second projection does no IO and cannot renew old evidence while the
// worker is blocked. Gateway/stave and public-probe projections stay unchanged.
pub(super) fn project(observation: &InternetObservation) -> InternetObservation {
    let mut answer = observation.clone();
    if matches!(answer.source, Some("flows" | "isp-hop"))
        && answer.status.as_deref() == Some("connected")
    {
        let age = now_ts().saturating_sub(answer.ts);
        if !(0..RECENT.as_secs() as i64).contains(&age) {
            answer.status = Some("disconnected".to_owned());
            answer.first_missing_signal = answer.first_missing_signal.or_else(|| {
                named_signal(if answer.source == Some("flows") {
                    "caduceus-stats-internet-flows-evidence-expired"
                } else {
                    "caduceus-stats-internet-isp-hop-evidence-expired"
                })
            });
        }
    }
    answer
}

fn gateway_answer(value: &Value) -> Result<InternetObservation, ()> {
    let internet = value.get("internet").ok_or(())?;
    let status = internet
        .get("status")
        .and_then(Value::as_str)
        .filter(|status| matches!(*status, "connected" | "disconnected"))
        .ok_or(())?;
    let ts = internet.get("ts").and_then(Value::as_i64).ok_or(())?;
    let age = now_ts().saturating_sub(ts);
    // A relayed answer must not become a loop; an old direct answer is still
    // an answering house, but never renews connected evidence.
    if internet.get("source").and_then(Value::as_str) == Some("gateway") {
        return Err(());
    }
    let signal = match internet.get("firstMissingSignal") {
        None | Some(Value::Null) => None,
        Some(Value::String(signal)) => {
            (!signal.trim().is_empty() && signal != "none").then(|| signal.clone())
        }
        _ => return Err(()),
    };
    let stale = !(-7..=RECENT.as_secs() as i64).contains(&age);
    Ok(InternetObservation {
        ts,
        status: Some(if stale { "disconnected" } else { status }.to_owned()),
        source: Some("gateway"),
        first_missing_signal: if stale {
            Some("caduceus-stats-internet-gateway-stale".to_owned())
        } else {
            signal.or_else(|| {
                (status == "disconnected")
                    .then(|| "caduceus-stats-internet-gateway-disconnected".to_owned())
            })
        },
    })
}

/// Shared with the Ruyi roster: one native HTTP read, 500 ms including connect,
/// write, read and EOF, and at most 64 KiB. No staff crossing or roster sweep.
pub(crate) async fn fetch_peer_stats(host: &str, port: u16) -> (Option<Value>, Option<String>) {
    let read = async {
        let mut stream = TcpStream::connect((host, port)).await?;
        stream.set_nodelay(true)?;
        stream.write_all(format!("GET /api/v1/appliance/stats HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            if bytes.len() + count > PEER_MAX {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "peer too large"));
            }
            bytes.extend_from_slice(&buffer[..count]);
        }
        Ok::<_, io::Error>(bytes)
    };
    let bytes = match timeout(PEER_TIMEOUT, read).await {
        Err(_) => return (None, Some("timeout".to_owned())),
        Ok(Err(error)) if error.kind() == io::ErrorKind::InvalidData => {
            return (None, Some("too-large".to_owned()))
        }
        Ok(Err(_)) => return (None, Some("unreachable".to_owned())),
        Ok(Ok(bytes)) => bytes,
    };
    let parse = || {
        let split = bytes
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .ok_or("malformed".to_owned())?;
        let headers = std::str::from_utf8(&bytes[..split]).map_err(|_| "malformed".to_owned())?;
        let status = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|status| status.parse::<u16>().ok())
            .ok_or("malformed".to_owned())?;
        if status != 200 {
            return Err(if (100..=599).contains(&status) {
                format!("refused-{status}")
            } else {
                "malformed".to_owned()
            });
        }
        let value: Value =
            serde_json::from_slice(&bytes[split + 4..]).map_err(|_| "malformed".to_owned())?;
        if !crate::routes::leaf_schema::accepts("caduceus.appliance.stats.sample.v1", &value) {
            return Err("malformed".to_owned());
        }
        Ok(value)
    };
    match parse() {
        Ok(value) => (Some(value), None),
        Err(signal) => (None, Some(signal)),
    }
}
