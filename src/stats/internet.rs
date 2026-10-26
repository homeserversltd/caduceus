//! House-first internet observation. Only the independent internet worker does IO.
use super::{
    dns_query, named_signal, now_ts, probe_internet, InternetObservation, INTERNET_CADENCE,
};
use crate::shared::{config, seat_identity};
use serde_json::Value;
use std::{
    fs,
    io::{self, Read},
    net::Ipv4Addr,
    os::fd::AsRawFd,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

const PEER_TIMEOUT: Duration = Duration::from_millis(500);
const PEER_MAX: usize = 64 * 1024;
const RECENT: Duration = Duration::from_secs(30);
const RESOLVER_TIMEOUT: Duration = Duration::from_secs(1);

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
    next_resolver_question: Option<Instant>,
    resolver_observation: Option<InternetObservation>,
    using_resolver: bool,
}

impl Sampler {
    pub(super) fn new() -> Self {
        Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .ok(),
            next_resolver_question: None,
            resolver_observation: None,
            using_resolver: false,
        }
    }

    pub(super) fn observe(&mut self) -> InternetObservation {
        let gateway = default_gateway();
        let perspective = perspective();
        if gateway_is_local(&perspective, gateway) {
            self.using_resolver = true;
            return self.resolver();
        }
        // Do not carry resolver evidence across a change of this body's role.
        self.next_resolver_question = None;
        self.resolver_observation = None;
        self.using_resolver = false;
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
        if self.using_resolver {
            if let Some(next) = self.next_resolver_question {
                return next
                    .saturating_duration_since(Instant::now())
                    .min(INTERNET_CADENCE)
                    .max(Duration::from_millis(10));
            }
        }
        INTERNET_CADENCE
    }

    fn resolver(&mut self) -> InternetObservation {
        let now = Instant::now();
        if self.next_resolver_question.is_some_and(|next| now < next) {
            if let Some(answer) = &self.resolver_observation {
                return project(answer);
            }
        }
        // Attempt time, not success, throttles both failures and successes.
        // Pokes cannot turn a failed question into seven-second outreach.
        let control_error = resolver_counters_available().err();
        // RTT/infra TTL and recursive reply totals include failure; neither is
        // a successful upstream witness. Until such a passive reader exists,
        // take the contract's local-question fallback, never call those green.
        let question = fresh_resolver_question();
        self.next_resolver_question = Some(Instant::now() + RECENT);
        let success = question.as_ref().is_ok_and(|name| {
            dns_query(Ipv4Addr::LOCALHOST, name, Instant::now() + RESOLVER_TIMEOUT).is_ok_and(
                |answer| answer.rcode == 0 && answer.ipv4_answer == Some(Ipv4Addr::new(1, 1, 1, 1)),
            )
        });
        let answer = if success {
            let mut answer = resolver_answer();
            answer.first_missing_signal = control_error.and_then(named_signal);
            answer
        } else if let Some(error) = control_error {
            // Preserve the original fallback for absent/unreadable control.
            let mut answer = probe_internet();
            answer.first_missing_signal = named_signal(error);
            answer
        } else {
            // A known resolver's failed upstream question is negative evidence,
            // not permission for an unrelated public TCP port to overwrite it.
            InternetObservation {
                ts: now_ts(),
                status: Some("disconnected".to_owned()),
                source: Some("resolver"),
                first_missing_signal: named_signal(
                    question
                        .err()
                        .unwrap_or("caduceus-stats-internet-resolver-upstream-query-failed"),
                ),
            }
        };
        self.resolver_observation = Some(answer.clone());
        answer
    }
}

// A one-second reader expires the witness even while the worker is blocked.
// Only resolver evidence is changed; gateway and public-probe projections stay.
pub(super) fn project(observation: &InternetObservation) -> InternetObservation {
    let mut answer = observation.clone();
    if answer.source == Some("resolver") && answer.status.as_deref() == Some("connected") {
        let age = now_ts().saturating_sub(answer.ts);
        if !(0..RECENT.as_secs() as i64).contains(&age) {
            answer.status = Some("disconnected".to_owned());
            answer.first_missing_signal =
                named_signal("caduceus-stats-internet-resolver-upstream-evidence-expired");
        }
    }
    answer
}

fn fresh_resolver_question() -> Result<String, &'static str> {
    let mut nonce = [0u8; 16];
    fs::File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|_| "caduceus-stats-internet-resolver-nonce-unavailable")?;
    let label: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    // sslip.io generates a positive A RR for the IP embedded in each fresh
    // owner name. A negative/NODATA answer (including aggressive NSEC cache
    // synthesis) is never accepted. Only localhost receives our DNS question.
    Ok(format!("n{label}.1-1-1-1.sslip.io"))
}

fn resolver_answer() -> InternetObservation {
    InternetObservation {
        ts: now_ts(),
        status: Some("connected".to_owned()),
        source: Some("resolver"),
        first_missing_signal: None,
    }
}

fn gateway_answer(value: &Value) -> Result<InternetObservation, ()> {
    let internet = value.get("internet").ok_or(())?;
    let status = internet
        .get("status")
        .and_then(Value::as_str)
        .filter(|status| matches!(*status, "connected" | "disconnected"))
        .ok_or(())?;
    let ts = internet.get("ts").and_then(Value::as_i64).ok_or(())?;
    let age = now_ts().checked_sub(ts).ok_or(())?;
    // Do not re-freshen a relayed or stale answer into an endless connected loop.
    // Older gateway builds without source remain valid direct house answers.
    if !(-7..=RECENT.as_secs() as i64).contains(&age)
        || internet.get("source").and_then(Value::as_str) == Some("gateway")
    {
        return Err(());
    }
    let signal = match internet.get("firstMissingSignal") {
        None | Some(Value::Null) => None,
        Some(Value::String(signal)) => {
            (!signal.trim().is_empty() && signal != "none").then(|| signal.clone())
        }
        _ => return Err(()),
    };
    Ok(InternetObservation {
        ts,
        status: Some(status.to_owned()),
        source: Some("gateway"),
        first_missing_signal: signal.or_else(|| {
            (status == "disconnected")
                .then(|| "caduceus-stats-internet-gateway-disconnected".to_owned())
        }),
    })
}

fn resolver_counters_available() -> Result<(), &'static str> {
    let text =
        resolver_stats().map_err(|_| "caduceus-stats-internet-resolver-counters-unavailable")?;
    let field = |name: &str| {
        text.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == name).then_some(value)
        })
    };
    field("time.up")
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
        .ok_or("caduceus-stats-internet-resolver-counters-malformed")?;
    Ok(())
}

fn resolver_stats() -> io::Result<String> {
    // No elevation or new grant: this succeeds only with the daemon's existing
    // rights. stats_noreset neither clears counters nor sends an upstream query.
    let mut child = Command::new("/usr/sbin/unbound-control")
        .arg("stats_noreset")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| io::Error::other("stdout absent"))?;
        let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) }
                < 0
        {
            return Err(io::Error::last_os_error());
        }
        let deadline = Instant::now() + PEER_TIMEOUT;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    if let Some(status) = child.try_wait()? {
                        return if status.success() {
                            String::from_utf8(bytes).map_err(|_| io::Error::other("invalid stats"))
                        } else {
                            Err(io::Error::other("control refused"))
                        };
                    }
                }
                Ok(count) => {
                    if bytes.len() + count > PEER_MAX {
                        return Err(io::Error::other("stats too large"));
                    }
                    bytes.extend_from_slice(&buffer[..count]);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "control timeout"));
            }
            thread::sleep(Duration::from_millis(2));
        }
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let _ = child.wait();
    result
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
