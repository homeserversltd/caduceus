//! Passive WAN evidence, with one route-next-hop echo only after a silent window.
use super::{
    flows, named_signal, now_ts, read_text, seat_identity, InternetObservation, INTERNET_CADENCE,
    RECENT,
};
use std::{
    ffi::CString,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    network: IpAddr,
    prefix: u32,
    metric: u32,
    interface: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Wan {
    pub(super) interface: String,
    pub(super) next_hop: Ipv4Addr,
    routes: Vec<Route>,
    local_addresses: Vec<IpAddr>,
    ipv6_addresses_known: bool,
}

impl Wan {
    pub(super) fn read() -> Option<Self> {
        let text = read_text("proc/net/route")?;
        let mut routes = Vec::new();
        let mut defaults = Vec::new();
        for line in text.lines().skip(1) {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() < 8 {
                continue;
            }
            let flags = u32::from_str_radix(f[3], 16).ok()?;
            if flags & 1 == 0 || flags & 0x200 != 0 {
                continue;
            }
            let network = Ipv4Addr::from(u32::from_str_radix(f[1], 16).ok()?.to_le_bytes());
            let mask = Ipv4Addr::from(u32::from_str_radix(f[7], 16).ok()?.to_le_bytes());
            let prefix = u32::from(mask).leading_ones();
            if u32::from(mask).count_ones() != prefix {
                return None;
            }
            let metric = f[6].parse().ok()?;
            let interface = f[0].to_owned();
            if network.is_unspecified() && prefix == 0 && flags & 2 != 0 {
                let hop = Ipv4Addr::from(u32::from_str_radix(f[2], 16).ok()?.to_le_bytes());
                if !hop.is_unspecified() {
                    defaults.push((metric, interface.clone(), hop));
                }
            }
            routes.push(Route {
                network: network.into(),
                prefix,
                metric,
                interface,
            });
        }
        if let Some(text) = read_text("proc/net/ipv6_route") {
            for line in text.lines() {
                let f: Vec<_> = line.split_whitespace().collect();
                if f.len() < 10 {
                    continue;
                }
                let Ok(network) = u128::from_str_radix(f[0], 16) else {
                    continue;
                };
                let Ok(prefix) = u32::from_str_radix(f[1], 16) else {
                    continue;
                };
                let Ok(metric) = u32::from_str_radix(f[5], 16) else {
                    continue;
                };
                let Ok(flags) = u32::from_str_radix(f[8], 16) else {
                    continue;
                };
                if prefix <= 128 && flags & 1 != 0 && flags & 0x200 == 0 {
                    routes.push(Route {
                        network: Ipv6Addr::from(network).into(),
                        prefix,
                        metric,
                        interface: f[9].to_owned(),
                    });
                }
            }
        }
        let mut local_addresses: Vec<IpAddr> = seat_identity::local_ipv4_interfaces()
            .into_iter()
            .map(|local| local.address.into())
            .collect();
        // A public address owned by this gateway is not an internet peer.
        // Without its IPv6 local-address read, decline IPv6 evidence rather
        // than crediting replies sent by the gateway itself on an inbound flow.
        let ipv6 = read_text("proc/net/if_inet6").and_then(|text| {
            text.lines()
                .map(|line| {
                    line.split_whitespace()
                        .next()
                        .and_then(|value| u128::from_str_radix(value, 16).ok())
                        .map(|value| IpAddr::V6(Ipv6Addr::from(value)))
                })
                .collect::<Option<Vec<_>>>()
        });
        let ipv6_addresses_known = ipv6.is_some();
        if let Some(ipv6) = ipv6 {
            local_addresses.extend(ipv6);
        }
        local_addresses.sort();
        local_addresses.dedup();
        defaults.sort();
        let (_, interface, next_hop) = defaults.into_iter().next()?;
        Some(Self {
            interface,
            next_hop,
            routes,
            local_addresses,
            ipv6_addresses_known,
        })
    }

    pub(super) fn carries(&self, destination: IpAddr) -> bool {
        if self.local_addresses.is_empty()
            || self.local_addresses.contains(&destination)
            || (destination.is_ipv6() && !self.ipv6_addresses_known)
            || destination == IpAddr::V4(self.next_hop)
            || !public(destination)
        {
            return false;
        }
        self.routes
            .iter()
            .filter(|r| match (r.network, destination) {
                (IpAddr::V4(network), IpAddr::V4(ip)) => {
                    let mask = u32::MAX.checked_shl(32 - r.prefix).unwrap_or(0);
                    u32::from(network) & mask == u32::from(ip) & mask
                }
                (IpAddr::V6(network), IpAddr::V6(ip)) => {
                    let mask = u128::MAX.checked_shl(128 - r.prefix).unwrap_or(0);
                    u128::from(network) & mask == u128::from(ip) & mask
                }
                _ => false,
            })
            .min_by_key(|r| (std::cmp::Reverse(r.prefix), r.metric))
            .is_some_and(|r| r.interface == self.interface)
    }
}

fn public(address: IpAddr) -> bool {
    match address {
        // CGNAT is an ISP/private realm, not public internet evidence. It is
        // deliberately still a legal next hop for the separate link witness.
        IpAddr::V4(ip) => super::super::is_public_ipv4(ip),
        IpAddr::V6(ip) => {
            let n = u128::from(ip);
            n >> 125 == 1 && n >> 96 != 0x2001_0db8 && n >> 100 != 0x2001_001 && n >> 108 != 0x3fff0
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Evidence {
    pub(super) at: Instant,
    pub(super) ts: i64,
}

impl Evidence {
    pub(super) fn now() -> Self {
        Self {
            at: Instant::now(),
            ts: now_ts(),
        }
    }
    pub(super) fn recent(self) -> bool {
        self.at.elapsed() < RECENT
            && (0..RECENT.as_secs() as i64).contains(&now_ts().saturating_sub(self.ts))
    }
}

pub(super) struct Gateway {
    wan: Option<Wan>,
    reader: Option<flows::Reader>,
    next_open: Instant,
    next_route: Instant,
    watching_since: Instant,
    flow: Option<Evidence>,
    hop: Option<(Evidence, bool, &'static str)>,
    missing_read: bool,
}

impl Gateway {
    pub(super) fn new() -> Self {
        let now = Instant::now();
        Self {
            wan: None,
            reader: None,
            next_open: now,
            next_route: now,
            watching_since: now,
            flow: None,
            hop: None,
            missing_read: false,
        }
    }

    pub(super) fn cadence(&self, echo_not_before: Option<Instant>) -> Duration {
        if self.reader.as_ref().is_some_and(flows::Reader::listening) {
            // The worker waits in a bounded kernel poll; this is not a hot
            // filesystem or staff-door loop. Nothing runs on the 1 s tick.
            return Duration::from_millis(1);
        }
        // Wake at the silence/budget edge rather than delaying a cold
        // window until the next ordinary seven-second table read.
        let silence_due = self
            .flow
            .map_or(self.watching_since + RECENT, |e| e.at + RECENT);
        let next = echo_not_before.map_or(silence_due, |budget| budget.max(silence_due));
        Some(next)
            .map(|next| next.saturating_duration_since(Instant::now()))
            .filter(|delay| !delay.is_zero())
            .unwrap_or(INTERNET_CADENCE)
            .min(INTERNET_CADENCE)
            .max(Duration::from_millis(10))
    }

    pub(super) fn observe(&mut self, echo_not_before: &mut Option<Instant>) -> InternetObservation {
        let now = Instant::now();
        if now >= self.next_route {
            let wan = Wan::read();
            // Any WAN/route change retires its old identities and evidence,
            // but never resets the body's echo budget.
            if wan != self.wan {
                self.wan = wan;
                self.reader = None;
                self.flow = None;
                self.hop = None;
                self.next_open = now;
                self.watching_since = now;
            }
            self.next_route = now + INTERNET_CADENCE;
        }
        let Some(wan) = self.wan.as_ref() else {
            return answer(
                "isp-hop",
                None,
                false,
                Some("caduceus-stats-internet-isp-hop-no-default-route"),
            );
        };
        if self.reader.is_none() && now >= self.next_open {
            self.reader = flows::Reader::open().ok();
            self.next_open = now + INTERNET_CADENCE;
            self.missing_read = self.reader.is_none();
        }
        if let Some(reader) = self.reader.as_mut() {
            match reader.observe(wan) {
                Ok(evidence) => {
                    self.missing_read = false;
                    if let Some(evidence) = evidence.filter(|e| e.recent()) {
                        self.flow = Some(evidence);
                    }
                }
                Err(()) => {
                    self.reader = None;
                    self.next_open = Instant::now() + INTERNET_CADENCE;
                    self.flow = None;
                    self.missing_read = true;
                }
            }
        }
        if let Some(evidence) = self.flow.filter(|e| e.recent()) {
            return answer("flows", Some(evidence), true, None);
        }
        let missing = self
            .missing_read
            .then_some("caduceus-stats-internet-flows-unreadable");
        // A cold readable table is not evidence of a silent house. First
        // observe an entire window. A missing read takes the explicit fallback.
        if missing.is_none() && self.flow.is_none() && self.watching_since.elapsed() < RECENT {
            return answer(
                "flows",
                None,
                false,
                Some("caduceus-stats-internet-flows-window-pending"),
            );
        }
        if echo_not_before.is_none_or(|next| Instant::now() >= next) {
            let evidence = Evidence::now();
            *echo_not_before = Some(evidence.at + RECENT);
            let result = echo(wan);
            self.hop = Some((
                evidence,
                result.is_ok(),
                result
                    .err()
                    .unwrap_or("caduceus-stats-internet-isp-hop-unavailable"),
            ));
        }
        match self.hop.filter(|(e, _, _)| e.recent()) {
            Some((evidence, true, _)) => answer("isp-hop", Some(evidence), true, missing),
            Some((evidence, false, signal)) => {
                answer("isp-hop", Some(evidence), false, missing.or(Some(signal)))
            }
            None => answer(
                "isp-hop",
                None,
                false,
                missing.or(Some("caduceus-stats-internet-isp-hop-evidence-expired")),
            ),
        }
    }
}

fn answer(
    source: &'static str,
    evidence: Option<Evidence>,
    connected: bool,
    signal: Option<&'static str>,
) -> InternetObservation {
    InternetObservation {
        ts: evidence.map_or_else(now_ts, |e| e.ts),
        status: Some(
            if connected {
                "connected"
            } else {
                "disconnected"
            }
            .to_owned(),
        ),
        source: Some(source),
        first_missing_signal: signal.and_then(named_signal),
    }
}

fn checksum(bytes: &[u8]) -> u16 {
    let sum: u32 = bytes
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    !((sum & 0xffff) + (sum >> 16)) as u16
}

fn echo(wan: &Wan) -> Result<(), &'static str> {
    const UNAVAILABLE: &str = "caduceus-stats-internet-isp-hop-unavailable";
    let device = CString::new(wan.interface.as_str()).map_err(|_| UNAVAILABLE)?;
    let index = unsafe { libc::if_nametoindex(device.as_ptr()) };
    if index == 0 {
        return Err(UNAVAILABLE);
    }
    let mut raw = false;
    let mut fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            libc::IPPROTO_ICMP,
        )
    };
    if fd < 0 {
        raw = true;
        fd = unsafe {
            libc::socket(
                libc::AF_INET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                libc::IPPROTO_ICMP,
            )
        };
    }
    if fd < 0 {
        return Err(UNAVAILABLE);
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    // IP_UNICAST_IF chooses the route's interface without a device-binding
    // privilege or a routing/configuration mutation. The value is network order.
    let index = index.to_be();
    if unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_UNICAST_IF,
            &index as *const _ as *const _,
            std::mem::size_of_val(&index) as _,
        )
    } != 0
    {
        return Err(UNAVAILABLE);
    }
    let mut nonce = [0u8; 16];
    if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), libc::GRND_NONBLOCK) }
        != nonce.len() as isize
    {
        return Err(UNAVAILABLE);
    }
    let mut message = [0u8; 24];
    message[0] = 8;
    message[4..6].copy_from_slice(&(std::process::id() as u16).to_be_bytes());
    message[6..8].copy_from_slice(&nonce[..2]);
    message[8..].copy_from_slice(&nonce);
    let sum: u32 = message
        .chunks_exact(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    let sum = (sum & 0xffff) + (sum >> 16);
    let check = !((sum & 0xffff) + (sum >> 16)) as u16;
    message[2..4].copy_from_slice(&check.to_be_bytes());
    let mut destination: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    destination.sin_family = libc::AF_INET as _;
    destination.sin_addr.s_addr = u32::from(wan.next_hop).to_be();
    let deadline = Instant::now() + Duration::from_secs(1);
    if unsafe {
        libc::sendto(
            socket.as_raw_fd(),
            message.as_ptr().cast(),
            message.len(),
            0,
            &destination as *const _ as *const _,
            std::mem::size_of_val(&destination) as _,
        )
    } != message.len() as isize
    {
        return Err("caduceus-stats-internet-isp-hop-send-failed");
    }
    // Exactly one datagram was sent. All remaining operations are bounded reads.
    let mut buffer = [0u8; 2048];
    while Instant::now() < deadline {
        if !flows::ready(socket.as_raw_fd(), deadline).map_err(|_| UNAVAILABLE)? {
            break;
        }
        let mut source: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&source) as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                &mut source as *mut _ as *mut _,
                &mut length,
            )
        };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(UNAVAILABLE);
        }
        if n as usize > buffer.len() || source.sin_addr.s_addr != destination.sin_addr.s_addr {
            continue;
        }
        let packet = &buffer[..n as usize];
        let offset = if raw {
            if packet.first().is_none_or(|p| p >> 4 != 4) {
                continue;
            }
            usize::from(packet[0] & 15) * 4
        } else {
            0
        };
        let Some(reply) = packet.get(offset..) else {
            continue;
        };
        if reply.len() == message.len()
            && reply[0] == 0
            && reply[1] == 0
            && reply[6..] == message[6..]
            && checksum(reply) == 0
            && (!raw || reply[4..6] == message[4..6])
        {
            return Ok(());
        }
    }
    Err("caduceus-stats-internet-isp-hop-no-reply")
}
