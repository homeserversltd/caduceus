//! Bounded conntrack metadata reads; no table mutation, packet capture or logs.
use super::gateway::{Evidence, Wan};
use crate::shared::config;
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    os::unix::fs::OpenOptionsExt,
    path::PathBuf,
    time::{Duration, Instant},
};

const MAX_FLOWS: usize = 16_384;
const MAX_BYTES: usize = 8 * 1024 * 1024;
const READ_BUDGET: Duration = Duration::from_millis(500);
const EVENT_BUDGET: Duration = Duration::from_millis(200);
const SNAPSHOT_CADENCE: Duration = Duration::from_secs(7);

fn open_table(path: &std::path::Path) -> io::Result<fs::File> {
    if !fs::metadata(path)?.is_file() {
        return Err(io::Error::other("not a kernel table file"));
    }
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Tuple {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    ports: [u8; 8],
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    id: u32,
    zone: [u16; 3],
    original: Tuple,
    reply: Tuple,
}

#[derive(Clone)]
struct Flow {
    key: Key,
    seen_reply: bool,
    packets: Option<u64>,
    mark: u32,
}

impl Flow {
    fn eligible(&self, wan: &Wan) -> bool {
        self.mark == 0
            && self.key.original.destination == self.key.reply.source
            && wan.carries(self.key.original.destination)
    }
    fn advanced(&self, previous: &Self) -> bool {
        self.key == previous.key
            && ((!previous.seen_reply && self.seen_reply)
                || previous
                    .packets
                    .zip(self.packets)
                    .is_some_and(|(before, after)| after > before))
    }
    fn useful(&self) -> bool {
        !self.seen_reply || self.packets.is_some()
    }
}

#[derive(Clone)]
struct Tracked {
    flow: Flow,
    read_at: Evidence,
}

pub(super) enum Reader {
    Native(Native),
    Table {
        path: PathBuf,
        previous: BTreeMap<Key, Tracked>,
    },
}

impl Reader {
    pub(super) fn open() -> Result<Self, ()> {
        let path = config::path("proc/net/nf_conntrack");
        match open_table(&path) {
            Ok(file) => {
                let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
                if unsafe { libc::fstatfs(file.as_raw_fd(), &mut stat) } != 0 {
                    return Err(());
                }
                // Honor a root-mounted table like the other filesystem sensors.
                // A real procfs table uses native netlink for stable kernel IDs.
                if stat.f_type != 0x9fa0 {
                    return Ok(Self::Table {
                        path,
                        previous: BTreeMap::new(),
                    });
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(()),
        }
        Native::open().map(Self::Native)
    }

    pub(super) fn listening(&self) -> bool {
        matches!(self, Self::Native(native) if native.events.is_some())
    }

    pub(super) fn observe(&mut self, wan: &Wan) -> Result<Option<Evidence>, ()> {
        match self {
            Self::Native(native) => native.observe(wan),
            Self::Table { path, previous } => {
                let bound = Evidence::now();
                let mut bytes = Vec::new();
                open_table(path)
                    .map_err(|_| ())?
                    .take(MAX_BYTES as u64 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| ())?;
                if bytes.len() > MAX_BYTES {
                    return Err(());
                }
                let text = std::str::from_utf8(&bytes).map_err(|_| ())?;
                let deadline = Instant::now() + READ_BUDGET;
                let mut next = BTreeMap::new();
                let mut evidence = None;
                for (count, line) in text.lines().enumerate() {
                    if count >= MAX_FLOWS || Instant::now() >= deadline {
                        return Err(());
                    }
                    let Some(flow) = proc_flow(line)? else {
                        continue;
                    };
                    if !flow.eligible(wan) {
                        continue;
                    }
                    if let Some(old) = previous.get(&flow.key) {
                        if flow.advanced(&old.flow) {
                            credit(&mut evidence, old.read_at);
                        }
                    }
                    // An absent/new already-replied row is only a baseline.
                    if flow.useful() {
                        next.insert(
                            flow.key.clone(),
                            Tracked {
                                flow,
                                read_at: bound,
                            },
                        );
                    }
                }
                *previous = next;
                Ok(evidence)
            }
        }
    }
}

fn credit(target: &mut Option<Evidence>, bound: Evidence) {
    // Packet time is not the receive time of a dump/event. This earlier,
    // confirmed counter/status sample is a conservative lower bound instead.
    if bound.recent() && target.is_none_or(|old| bound.at > old.at) {
        *target = Some(bound);
    }
}

pub(super) struct Native {
    query: Netlink,
    events: Option<Netlink>,
    previous: BTreeMap<Key, Tracked>,
    next_snapshot: Instant,
}

impl Native {
    fn open() -> Result<Self, ()> {
        // Multicast is supplementary. A body with only dump rights can still
        // use actual counter/status deltas, never existence or a guessed age.
        let events = Netlink::open(7).ok();
        Ok(Self {
            query: Netlink::open(0)?,
            events,
            previous: BTreeMap::new(),
            next_snapshot: Instant::now(),
        })
    }

    fn observe(&mut self, wan: &Wan) -> Result<Option<Evidence>, ()> {
        let mut evidence = None;
        if Instant::now() >= self.next_snapshot {
            let bound = Evidence::now();
            let rows = self.query.request(None, Instant::now() + READ_BUDGET)?;
            let mut next = BTreeMap::new();
            for flow in rows.into_iter().filter(|flow| flow.eligible(wan)) {
                if let Some(old) = self.previous.get(&flow.key) {
                    if flow.advanced(&old.flow) {
                        credit(&mut evidence, old.read_at);
                    }
                }
                if flow.useful() {
                    next.insert(
                        flow.key.clone(),
                        Tracked {
                            flow,
                            read_at: bound,
                        },
                    );
                }
            }
            self.previous = next;
            self.next_snapshot = Instant::now() + SNAPSHOT_CADENCE;
        }
        let deadline = Instant::now() + EVENT_BUDGET;
        let mut bytes = 0;
        let mut messages = 0;
        while Instant::now() < deadline {
            let Some(events) = self.events.as_ref() else {
                break;
            };
            if !ready(events.fd.as_raw_fd(), deadline).map_err(|_| ())? {
                break;
            }
            let Some(batch) = events.receive()? else {
                continue;
            };
            bytes += batch.len();
            if bytes > MAX_BYTES {
                return Err(());
            }
            for message in Messages::new(&batch) {
                let message = message?;
                messages += 1;
                if messages > MAX_FLOWS || message.flags & 0x10 != 0 {
                    return Err(());
                }
                if message.kind == 2 || message.kind == 4 {
                    return Err(());
                }
                if !matches!(message.kind, 0x100 | 0x102) {
                    continue;
                }
                let flow = netlink_flow(message.body)?;
                if !flow.eligible(wan) {
                    continue;
                }
                if let Some(old) = self.previous.get(&flow.key) {
                    if flow.advanced(&old.flow) {
                        credit(&mut evidence, old.read_at);
                    }
                }
                if message.kind == 0x102 || !flow.useful() {
                    self.previous.remove(&flow.key);
                } else if !flow.seen_reply || !self.previous.contains_key(&flow.key) {
                    // An event may have sat in a queue. Confirm the actual
                    // current row before assigning a zero-state timestamp;
                    // NEW/ASSURED existence alone is never fresh evidence.
                    if Instant::now() >= deadline {
                        continue;
                    }
                    let bound = Evidence::now();
                    let current = self.query.request(Some(&flow.key), deadline)?;
                    if let Some(current) = current.into_iter().next().filter(|f| f.eligible(wan)) {
                        if let Some(old) = self.previous.get(&current.key) {
                            if current.advanced(&old.flow) {
                                credit(&mut evidence, old.read_at);
                            }
                        }
                        if current.useful()
                            && self.previous.len() >= MAX_FLOWS
                            && !self.previous.contains_key(&current.key)
                        {
                            return Err(());
                        }
                        if current.useful() {
                            self.previous.insert(
                                current.key.clone(),
                                Tracked {
                                    flow: current,
                                    read_at: bound,
                                },
                            );
                        } else {
                            self.previous.remove(&current.key);
                        }
                    }
                } else if let Some(old) = self.previous.get_mut(&flow.key) {
                    // Keep the earlier real-read bound. Repeated events or
                    // their receive times must not keep sticky state green.
                    old.flow = flow;
                }
            }
        }
        Ok(evidence)
    }
}

struct Netlink {
    fd: OwnedFd,
    sequence: u32,
}

impl Netlink {
    fn open(groups: u32) -> Result<Self, ()> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                12,
            )
        };
        if fd < 0 {
            return Err(());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as _;
        address.nl_groups = groups;
        if unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &address as *const _ as *const _,
                std::mem::size_of_val(&address) as _,
            )
        } != 0
        {
            return Err(());
        }
        Ok(Self { fd, sequence: 0 })
    }

    fn receive(&self) -> Result<Option<Vec<u8>>, ()> {
        let mut buffer = vec![0u8; 65536];
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&sender) as libc::socklen_t;
        let n = unsafe {
            libc::recvfrom(
                self.fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT | libc::MSG_TRUNC,
                &mut sender as *mut _ as *mut _,
                &mut length,
            )
        };
        if n < 0 {
            return if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(())
            };
        }
        if n == 0
            || n as usize > buffer.len()
            || sender.nl_pid != 0
            || sender.nl_family != libc::AF_NETLINK as libc::sa_family_t
        {
            return Err(());
        }
        buffer.truncate(n as usize);
        Ok(Some(buffer))
    }

    fn request(&mut self, key: Option<&Key>, deadline: Instant) -> Result<Vec<Flow>, ()> {
        self.sequence = self.sequence.wrapping_add(1).max(1);
        let mut request = vec![0u8; 20];
        request[4..6].copy_from_slice(&0x101u16.to_ne_bytes()); // CT_GET only, never CTRZERO.
        request[6..8].copy_from_slice(&(if key.is_some() { 1u16 } else { 0x301 }).to_ne_bytes());
        request[8..12].copy_from_slice(&self.sequence.to_ne_bytes());
        if let Some(key) = key {
            request[16] = match key.original.source {
                IpAddr::V4(_) => libc::AF_INET,
                IpAddr::V6(_) => libc::AF_INET6,
            } as u8;
            attribute(
                &mut request,
                1 | 0x8000,
                &encode_tuple(&key.original, key.zone[1]),
            );
            attribute(&mut request, 12, &key.id.to_be_bytes());
            if key.zone[0] != 0 {
                attribute(&mut request, 18, &key.zone[0].to_be_bytes());
            }
        }
        let length = request.len() as u32;
        request[..4].copy_from_slice(&length.to_ne_bytes());
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as _;
        if unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                request.as_ptr().cast(),
                request.len(),
                0,
                &kernel as *const _ as *const _,
                std::mem::size_of_val(&kernel) as _,
            )
        } != request.len() as isize
        {
            return Err(());
        }
        let mut rows = Vec::new();
        let mut bytes = 0;
        while ready(self.fd.as_raw_fd(), deadline).map_err(|_| ())? {
            let Some(batch) = self.receive()? else {
                continue;
            };
            bytes += batch.len();
            if bytes > MAX_BYTES {
                return Err(());
            }
            for message in Messages::new(&batch) {
                let message = message?;
                if message.sequence != self.sequence {
                    continue;
                }
                if message.flags & 0x10 != 0 || message.kind == 4 {
                    return Err(());
                }
                match message.kind {
                    2 => {
                        let error = i32::from_ne_bytes(
                            message
                                .body
                                .get(..4)
                                .ok_or(())?
                                .try_into()
                                .map_err(|_| ())?,
                        );
                        if key.is_some() && error == -libc::ENOENT {
                            return Ok(Vec::new());
                        }
                        return Err(());
                    }
                    3 => {
                        if message.body.len() >= 4 && message.body[..4] != [0; 4] {
                            return Err(());
                        }
                        return Ok(rows);
                    }
                    0x100 => {
                        let row = netlink_flow(message.body)?;
                        if key.is_some_and(|expected| expected != &row.key) {
                            return Err(());
                        }
                        rows.push(row);
                        if rows.len() > MAX_FLOWS {
                            return Err(());
                        }
                        if key.is_some() {
                            return Ok(rows);
                        }
                    }
                    _ => return Err(()),
                }
            }
        }
        // A partial dump is not an empty table or a valid baseline.
        Err(())
    }
}

pub(super) fn ready(fd: RawFd, deadline: Instant) -> io::Result<bool> {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Ok(false);
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let n = unsafe {
            libc::poll(
                &mut poll,
                1,
                left.as_millis().max(1).min(i32::MAX as u128) as i32,
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if n == 0 {
            return Ok(false);
        }
        if poll.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("kernel read failed"));
        }
        return Ok(poll.revents & libc::POLLIN != 0);
    }
}

struct Message<'a> {
    kind: u16,
    flags: u16,
    sequence: u32,
    body: &'a [u8],
}
struct Messages<'a> {
    bytes: &'a [u8],
}
impl<'a> Messages<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}
impl<'a> Iterator for Messages<'a> {
    type Item = Result<Message<'a>, ()>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let result = (|| {
            let header = self.bytes.get(..16).ok_or(())?;
            let length = u32::from_ne_bytes(header[..4].try_into().map_err(|_| ())?) as usize;
            if length < 16 {
                return Err(());
            }
            let body = self.bytes.get(16..length).ok_or(())?;
            let result = Message {
                kind: u16::from_ne_bytes(header[4..6].try_into().map_err(|_| ())?),
                flags: u16::from_ne_bytes(header[6..8].try_into().map_err(|_| ())?),
                sequence: u32::from_ne_bytes(header[8..12].try_into().map_err(|_| ())?),
                body,
            };
            self.bytes = self.bytes.get(align(length)..).ok_or(())?;
            Ok(result)
        })();
        if result.is_err() {
            self.bytes = &[];
        }
        Some(result)
    }
}

fn align(n: usize) -> usize {
    (n + 3) & !3
}
fn attributes(bytes: &[u8]) -> Result<BTreeMap<u16, &[u8]>, ()> {
    let mut result = BTreeMap::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let h = bytes.get(offset..offset + 4).ok_or(())?;
        let length = u16::from_ne_bytes([h[0], h[1]]) as usize;
        if length < 4 {
            return Err(());
        }
        let kind = u16::from_ne_bytes([h[2], h[3]]) & 0x3fff;
        let payload = bytes.get(offset + 4..offset + length).ok_or(())?;
        // Empty alignment pads can legitimately repeat (64-bit counters).
        if !payload.is_empty() && result.insert(kind, payload).is_some() {
            return Err(());
        }
        offset += align(length);
        if offset > bytes.len() || result.len() > 64 {
            return Err(());
        }
    }
    Ok(result)
}
fn attribute(output: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let length = payload.len() + 4;
    output.extend_from_slice(&(length as u16).to_ne_bytes());
    output.extend_from_slice(&kind.to_ne_bytes());
    output.extend_from_slice(payload);
    output.resize(output.len() + align(length) - length, 0);
}
fn be32(bytes: &[u8]) -> Result<u32, ()> {
    Ok(u32::from_be_bytes(bytes.try_into().map_err(|_| ())?))
}
fn be16(bytes: &[u8]) -> Result<u16, ()> {
    Ok(u16::from_be_bytes(bytes.try_into().map_err(|_| ())?))
}

fn decode_tuple(bytes: &[u8], family: u8) -> Result<(Tuple, u16), ()> {
    let a = attributes(bytes)?;
    let ip = attributes(a.get(&1).ok_or(())?)?;
    let address = |kind4, kind6| -> Result<IpAddr, ()> {
        match i32::from(family) {
            libc::AF_INET => Ok(Ipv4Addr::from(
                <[u8; 4]>::try_from(*ip.get(&kind4).ok_or(())?).map_err(|_| ())?,
            )
            .into()),
            libc::AF_INET6 => Ok(Ipv6Addr::from(
                <[u8; 16]>::try_from(*ip.get(&kind6).ok_or(())?).map_err(|_| ())?,
            )
            .into()),
            _ => Err(()),
        }
    };
    let p = attributes(a.get(&2).ok_or(())?)?;
    let protocol = *p.get(&1).and_then(|p| p.first()).ok_or(())?;
    let mut ports = [0u8; 8];
    if matches!(protocol, 6 | 17 | 33 | 132 | 136) {
        ports[..2].copy_from_slice(p.get(&2).filter(|p| p.len() == 2).ok_or(())?);
        ports[2..4].copy_from_slice(p.get(&3).filter(|p| p.len() == 2).ok_or(())?);
    } else if matches!(protocol, 1 | 58) {
        let offset = if protocol == 1 { 0 } else { 3 };
        ports[..2].copy_from_slice(p.get(&(4 + offset)).filter(|p| p.len() == 2).ok_or(())?);
        ports[2] = *p.get(&(5 + offset)).and_then(|p| p.first()).ok_or(())?;
        ports[3] = *p.get(&(6 + offset)).and_then(|p| p.first()).ok_or(())?;
    }
    Ok((
        Tuple {
            source: address(1, 3)?,
            destination: address(2, 4)?,
            protocol,
            ports,
        },
        a.get(&3).map_or(Ok(0), |p| be16(p))?,
    ))
}

fn netlink_flow(body: &[u8]) -> Result<Flow, ()> {
    let family = *body.first().ok_or(())?;
    let a = attributes(body.get(4..).ok_or(())?)?;
    let (original, origin_zone) = decode_tuple(a.get(&1).ok_or(())?, family)?;
    let (reply, reply_zone) = decode_tuple(a.get(&2).ok_or(())?, family)?;
    let packets = a
        .get(&10)
        .map(|bytes| {
            let p = attributes(bytes)?;
            let b = p.get(&1).ok_or(())?;
            Ok::<_, ()>(u64::from_be_bytes((*b).try_into().map_err(|_| ())?))
        })
        .transpose()?;
    Ok(Flow {
        key: Key {
            id: be32(a.get(&12).ok_or(())?)?,
            zone: [
                a.get(&18).map_or(Ok(0), |p| be16(p))?,
                origin_zone,
                reply_zone,
            ],
            original,
            reply,
        },
        seen_reply: be32(a.get(&3).ok_or(())?)? & 2 != 0,
        packets,
        mark: a.get(&8).map_or(Ok(0), |p| be32(p))?,
    })
}

fn encode_tuple(tuple: &Tuple, zone: u16) -> Vec<u8> {
    let mut ip = Vec::new();
    match (tuple.source, tuple.destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            attribute(&mut ip, 1, &source.octets());
            attribute(&mut ip, 2, &destination.octets());
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            attribute(&mut ip, 3, &source.octets());
            attribute(&mut ip, 4, &destination.octets());
        }
        _ => unreachable!(),
    }
    let mut proto = Vec::new();
    attribute(&mut proto, 1, &[tuple.protocol]);
    if matches!(tuple.protocol, 6 | 17 | 33 | 132 | 136) {
        attribute(&mut proto, 2, &tuple.ports[..2]);
        attribute(&mut proto, 3, &tuple.ports[2..4]);
    } else if matches!(tuple.protocol, 1 | 58) {
        let offset = if tuple.protocol == 1 { 0 } else { 3 };
        attribute(&mut proto, 4 + offset, &tuple.ports[..2]);
        attribute(&mut proto, 5 + offset, &tuple.ports[2..3]);
        attribute(&mut proto, 6 + offset, &tuple.ports[3..4]);
    }
    let mut output = Vec::new();
    attribute(&mut output, 1 | 0x8000, &ip);
    attribute(&mut output, 2 | 0x8000, &proto);
    if zone != 0 {
        attribute(&mut output, 3, &zone.to_be_bytes());
    }
    output
}

fn proc_flow(line: &str) -> Result<Option<Flow>, ()> {
    if line.trim().is_empty() {
        return Ok(None);
    }
    let fields: Vec<_> = line.split_whitespace().collect();
    if !matches!(fields.first(), Some(&"ipv4") | Some(&"ipv6")) {
        return Err(());
    }
    let protocol = fields.get(3).ok_or(())?.parse::<u8>().map_err(|_| ())?;
    if !matches!(protocol, 1 | 6 | 17 | 58 | 132 | 136) {
        return Ok(None);
    }
    let values =
        |name: &str| -> Vec<&str> { fields.iter().filter_map(|p| p.strip_prefix(name)).collect() };
    let sources = values("src=");
    let destinations = values("dst=");
    if sources.len() != 2 || destinations.len() != 2 {
        return Err(());
    }
    let sport = values("sport=");
    let dport = values("dport=");
    let ids = values("id=");
    let types = values("type=");
    let codes = values("code=");
    let tuple = |i: usize| -> Result<Tuple, ()> {
        let mut ports = [0u8; 8];
        if matches!(protocol, 1 | 58) {
            ports[..2].copy_from_slice(
                &ids.get(i)
                    .ok_or(())?
                    .parse::<u16>()
                    .map_err(|_| ())?
                    .to_be_bytes(),
            );
            ports[2] = types.get(i).ok_or(())?.parse().map_err(|_| ())?;
            ports[3] = codes.get(i).ok_or(())?.parse().map_err(|_| ())?;
        } else {
            ports[..2].copy_from_slice(
                &sport
                    .get(i)
                    .ok_or(())?
                    .parse::<u16>()
                    .map_err(|_| ())?
                    .to_be_bytes(),
            );
            ports[2..4].copy_from_slice(
                &dport
                    .get(i)
                    .ok_or(())?
                    .parse::<u16>()
                    .map_err(|_| ())?
                    .to_be_bytes(),
            );
        }
        Ok(Tuple {
            source: sources[i].parse().map_err(|_| ())?,
            destination: destinations[i].parse().map_err(|_| ())?,
            protocol,
            ports,
        })
    };
    let packets = values("packets=");
    let packets = match packets.as_slice() {
        [] => None,
        [_, reply] => Some(reply.parse().map_err(|_| ())?),
        _ => return Err(()),
    };
    let number = |name: &str| -> Result<u32, ()> {
        values(name)
            .first()
            .map_or(Ok(0), |p| p.parse().map_err(|_| ()))
    };
    Ok(Some(Flow {
        key: Key {
            id: 0,
            zone: [number("zone=")?.try_into().map_err(|_| ())?, 0, 0],
            original: tuple(0)?,
            reply: tuple(1)?,
        },
        seen_reply: !fields.contains(&"[UNREPLIED]"),
        packets,
        mark: number("mark=")?,
    }))
}
