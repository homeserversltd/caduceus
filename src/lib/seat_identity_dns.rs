//! Seat identity DNS: a single bounded native A/IN lookup, independent of NSS.
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

const MALFORMED: &str = "seat-identity-dns-response-malformed";
const FAILED: &str = "seat-identity-dns-query-failed";
const TIMEOUT: &str = "seat-identity-dns-query-timeout";
const SERVFAIL: &str = "seat-identity-dns-response-servfail";
const BUDGET: Duration = Duration::from_millis(100);

fn remaining(deadline: Instant) -> Result<Duration, &'static str> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or(TIMEOUT)
}

fn nameservers(contents: &str) -> Vec<SocketAddr> {
    let mut servers = Vec::new();
    for line in contents.lines() {
        let mut fields = line
            .split(['#', ';'])
            .next()
            .unwrap_or_default()
            .split_whitespace();
        if fields.next() != Some("nameserver") {
            continue;
        }
        if let Some(ip) = fields.next().and_then(|v| v.parse::<IpAddr>().ok()) {
            let server = SocketAddr::new(ip, 53);
            if !servers.contains(&server) {
                servers.push(server);
            }
            if servers.len() == 3 {
                break;
            }
        }
    }
    servers
}

fn query(name: &str, id: u16) -> Result<Vec<u8>, &'static str> {
    if name.len() > 253 || name.is_empty() {
        return Err("seat-identity-dns-name-invalid");
    }
    let mut packet = Vec::with_capacity(18 + name.len());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err("seat-identity-dns-name-invalid");
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.extend_from_slice(&[0, 0, 1, 0, 1]);
    Ok(packet)
}

fn u16_at(packet: &[u8], offset: &mut usize) -> Result<u16, &'static str> {
    let end = offset.checked_add(2).ok_or(MALFORMED)?;
    let bytes = packet.get(*offset..end).ok_or(MALFORMED)?;
    *offset = end;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn name_at(packet: &[u8], offset: &mut usize) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut cursor = *offset;
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut hops = 0;
    let mut encoded_length = 1_usize;
    loop {
        if hops > packet.len() {
            return Err(MALFORMED);
        }
        let length = *packet.get(cursor).ok_or(MALFORMED)?;
        if length & 0xc0 == 0xc0 {
            let next = cursor.checked_add(1).ok_or(MALFORMED)?;
            let target = (usize::from(length & 0x3f) << 8)
                | usize::from(*packet.get(next).ok_or(MALFORMED)?);
            if target >= packet.len() {
                return Err(MALFORMED);
            }
            if !jumped {
                *offset = cursor.checked_add(2).ok_or(MALFORMED)?;
                encoded_length = encoded_length.checked_add(1).ok_or(MALFORMED)?;
            }
            cursor = target;
            jumped = true;
            hops += 1;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(MALFORMED);
        }
        cursor = cursor.checked_add(1).ok_or(MALFORMED)?;
        encoded_length = encoded_length
            .checked_add(usize::from(length) + 1)
            .ok_or(MALFORMED)?;
        if encoded_length > 255 {
            return Err(MALFORMED);
        }
        if length == 0 {
            if !jumped {
                *offset = cursor;
            }
            return Ok(labels);
        }
        let end = cursor.checked_add(usize::from(length)).ok_or(MALFORMED)?;
        labels.push(packet.get(cursor..end).ok_or(MALFORMED)?.to_vec());
        cursor = end;
    }
}

fn name_matches(labels: &[Vec<u8>], expected: &str) -> bool {
    let parts: Vec<_> = expected.split('.').map(str::as_bytes).collect();
    labels.len() == parts.len()
        && labels
            .iter()
            .zip(parts)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn parse(packet: &[u8], id: u16, expected: &str) -> Result<Vec<Ipv4Addr>, &'static str> {
    if packet.len() < 12 || u16::from_be_bytes([packet[0], packet[1]]) != id {
        return Err(MALFORMED);
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0
        || flags & 0x7800 != 0
        || flags & 0x0200 != 0
        || flags & 0x0040 != 0
        || u16::from_be_bytes([packet[4], packet[5]]) != 1
    {
        return Err(MALFORMED);
    }
    let counts = [
        u16::from_be_bytes([packet[6], packet[7]]),
        u16::from_be_bytes([packet[8], packet[9]]),
        u16::from_be_bytes([packet[10], packet[11]]),
    ];
    let mut offset = 12;
    if !name_matches(&name_at(packet, &mut offset)?, expected)
        || u16_at(packet, &mut offset)? != 1
        || u16_at(packet, &mut offset)? != 1
    {
        return Err(MALFORMED);
    }
    let mut answers = Vec::new();
    let mut cname = false;
    for (section, count) in counts.into_iter().enumerate() {
        for _ in 0..count {
            let owner = name_at(packet, &mut offset)?;
            let kind = u16_at(packet, &mut offset)?;
            let class = u16_at(packet, &mut offset)?;
            let ttl_end = offset.checked_add(4).ok_or(MALFORMED)?;
            packet.get(offset..ttl_end).ok_or(MALFORMED)?;
            offset = ttl_end;
            let len = usize::from(u16_at(packet, &mut offset)?);
            let end = offset.checked_add(len).ok_or(MALFORMED)?;
            let data = packet.get(offset..end).ok_or(MALFORMED)?;
            if section == 0 && class == 1 && (kind == 1 || kind == 5) {
                if !name_matches(&owner, expected) {
                    return Err("seat-identity-dns-answer-owner-mismatch");
                }
                if kind == 1 {
                    if data.len() != 4 {
                        return Err(MALFORMED);
                    }
                    answers.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
                } else {
                    let mut cname_offset = offset;
                    name_at(packet, &mut cname_offset)?;
                    if cname_offset != end {
                        return Err(MALFORMED);
                    }
                    cname = true;
                }
            }
            offset = end;
        }
    }
    if offset != packet.len() {
        return Err(MALFORMED);
    }
    if cname {
        return Err("seat-identity-dns-cname-unsupported");
    }
    match flags & 15 {
        0 => Ok(answers),
        3 if answers.is_empty() => Ok(answers),
        3 => Err(MALFORMED),
        2 => Err(SERVFAIL),
        _ => Err("seat-identity-dns-response-failed"),
    }
}

fn exchange(
    server: SocketAddr,
    request: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, &'static str> {
    remaining(deadline)?;
    let bind = if server.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    };
    let socket = UdpSocket::bind(bind).map_err(|_| FAILED)?;
    socket.connect(server).map_err(|_| FAILED)?;
    socket
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|_| FAILED)?;
    socket.send(request).map_err(|_| FAILED)?;
    socket
        .set_read_timeout(Some(remaining(deadline)?))
        .map_err(|_| FAILED)?;
    let mut buf = [0u8; 4096];
    let size = socket.recv(&mut buf).map_err(|error| match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => TIMEOUT,
        _ => FAILED,
    })?;
    remaining(deadline)?;
    Ok(buf[..size].to_vec())
}

pub(super) fn resolve(name: &str) -> Option<Ipv4Addr> {
    let deadline = Instant::now() + BUDGET;
    let contents = fs::read_to_string(super::super::config::path("etc/resolv.conf")).ok()?;
    static NEXT_ID: AtomicU16 = AtomicU16::new(0x5259);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let request = query(name, id).ok()?;
    for server in nameservers(&contents) {
        let result =
            exchange(server, &request, deadline).and_then(|packet| parse(&packet, id, name));
        match result {
            Ok(mut answers) => {
                if remaining(deadline).is_err() {
                    return None;
                }
                answers.sort_unstable();
                answers.dedup();
                let address = answers.into_iter().next()?;
                return (!address.is_loopback()
                    && !address.is_unspecified()
                    && !address.is_link_local()
                    && !address.is_multicast())
                .then_some(address);
            }
            Err(FAILED | TIMEOUT | SERVFAIL) => continue,
            Err(_) => return None,
        }
    }
    None
}
