use std::cmp::Reverse;
use std::ffi::CStr;
use std::fs;
use std::net::{Ipv4Addr, ToSocketAddrs};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct InterfaceAddress {
    pub(crate) interface: String,
    pub(crate) address: Ipv4Addr,
    pub(crate) netmask: Option<Ipv4Addr>,
    pub(crate) mac: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SeatIdentity {
    pub(crate) mac: Option<String>,
    pub(crate) ipv4: Option<Ipv4Addr>,
    pub(crate) ipv4_source: Option<&'static str>,
}

pub(crate) fn local_hostname() -> String {
    fs::read_to_string(super::config::path("etc/hostname"))
        .ok()
        .map(|hostname| normalize_hostname(&hostname))
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn normalize_hostname(hostname: &str) -> String {
    hostname.trim().to_ascii_lowercase()
}

pub(crate) fn resolver_target(hostname: &str) -> Option<String> {
    let hostname = normalize_hostname(hostname);
    if hostname.is_empty() {
        None
    } else if hostname == "home" {
        Some("home.arpa".to_owned())
    } else {
        Some(format!("{hostname}.home.arpa"))
    }
}

pub(crate) fn resolve_home_arpa_ipv4(hostname: &str) -> Option<Ipv4Addr> {
    let target = resolver_target(hostname)?;
    let mut addresses: Vec<Ipv4Addr> = (target.as_str(), 0)
        .to_socket_addrs()
        .ok()?
        .filter_map(|address| match address.ip() {
            std::net::IpAddr::V4(address) => Some(address),
            std::net::IpAddr::V6(_) => None,
        })
        .collect();
    addresses.sort_unstable();
    addresses.dedup();
    addresses.into_iter().next()
}

fn normalized_mac(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let bytes = value.as_bytes();
    (bytes.len() == 17
        && bytes.iter().enumerate().all(|(index, byte)| {
            if index % 3 == 2 {
                *byte == b':'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        }))
    .then_some(value)
}

fn interface_mac(interface: &str) -> Option<String> {
    let path = super::config::path(&format!("sys/class/net/{interface}/address"));
    fs::read_to_string(path)
        .ok()
        .and_then(|mac| normalized_mac(&mac))
}

fn ipv4_from_sockaddr(address: *const libc::sockaddr) -> Option<Ipv4Addr> {
    if address.is_null() || unsafe { (*address).sa_family as i32 } != libc::AF_INET {
        return None;
    }
    let address = unsafe { *(address as *const libc::sockaddr_in) };
    Some(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)))
}

pub(crate) fn local_ipv4_interfaces() -> Vec<InterfaceAddress> {
    let mut head = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Vec::new();
    }

    let mut interfaces = Vec::new();
    let mut current = head;
    while !current.is_null() {
        let address = unsafe { (*current).ifa_addr };
        if let Some(address) = ipv4_from_sockaddr(address) {
            let interface = unsafe {
                if (*current).ifa_name.is_null() {
                    None
                } else {
                    CStr::from_ptr((*current).ifa_name)
                        .to_str()
                        .ok()
                        .map(str::to_owned)
                }
            };
            if let Some(interface) = interface {
                let netmask = ipv4_from_sockaddr(unsafe { (*current).ifa_netmask });
                interfaces.push(InterfaceAddress {
                    mac: interface_mac(&interface),
                    interface,
                    address,
                    netmask,
                });
            }
        }
        current = unsafe { (*current).ifa_next };
    }
    unsafe { libc::freeifaddrs(head) };

    interfaces.sort_by(|left, right| interface_sort_key(left).cmp(&interface_sort_key(right)));
    interfaces
}

fn prefix_len(netmask: Option<Ipv4Addr>) -> u32 {
    netmask.map(u32::from).unwrap_or(0).count_ones()
}

fn network(address: Ipv4Addr, netmask: Option<Ipv4Addr>) -> u32 {
    u32::from(address) & netmask.map(u32::from).unwrap_or(0)
}

fn interface_sort_key(value: &InterfaceAddress) -> (u8, u8, Reverse<u32>, u32, u32, String) {
    (
        address_class(value.address),
        private_rank(value.address).unwrap_or(u8::MAX),
        Reverse(prefix_len(value.netmask)),
        network(value.address, value.netmask),
        u32::from(value.address),
        value.mac.clone().unwrap_or_default(),
    )
}

fn is_cgnat(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    (u32::from(Ipv4Addr::new(100, 64, 0, 0))..=u32::from(Ipv4Addr::new(100, 127, 255, 255)))
        .contains(&value)
}

fn private_rank(address: Ipv4Addr) -> Option<u8> {
    let octets = address.octets();
    if octets[0] == 192 && octets[1] == 168 {
        Some(0)
    } else if octets[0] == 10 {
        Some(1)
    } else if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        Some(2)
    } else {
        None
    }
}

fn address_class(address: Ipv4Addr) -> u8 {
    if address.is_loopback() || address.is_link_local() || address.is_unspecified() {
        4
    } else if private_rank(address).is_some() {
        0
    } else if !is_cgnat(address) && !address.is_multicast() {
        1
    } else {
        2
    }
}

fn eligible_for_fallback(value: &InterfaceAddress) -> bool {
    !value.address.is_loopback()
        && !value.address.is_link_local()
        && !value.address.is_unspecified()
        && !value.address.is_multicast()
}

fn fallback_sort_key(value: &InterfaceAddress) -> (u8, u8, Reverse<u32>, u32, u32, String) {
    let class = if private_rank(value.address).is_some() {
        0
    } else if !is_cgnat(value.address) {
        1
    } else {
        2
    };
    (
        class,
        private_rank(value.address).unwrap_or(u8::MAX),
        Reverse(prefix_len(value.netmask)),
        network(value.address, value.netmask),
        u32::from(value.address),
        value.mac.clone().unwrap_or_default(),
    )
}

fn exact<'a>(
    interfaces: &'a [InterfaceAddress],
    address: Ipv4Addr,
) -> Option<&'a InterfaceAddress> {
    interfaces
        .iter()
        .filter(|value| value.address == address)
        .min_by_key(|value| interface_sort_key(value))
}

fn fallback<'a>(interfaces: &'a [InterfaceAddress]) -> Option<&'a InterfaceAddress> {
    interfaces
        .iter()
        .filter(|value| eligible_for_fallback(value))
        .min_by_key(|value| fallback_sort_key(value))
}

/// Selects an identity without consulting interface enumeration or name order.
/// A DNS answer is authoritative: no other address may supply its MAC.
pub(crate) fn choose(
    interfaces: &[InterfaceAddress],
    dns_ipv4: Option<Ipv4Addr>,
    bind_ipv4: Option<Ipv4Addr>,
) -> SeatIdentity {
    if let Some(address) = dns_ipv4 {
        return exact(interfaces, address).map_or(
            SeatIdentity {
                mac: None,
                ipv4: None,
                ipv4_source: None,
            },
            |value| SeatIdentity {
                mac: value.mac.clone(),
                ipv4: Some(value.address),
                ipv4_source: Some("dns"),
            },
        );
    }

    let selected = match bind_ipv4.filter(|address| !address.is_unspecified()) {
        Some(address) => exact(interfaces, address),
        None => fallback(interfaces),
    };
    selected.map_or(
        SeatIdentity {
            mac: None,
            ipv4: None,
            ipv4_source: None,
        },
        |value| SeatIdentity {
            mac: value.mac.clone(),
            ipv4: Some(value.address),
            ipv4_source: Some("bind-lan-fallback"),
        },
    )
}

pub(crate) fn current(dns_ipv4: Option<Ipv4Addr>, bind_ipv4: Option<Ipv4Addr>) -> SeatIdentity {
    choose(&local_ipv4_interfaces(), dns_ipv4, bind_ipv4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn interface(name: &str, address: [u8; 4], netmask: [u8; 4], mac: &str) -> InterfaceAddress {
        InterfaceAddress {
            interface: name.to_owned(),
            address: Ipv4Addr::from(address),
            netmask: Some(Ipv4Addr::from(netmask)),
            mac: Some(mac.to_owned()),
        }
    }

    #[test]
    fn hostname_is_trimmed_and_lowercased() {
        assert_eq!("fixture-host", normalize_hostname("  Fixture-Host\n"));
    }

    #[test]
    fn resolver_target_is_canonical_without_network_access() {
        assert_eq!(resolver_target("  HOME\n").as_deref(), Some("home.arpa"));
        assert_eq!(
            resolver_target("  Fixture-Host\n").as_deref(),
            Some("fixture-host.home.arpa")
        );
        assert_eq!(resolver_target("  \n"), None);
    }

    #[test]
    fn dns_selects_exact_interface_even_when_wan_and_bridge_precede_lan() {
        let interfaces = vec![
            interface(
                "wan0",
                [100, 90, 0, 4],
                [255, 255, 0, 0],
                "aa:aa:aa:aa:aa:aa",
            ),
            interface(
                "br0",
                [172, 18, 0, 2],
                [255, 255, 0, 0],
                "bb:bb:bb:bb:bb:bb",
            ),
            interface(
                "lan0",
                [192, 168, 123, 44],
                [255, 255, 255, 0],
                "cc:cc:cc:cc:cc:cc",
            ),
        ];
        let identity = choose(&interfaces, Some(Ipv4Addr::new(192, 168, 123, 44)), None);
        assert_eq!(identity.mac.as_deref(), Some("cc:cc:cc:cc:cc:cc"));
        assert_eq!(identity.ipv4, Some(Ipv4Addr::new(192, 168, 123, 44)));
        assert_eq!(identity.ipv4_source, Some("dns"));
    }

    #[test]
    fn missing_dns_uses_deterministic_private_lan_fallback() {
        let interfaces = vec![
            interface(
                "wan0",
                [100, 90, 0, 4],
                [255, 255, 0, 0],
                "aa:aa:aa:aa:aa:aa",
            ),
            interface(
                "br0",
                [172, 18, 0, 2],
                [255, 255, 0, 0],
                "bb:bb:bb:bb:bb:bb",
            ),
            interface(
                "lan0",
                [192, 168, 123, 44],
                [255, 255, 255, 0],
                "cc:cc:cc:cc:cc:cc",
            ),
            interface("lo", [127, 0, 0, 1], [255, 0, 0, 0], "dd:dd:dd:dd:dd:dd"),
        ];
        let identity = choose(&interfaces, None, Some(Ipv4Addr::new(0, 0, 0, 0)));
        assert_eq!(identity.mac.as_deref(), Some("cc:cc:cc:cc:cc:cc"));
        assert_eq!(identity.ipv4, Some(Ipv4Addr::new(192, 168, 123, 44)));
        assert_eq!(identity.ipv4_source, Some("bind-lan-fallback"));
    }
}
