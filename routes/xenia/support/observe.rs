use super::{observation, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct Listener {
    pub inode: u64,
    pub endpoint: String,
    pub port: Option<u16>,
    pub loopback: bool,
}
impl Listener {
    pub fn value(&self) -> Value {
        json!({"inode": self.inode, "endpoint": self.endpoint, "port": self.port, "loopback": self.loopback})
    }
}

/// Shared kernel socket census for C1 and the C2 observation reader. It does
/// not trust a guest's reported endpoint, nor turn a failed proc read into [].
pub fn sockets() -> Result<Vec<Listener>> {
    let mut result = Vec::new();
    for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let text = fs::read_to_string(path).map_err(|e| observation("H", path, e.to_string()))?;
        for line in text.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 10 {
                return Err(observation("H", path, "socket-row-invalid"));
            }
            if fields[3] != "0A" {
                continue;
            }
            let (hex, port) = fields[1]
                .split_once(':')
                .ok_or_else(|| observation("H", path, "socket-address-invalid"))?;
            let port =
                u16::from_str_radix(port, 16).map_err(|e| observation("H", path, e.to_string()))?;
            let ip = if ipv6 {
                if hex.len() != 32 {
                    return Err(observation("H", path, "socket-ipv6-invalid"));
                }
                let mut bytes = [0u8; 16];
                for i in 0..4 {
                    let word = u32::from_str_radix(&hex[i * 8..i * 8 + 8], 16)
                        .map_err(|e| observation("H", path, e.to_string()))?;
                    bytes[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
                }
                IpAddr::V6(Ipv6Addr::from(bytes))
            } else {
                let word = u32::from_str_radix(hex, 16)
                    .map_err(|e| observation("H", path, e.to_string()))?;
                IpAddr::V4(Ipv4Addr::from(word.to_ne_bytes()))
            };
            let inode = fields[9]
                .parse()
                .map_err(|e: std::num::ParseIntError| observation("H", path, e.to_string()))?;
            result.push(Listener {
                inode,
                port: Some(port),
                loopback: ip.is_loopback(),
                endpoint: format!("http://{}", std::net::SocketAddr::new(ip, port)),
            });
        }
    }
    let path = "/proc/net/unix";
    let text = fs::read_to_string(path).map_err(|e| observation("H", path, e.to_string()))?;
    for line in text.lines().skip(1) {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() < 7 {
            return Err(observation("H", path, "unix-socket-row-invalid"));
        }
        if fields[3] != "00010000" || fields.len() < 8 {
            continue;
        }
        let inode = fields[6]
            .parse()
            .map_err(|e: std::num::ParseIntError| observation("H", path, e.to_string()))?;
        result.push(Listener {
            inode,
            port: None,
            loopback: true,
            endpoint: format!("unix:{}", fields[7]),
        });
    }
    Ok(result)
}

fn unit_properties(unit: &str) -> Result<BTreeMap<String, String>> {
    let mut child = Command::new("systemctl")
        .args([
            "show",
            "--no-pager",
            "--property=LoadState,ActiveState,SubState,ControlGroup,MainPID",
            "--",
            unit,
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| observation("status", "systemctl", e.to_string()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| observation("status", "systemctl", "unit-pipe-absent"))?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.take(65537).read_to_end(&mut bytes).map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            other => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err(observation(
                    "status",
                    "systemctl",
                    format!("unit-observation-timeout-or-failed: {other:?}"),
                ));
            }
        }
    };
    let bytes = reader
        .join()
        .map_err(|_| observation("status", "systemctl", "unit-reader-failed"))?
        .map_err(|e| observation("status", "systemctl", e.to_string()))?;
    if bytes.len() > 65536 {
        return Err(observation("status", "systemctl", "unit-output-too-large"));
    }
    let text =
        String::from_utf8(bytes).map_err(|e| observation("status", "systemctl", e.to_string()))?;
    let props: BTreeMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.into(), v.into()))
        .collect();
    // Some systemctl versions return nonzero for LoadState=not-found. That
    // explicit property is the absence witness; stderr/nonzero alone is not.
    if props.get("LoadState").map(String::as_str) == Some("not-found") {
        return Ok(props);
    }
    if !status.success() {
        return Err(observation(
            "status",
            "systemctl",
            format!("unit-observation-failed: {status}"),
        ));
    }
    for field in [
        "LoadState",
        "ActiveState",
        "SubState",
        "ControlGroup",
        "MainPID",
    ] {
        if !props.contains_key(field) {
            return Err(observation("status", field, "unit-property-absent"));
        }
    }
    Ok(props)
}

fn cgroup_pids(path: &Path, out: &mut BTreeSet<u32>) -> Result<()> {
    let text = fs::read_to_string(path.join("cgroup.procs"))
        .map_err(|e| observation("status", "cgroup.procs", e.to_string()))?;
    for line in text.lines() {
        out.insert(line.parse().map_err(|e: std::num::ParseIntError| {
            observation("status", "cgroup.procs", e.to_string())
        })?);
    }
    for entry in fs::read_dir(path).map_err(|e| observation("status", "cgroup", e.to_string()))? {
        let entry = entry.map_err(|e| observation("status", "cgroup", e.to_string()))?;
        if entry
            .file_type()
            .map_err(|e| observation("status", "cgroup", e.to_string()))?
            .is_dir()
        {
            cgroup_pids(&entry.path(), out)?;
        }
    }
    Ok(())
}

pub fn runtime(entry: &Value) -> Result<Value> {
    if entry["kind"].as_str() != Some("cartridge-process") {
        return Ok(
            json!({"state": "not-process", "unit": null, "listeners": [], "health": "unobserved"}),
        );
    }
    let id = entry["id"]
        .as_str()
        .ok_or_else(|| observation("status", "entry.id", "entry-id-absent"))?;
    let unit = format!("{id}.service");
    let props = unit_properties(&unit)?;
    if props.get("LoadState").map(String::as_str) == Some("not-found") {
        return Ok(
            json!({"state": "absent", "unit": unit, "properties": props, "pids": [], "listeners": [], "health": "unknown"}),
        );
    }
    let group = props.get("ControlGroup").map(String::as_str).unwrap_or("");
    let mut pids = BTreeSet::new();
    if !group.is_empty() {
        if !group.starts_with('/')
            || Path::new(group)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(observation("status", "ControlGroup", "cgroup-path-invalid"));
        }
        cgroup_pids(
            &Path::new("/sys/fs/cgroup").join(group.trim_start_matches('/')),
            &mut pids,
        )?;
    } else if props.get("ActiveState").map(String::as_str) == Some("active") {
        return Err(observation(
            "status",
            "ControlGroup",
            "active-unit-cgroup-absent",
        ));
    }
    let mut inodes = BTreeSet::new();
    for pid in &pids {
        let directory = format!("/proc/{pid}/fd");
        for fd in fs::read_dir(&directory)
            .map_err(|e| observation("status", &directory, e.to_string()))?
        {
            let fd = fd.map_err(|e| observation("status", &directory, e.to_string()))?;
            let target = fs::read_link(fd.path())
                .map_err(|e| observation("status", &directory, e.to_string()))?;
            if let Some(inode) = target
                .to_str()
                .and_then(|s| s.strip_prefix("socket:["))
                .and_then(|s| s.strip_suffix(']'))
            {
                inodes.insert(
                    inode
                        .parse::<u64>()
                        .map_err(|e| observation("status", &directory, e.to_string()))?,
                );
            }
        }
    }
    let listeners: Vec<_> = sockets()?
        .into_iter()
        .filter(|s| s.loopback && inodes.contains(&s.inode))
        .map(|s| s.value())
        .collect();
    Ok(
        json!({"state": props.get("ActiveState"), "unit": unit, "properties": props, "pids": pids, "socket_inodes": inodes, "listeners": listeners, "health": "unobserved"}),
    )
}
