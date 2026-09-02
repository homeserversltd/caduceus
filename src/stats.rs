//! Native, persistent per-host appliance telemetry.
use crate::shared::config;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::CString,
    fs,
    net::TcpStream,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, OnceLock, RwLock,
    },
    time::Instant,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::interval;

const RAW_LIMIT: usize = 3600;
const MINUTE_LIMIT: usize = 10_080;
const UNAVAILABLE: &str = "collector unavailable";
struct StatsState {
    raw: VecDeque<Value>,
    minute: VecDeque<Value>,
    model_lanes: Vec<Value>,
    last_model_lane_pulse_unix: AtomicU64,
    model_lane_pulse_requested: AtomicBool,
    error: Option<String>,
    process_ticks: BTreeMap<u32, u64>,
    process_sample_at: Option<Instant>,
    gpu_cache: Option<Value>,
    last_gpu_refresh: Option<Instant>,
}
static STATE: OnceLock<Arc<RwLock<StatsState>>> = OnceLock::new();
const MODEL_LANE_PULSE_INTERVAL: u64 = 86_400;
const MODEL_LANE_TIMEOUT: Duration = Duration::from_millis(400);

fn db_path() -> PathBuf {
    config::path("var/lib/caduceus/stats.sqlite3")
}
fn open_db() -> Result<Connection, String> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let c = Connection::open(path).map_err(|e| e.to_string())?;
    c.execute_batch("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS raw_samples (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS minute_samples (id INTEGER PRIMARY KEY, bucket INTEGER NOT NULL, data TEXT NOT NULL); CREATE INDEX IF NOT EXISTS raw_ts ON raw_samples(ts); CREATE INDEX IF NOT EXISTS minute_bucket ON minute_samples(bucket);") .map_err(|e| e.to_string())?;
    Ok(c)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn number(s: &str) -> Option<f64> {
    s.parse().ok()
}
fn read_text(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}
fn meminfo() -> Value {
    let mut m = serde_json::Map::new();
    if let Some(t) = read_text("/proc/meminfo") {
        for line in t.lines() {
            let mut p = line.split_whitespace();
            if let (Some(k), Some(v)) = (p.next(), p.next()) {
                if ["MemTotal:", "MemAvailable:", "SwapTotal:", "SwapFree:"].contains(&k) {
                    if let Ok(v) = v.parse::<u64>() {
                        m.insert(k.trim_end_matches(':').to_string(), json!(v * 1024));
                    }
                }
            }
        }
    }
    if let (Some(total), Some(avail)) = (
        m.get("MemTotal").and_then(Value::as_u64),
        m.get("MemAvailable").and_then(Value::as_u64),
    ) {
        m.insert("usedBytes".into(), json!(total.saturating_sub(avail)));
    }
    if let (Some(total), Some(free)) = (
        m.get("SwapTotal").and_then(Value::as_u64),
        m.get("SwapFree").and_then(Value::as_u64),
    ) {
        m.insert("usedBytesSwap".into(), json!(total.saturating_sub(free)));
    }
    Value::Object(m)
}
fn load() -> Value {
    read_text("/proc/loadavg")
        .and_then(|s| {
            s.split_whitespace()
                .take(3)
                .map(number)
                .collect::<Option<Vec<_>>>()
        })
        .map(|v| json!({"one":v[0],"five":v[1],"fifteen":v[2]}))
        .unwrap_or(Value::Null)
}
fn thermal_label(name: &str) -> &'static str {
    let name = name.trim().to_ascii_lowercase();
    if matches!(name.as_str(), "coretemp" | "k10temp" | "zenpower") {
        "cpu"
    } else if name == "amdgpu" || name.starts_with("nvidia") {
        "gpu"
    } else if name == "nvme" || name.starts_with("nvme") {
        "storage"
    } else {
        "other"
    }
}
fn temperatures() -> Value {
    let mut paths = BTreeSet::new();
    let mut sources: BTreeMap<PathBuf, &'static str> = BTreeMap::new();
    if let Ok(entries) = fs::read_dir("/sys/class/thermal") {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("thermal_zone") {
                let path = e.path().join("temp");
                paths.insert(path.clone());
                let label = read_text(&e.path().join("type").to_string_lossy())
                    .map(|s| thermal_label(&s))
                    .unwrap_or("other");
                sources.insert(path, label);
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/sys/class/hwmon") {
        for e in entries.flatten() {
            let label = read_text(&e.path().join("name").to_string_lossy())
                .map(|s| thermal_label(&s))
                .unwrap_or("other");
            if let Ok(ts) = fs::read_dir(e.path()) {
                for t in ts.flatten() {
                    let n = t.file_name().to_string_lossy().to_string();
                    if n.starts_with("temp") && n.ends_with("_input") {
                        let path = t.path();
                        paths.insert(path.clone());
                        sources.insert(path, label);
                    }
                }
            }
        }
    }
    let mut values = Vec::new();
    let mut by_source = Vec::new();
    for path in paths {
        if let Some(value) = fs::read_to_string(&path)
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
        {
            let celsius = value / 1000.0;
            values.push(celsius);
            by_source.push(json!({
                "label": sources.get(&path).copied().unwrap_or("other"),
                "celsius": celsius,
            }));
        }
    }
    if values.is_empty() {
        Value::Null
    } else {
        json!({"celsius": values.iter().sum::<f64>() / values.len() as f64, "sources": values.len(), "bySource": by_source})
    }
}
fn fans() -> Value {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir("/sys/class/hwmon") {
        for e in entries.flatten() {
            let label = match read_text(&e.path().join("name").to_string_lossy()) {
                Some(name) => name.trim().to_string(),
                None => continue,
            };
            if let Ok(files) = fs::read_dir(e.path()) {
                for file in files.flatten() {
                    let name = file.file_name().to_string_lossy().to_string();
                    if name.starts_with("fan") && name.ends_with("_input") {
                        if let Some(rpm) = fs::read_to_string(file.path())
                            .ok()
                            .and_then(|v| v.trim().parse::<f64>().ok())
                        {
                            out.push(json!({"label":label,"rpm":rpm}));
                        }
                    }
                }
            }
        }
    }
    if out.is_empty() {
        Value::Null
    } else {
        json!(out)
    }
}
fn network() -> Value {
    let excluded = |n: &str| {
        n == "lo"
            || n == "docker0"
            || n.starts_with("br-")
            || n.starts_with("virbr")
            || n.starts_with("vnet")
            || n.starts_with("zt")
    };
    let mut list = Vec::new();
    if let Some(t) = read_text("/proc/net/dev") {
        for line in t.lines().skip(2) {
            if let Some((name, rest)) = line.split_once(':') {
                let name = name.trim();
                let p: Vec<_> = rest.split_whitespace().collect();
                if !excluded(name) && p.len() >= 9 {
                    let state = read_text(&format!("/sys/class/net/{name}/operstate"))
                        .map(|s| s.trim().to_string());
                    list.push(json!({"name":name,"rxBytes":p[0].parse::<u64>().unwrap_or(0),"txBytes":p[8].parse::<u64>().unwrap_or(0),"operstate":state}));
                }
            }
        }
    }
    list.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    json!(list)
}
fn tcp() -> Value {
    let mut counts = serde_json::Map::new();
    for file in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Some(t) = read_text(file) {
            for line in t.lines().skip(1) {
                if let Some(state) = line.split_whitespace().nth(3) {
                    let k = match state {
                        "01" => "established",
                        "0A" => "listen",
                        "02" => "synSent",
                        "03" => "synRecv",
                        "04" => "finWait1",
                        "05" => "finWait2",
                        "06" => "timeWait",
                        "07" => "close",
                        "08" => "closeWait",
                        "09" => "lastAck",
                        "0B" => "closing",
                        _ => "other",
                    };
                    *counts.entry(k).or_insert(json!(0)) =
                        json!(counts.get(k).and_then(Value::as_u64).unwrap_or(0) + 1);
                }
            }
        }
    }
    Value::Object(counts)
}
fn disk_io(usage: &Value) -> Value {
    let mut wanted = BTreeSet::new();
    if let Some(rows) = usage.as_array() {
        for row in rows {
            if let (Some(fs), Some(mount)) = (row["filesystem"].as_str(), row["path"].as_str()) {
                wanted.insert((
                    fs.rsplit('/').next().unwrap_or(fs).to_string(),
                    mount.to_string(),
                ));
            }
        }
    }
    let mut stats = std::collections::BTreeMap::new();
    if let Some(t) = read_text("/proc/diskstats") {
        for l in t.lines() {
            let p: Vec<_> = l.split_whitespace().collect();
            if p.len() > 9 {
                stats.insert(
                    p[2].to_string(),
                    (
                        p[5].parse::<u64>().unwrap_or(0) * 512,
                        p[9].parse::<u64>().unwrap_or(0) * 512,
                    ),
                );
            }
        }
    }
    let mut out = Vec::new();
    for (device, mount) in wanted {
        if let Some((r, w)) = stats.get(&device) {
            out.push(json!({"device":device,"mount":mount,"readBytes":r,"writeBytes":w}));
        }
    }
    json!(out)
}
fn has_nvidia_gpu() -> bool {
    if fs::read_dir("/proc/driver/nvidia/gpus")
        .ok()
        .and_then(|mut entries| entries.next())
        .is_some()
    {
        return true;
    }
    fs::read_dir("/sys/class/drm")
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_prefix("card")
                .map_or(false, |n| {
                    !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())
                })
        })
        .any(|e| {
            read_text(&e.path().join("device/vendor").to_string_lossy())
                .map_or(false, |v| v.trim().eq_ignore_ascii_case("0x10de"))
        })
}
fn refresh_nvidia_gpu_cache() -> Option<(bool, String)> {
    let mut c = Command::new("nvidia-smi");
    c.args([
        "--query-gpu=utilization.gpu,temperature.gpu,fan.speed,memory.used,memory.total",
        "--format=csv,noheader,nounits",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    let mut child = c.spawn().ok()?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().ok()? {
            let output = child.wait_with_output().ok()?;
            return Some((status.success(), String::from_utf8(output.stdout).ok()?));
        }
        if start.elapsed() >= Duration::from_millis(900) {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn nvidia_gpu_output(output: &str) -> Value {
    let f = match output.lines().find(|l| !l.trim().is_empty()) {
        Some(l) => l.split(',').map(str::trim).collect::<Vec<_>>(),
        None => return Value::Null,
    };
    if f.len() != 5 {
        return Value::Null;
    }
    let n = |s: &str| s.parse::<f64>().ok().filter(|v| v.is_finite());
    let (u, t, fan) = match (n(f[0]), n(f[1]), n(f[2])) {
        (Some(a), Some(b), Some(c)) => (a, b, c),
        _ => return Value::Null,
    };
    let m = |s: &str| s.parse::<u64>().ok()?.checked_mul(1024)?.checked_mul(1024);
    let (used, total) = match (m(f[3]), m(f[4])) {
        (Some(a), Some(b)) => (a, b),
        _ => return Value::Null,
    };
    json!({"utilizationPercent":u,"temperatureCelsius":t,"fanPercent":fan,"memoryUsedBytes":used,"memoryTotalBytes":total})
}
fn gpu_sysfs() -> Value {
    let mut out = serde_json::Map::new();
    let mut temps = Vec::new();
    if let Ok(es) = fs::read_dir("/sys/class/drm") {
        for e in es.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.strip_prefix("card").map_or(false, |n| {
                !n.is_empty() && n.chars().all(|c| c.is_ascii_digit())
            }) {
                continue;
            }
            let d = e.path().join("device");
            if read_text(&d.join("vendor").to_string_lossy()).is_none() {
                continue;
            }
            for (file, key) in [
                ("gpu_busy_percent", "utilizationPercent"),
                ("mem_info_vram_used", "memoryUsedBytes"),
                ("mem_info_vram_total", "memoryTotalBytes"),
            ] {
                if let Some(v) = read_text(&d.join(file).to_string_lossy())
                    .and_then(|x| x.trim().parse::<u64>().ok())
                {
                    out.insert(key.into(), json!(v));
                }
            }
            if let Ok(hs) = fs::read_dir(d.join("hwmon")) {
                for h in hs.flatten() {
                    if let Ok(fs2) = fs::read_dir(h.path()) {
                        for f in fs2.flatten() {
                            let n = f.file_name().to_string_lossy().to_string();
                            if n.starts_with("temp") && n.ends_with("_input") {
                                if let Some(v) = read_text(&f.path().to_string_lossy())
                                    .and_then(|x| x.trim().parse::<f64>().ok())
                                {
                                    temps.push(v / 1000.0)
                                }
                            } else if n.starts_with("pwm") && n.ends_with("_max") {
                                if let Some(max) = read_text(&f.path().to_string_lossy())
                                    .and_then(|x| x.trim().parse::<f64>().ok())
                                    .filter(|v| v.is_finite() && *v > 0.0)
                                {
                                    let pwm_name = n.trim_end_matches("_max");
                                    let pwm_path = f.path().with_file_name(pwm_name);
                                    if let Some(value) = read_text(&pwm_path.to_string_lossy())
                                        .and_then(|x| x.trim().parse::<f64>().ok())
                                        .filter(|v| v.is_finite())
                                    {
                                        out.insert("fanPercent".into(), json!(value * 100.0 / max));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if let Some(v) = temps.first() {
        out.insert("temperatureCelsius".into(), json!(*v));
    }
    if out.is_empty() {
        Value::Null
    } else {
        Value::Object(out)
    }
}
fn gpu(cached: Option<&Value>) -> Value {
    let mut out = match cached {
        Some(Value::Object(m)) => m.clone(),
        _ => serde_json::Map::new(),
    };
    if let Value::Object(m) = gpu_sysfs() {
        for (k, v) in m {
            out.insert(k, v);
        }
    }
    if out.is_empty() {
        Value::Null
    } else {
        Value::Object(out)
    }
}
fn statvfs_bytes(path: &str) -> Option<(u64, u64, u64)> {
    let path = CString::new(path).ok()?;
    let mut st = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(path.as_ptr(), st.as_mut_ptr()) } != 0 {
        return None;
    }
    let st = unsafe { st.assume_init() };
    let block = st.f_frsize.max(1) as u64;
    Some((
        (st.f_blocks as u64).checked_mul(block)?,
        (st.f_blocks as u64)
            .saturating_sub(st.f_bfree as u64)
            .checked_mul(block)?,
        (st.f_bavail as u64).checked_mul(block)?,
    ))
}
fn unescape_mountinfo(s: &str) -> String {
    let mut o = String::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if i + 4 <= b.len()
            && b[i] == b'\\'
            && b[i + 1..i + 4].iter().all(|x| (b'0'..=b'7').contains(x))
        {
            o.push((b[i + 1..i + 4].iter().fold(0, |n, x| n * 8 + x - b'0')) as char);
            i += 4
        } else {
            o.push(b[i] as char);
            i += 1
        }
    }
    o
}
fn mount_owner(path: &str) -> Option<(String, String)> {
    let mut best = None;
    for line in read_text("/proc/self/mountinfo")?.lines() {
        let Some((l, r)) = line.split_once(" - ") else {
            continue;
        };
        let f: Vec<_> = l.split_whitespace().collect();
        let Some(mf) = f.get(4) else { continue };
        let m = unescape_mountinfo(mf);
        if (path == m || path.starts_with(&(m.trim_end_matches('/').to_owned() + "/")))
            && best
                .as_ref()
                .map_or(true, |b: &(String, String, usize)| m.len() > b.2)
        {
            let Some(sf) = r.split_whitespace().nth(1) else {
                continue;
            };
            let mount_len = m.len();
            best = Some((unescape_mountinfo(sf), m, mount_len));
        }
    }
    best.map(|(s, m, _)| (s, m))
}
fn disk_usage() -> Value {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for path in ["/", "/home", "/vault", "/mnt/nas"] {
        let Some((total, used, available)) = statvfs_bytes(path) else {
            continue;
        };
        let (fsname, mount) = mount_owner(path).unwrap_or_else(|| ("unknown".into(), path.into()));
        if !seen.insert(mount.clone()) {
            continue;
        }
        let d = used.saturating_add(available);
        let pct = if d == 0 {
            0
        } else {
            used.saturating_mul(100).saturating_add(d - 1) / d
        };
        out.push(json!({"filesystem":fsname,"path":mount,"totalBytes":total,"usedBytes":used,"availableBytes":available,"usePercent":format!("{pct}%")}));
    }
    json!(out)
}
fn processes(
    previous: &BTreeMap<u32, u64>,
    elapsed: Option<Duration>,
) -> (Value, BTreeMap<u32, u64>) {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    let mut next = BTreeMap::new();
    let mut rows = Vec::new();
    if let Ok(es) = fs::read_dir("/proc") {
        for e in es.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            let Some(stat) = read_text(&e.path().join("stat").to_string_lossy()) else {
                continue;
            };
            let Some(close) = stat.rfind(')') else {
                continue;
            };
            let Some(open) = stat.find('(').filter(|open| *open < close) else {
                continue;
            };
            let f: Vec<_> = stat[close + 2..].split_whitespace().collect();
            if f.len() <= 19 {
                continue;
            }
            let Ok(u) = f[11].parse::<u64>() else {
                continue;
            };
            let Ok(st) = f[12].parse::<u64>() else {
                continue;
            };
            let ticks = u + st;
            next.insert(pid, ticks);
            let rss = read_text(&e.path().join("statm").to_string_lossy())
                .and_then(|x| x.split_whitespace().nth(1)?.parse::<u64>().ok())
                .unwrap_or(0)
                * page;
            let command = stat[open + 1..close].to_string();
            let cpu = match (previous.get(&pid), elapsed) {
                (Some(old), Some(dt)) if dt.as_secs_f64() > 0.0 => {
                    ticks.saturating_sub(*old) as f64 / hz / dt.as_secs_f64() * 100.0
                }
                _ => 0.0,
            };
            if !["ps", "sh", "bash", "sudo", "python3"].contains(&command.as_str())
                && (cpu > 0.0 || rss > 0)
            {
                rows.push(
                    json!({"command":command,"cpuPercent":cpu,"rssBytes":rss,"processCount":1}),
                );
            }
        }
    }
    rows.sort_by(|a, b| {
        b["cpuPercent"]
            .as_f64()
            .partial_cmp(&a["cpuPercent"].as_f64())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    rows.truncate(10);
    (json!(rows), next)
}

fn loopback_listener_ports() -> BTreeSet<u16> {
    let mut ports = BTreeSet::new();
    for (path, ipv6) in [("/proc/net/tcp", false), ("/proc/net/tcp6", true)] {
        let Some(contents) = read_text(path) else {
            continue;
        };
        for line in contents.lines().skip(1) {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 4 || fields[3] != "0A" {
                continue;
            }
            let Some((address, port)) = fields[1].split_once(':') else {
                continue;
            };
            let loopback = if ipv6 {
                if address.len() != 32 {
                    false
                } else {
                    let mut bytes = [0u8; 16];
                    let parsed = (0..16).all(|i| {
                        u8::from_str_radix(&address[i * 2..i * 2 + 2], 16)
                            .map(|v| bytes[i] = v)
                            .is_ok()
                    });
                    for chunk in bytes.chunks_exact_mut(4) {
                        chunk.reverse();
                    }
                    parsed
                        && (bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
                            || (0..10).all(|i| bytes[i] == 0)
                                && bytes[10..12] == [255, 255]
                                && bytes[12..] == [127, 0, 0, 1])
                }
            } else if address.len() == 8 {
                u32::from_str_radix(address, 16)
                    .ok()
                    .map(|v| v.to_le_bytes() == [127, 0, 0, 1])
                    .unwrap_or(false)
            } else {
                false
            };
            if loopback {
                if let Ok(port) = u16::from_str_radix(port, 16) {
                    ports.insert(port);
                }
            }
        }
    }
    ports
}

fn http_json(port: u16, path: &str) -> Option<Value> {
    let mut stream = TcpStream::connect_timeout(
        &std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        MODEL_LANE_TIMEOUT,
    )
    .ok()?;
    stream.set_read_timeout(Some(MODEL_LANE_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(MODEL_LANE_TIMEOUT)).ok()?;
    use std::io::{Read, Write};
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).ok()?;
    let split = bytes.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&bytes[..split]).ok()?;
    if !headers.lines().next()?.contains(" 200 ") {
        return None;
    }
    serde_json::from_slice(&bytes[split + 4..]).ok()
}

fn model_lane(port: u16) -> Option<Value> {
    let props = http_json(port, "/props");
    if let Some(props) = props.as_ref() {
        let total_slots = props.get("total_slots").and_then(Value::as_i64);
        let alias = props
            .get("model_alias")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned);
        if let (Some(alias), Some(total_slots)) = (alias, total_slots) {
            let n_ctx_per_slot = props
                .pointer("/default_generation_settings/n_ctx")
                .and_then(Value::as_i64);
            let busy_slots = if props.get("endpoint_slots").and_then(Value::as_bool) == Some(true) {
                http_json(port, "/slots").and_then(|slots| {
                    slots.as_array().map(|items| {
                        items
                            .iter()
                            .filter(|item| {
                                item.get("is_processing").and_then(Value::as_bool) == Some(true)
                            })
                            .count() as i64
                    })
                })
            } else {
                None
            };
            return Some(
                json!({"alias":alias,"total_slots":total_slots,"n_ctx_per_slot":n_ctx_per_slot,"busy_slots":busy_slots}),
            );
        }
    }
    let models = http_json(port, "/v1/models")?;
    let first = models.get("data")?.as_array()?.first()?;
    let n_ctx = first.pointer("/meta/n_ctx").and_then(Value::as_i64)?;
    let alias = first
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .or_else(|| {
            first
                .pointer("/meta/model_alias")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })?;
    Some(
        json!({"alias":alias,"total_slots":Value::Null,"n_ctx_per_slot":n_ctx,"busy_slots":Value::Null}),
    )
}

fn scan_model_lanes() -> Vec<Value> {
    loopback_listener_ports()
        .into_iter()
        .filter_map(model_lane)
        .collect()
}

fn snapshot_with_state(
    previous: Option<&Value>,
    process_ticks: &BTreeMap<u32, u64>,
    elapsed: Option<Duration>,
    gpu_cache: Option<&Value>,
) -> (Value, BTreeMap<u32, u64>) {
    let ts = now();
    let net = network();
    let usage = disk_usage();
    let io = disk_io(&usage);
    let mut v = json!({"schema":"caduceus.appliance.stats.sample.v1","ts":ts,"collectedAt":chrono::DateTime::<chrono::Utc>::from_timestamp(ts,0).map(|d|d.to_rfc3339()),"load":load(),"temperature":temperatures(),"fans":fans(),"gpu":gpu(gpu_cache),"memory":meminfo(),"network":{"interfaces":net,"throughput":Value::Null},"tcp":tcp(),"disk":{"io":io,"usage":usage,"throughput":Value::Null},"processes":Value::Null});
    if let Some(prev) = previous {
        let dt = (ts - prev.get("ts").and_then(Value::as_i64).unwrap_or(ts)).max(1) as f64;
        let mut through = json!({});
        if let (Some(a), Some(b)) = (
            prev.pointer("/network/interfaces")
                .and_then(Value::as_array),
            v.pointer("/network/interfaces").and_then(Value::as_array),
        ) {
            let rx = a
                .iter()
                .filter_map(|x| x.get("rxBytes").and_then(Value::as_u64))
                .sum::<u64>();
            let tx = a
                .iter()
                .filter_map(|x| x.get("txBytes").and_then(Value::as_u64))
                .sum::<u64>();
            let rx2 = b
                .iter()
                .filter_map(|x| x.get("rxBytes").and_then(Value::as_u64))
                .sum::<u64>();
            let tx2 = b
                .iter()
                .filter_map(|x| x.get("txBytes").and_then(Value::as_u64))
                .sum::<u64>();
            through = json!({"rxBytesPerSecond":(rx2.saturating_sub(rx) as f64)/dt,"txBytesPerSecond":(tx2.saturating_sub(tx) as f64)/dt});
        }
        v["network"]["throughput"] = through;
        let total = |x: &Value, key: &str| {
            x.as_array()
                .map(|a| a.iter().filter_map(|r| r[key].as_u64()).sum::<u64>())
                .unwrap_or(0)
        };
        if let (Some(a), Some(b)) = (prev.pointer("/disk/io"), v.pointer("/disk/io")) {
            v["disk"]["throughput"] = json!({"readBytesPerSecond":total(b,"readBytes").saturating_sub(total(a,"readBytes")) as f64/dt,"writeBytesPerSecond":total(b,"writeBytes").saturating_sub(total(a,"writeBytes")) as f64/dt});
        }
    }
    let (processes, ticks) = processes(process_ticks, elapsed);
    v["processes"] = processes;
    (v, ticks)
}
fn avg(samples: &[Value], path: &str) -> Value {
    let v: Vec<f64> = samples
        .iter()
        .filter_map(|x| x.pointer(path).and_then(Value::as_f64))
        .collect();
    if v.is_empty() {
        Value::Null
    } else {
        json!(v.iter().sum::<f64>() / v.len() as f64)
    }
}
fn aggregate(bucket: i64, samples: &[Value]) -> Value {
    json!({"schema":"caduceus.appliance.stats.minute.v1","bucket":bucket,"samples":samples.len(),"aggregation":{"loadOne":avg(samples,"/load/one"),"loadFive":avg(samples,"/load/five"),"loadFifteen":avg(samples,"/load/fifteen"),"temperatureCelsius":avg(samples,"/temperature/celsius"),"gpuUtilizationPercent":avg(samples,"/gpu/utilizationPercent"),"gpuTemperatureCelsius":avg(samples,"/gpu/temperatureCelsius"),"memoryUsedBytes":avg(samples,"/memory/usedBytes"),"swapUsedBytes":avg(samples,"/memory/usedBytesSwap"),"networkRxBytesPerSecond":avg(samples,"/network/throughput/rxBytesPerSecond"),"networkTxBytesPerSecond":avg(samples,"/network/throughput/txBytesPerSecond"),"diskReadBytesPerSecond":avg(samples,"/disk/throughput/readBytesPerSecond"),"diskWriteBytesPerSecond":avg(samples,"/disk/throughput/writeBytesPerSecond")},"last":samples.last()})
}
fn persist(c: &Connection, v: &Value) -> Result<(), String> {
    let ts = v["ts"].as_i64().unwrap_or_else(now);
    c.execute(
        "INSERT INTO raw_samples(ts,data) VALUES(?1,?2)",
        params![ts, v.to_string()],
    )
    .map_err(|e| e.to_string())?;
    c.execute("DELETE FROM raw_samples WHERE id NOT IN (SELECT id FROM raw_samples ORDER BY ts DESC,id DESC LIMIT ?1)",[RAW_LIMIT]).map_err(|e|e.to_string())?;
    Ok(())
}
fn persist_minute(c: &Connection, v: &Value) -> Result<(), String> {
    c.execute(
        "INSERT INTO minute_samples(bucket,data) VALUES(?1,?2)",
        params![v["bucket"].as_i64().unwrap_or(0), v.to_string()],
    )
    .map_err(|e| e.to_string())?;
    c.execute("DELETE FROM minute_samples WHERE id NOT IN (SELECT id FROM minute_samples ORDER BY bucket DESC,id DESC LIMIT ?1)",[MINUTE_LIMIT]).map_err(|e|e.to_string())?;
    Ok(())
}
fn load_state(c: &Connection) -> Result<(VecDeque<Value>, VecDeque<Value>), String> {
    let mut r = VecDeque::new();
    let mut q = c
        .prepare("SELECT data FROM raw_samples ORDER BY ts ASC,id ASC")
        .map_err(|e| e.to_string())?;
    for x in q
        .query_map([], |z| z.get::<_, String>(0))
        .map_err(|e| e.to_string())?
    {
        if let Ok(v) = serde_json::from_str(&x.map_err(|e| e.to_string())?) {
            r.push_back(v)
        }
    }
    let mut m = VecDeque::new();
    let mut q = c
        .prepare("SELECT data FROM minute_samples ORDER BY bucket ASC,id ASC")
        .map_err(|e| e.to_string())?;
    for x in q
        .query_map([], |z| z.get::<_, String>(0))
        .map_err(|e| e.to_string())?
    {
        if let Ok(v) = serde_json::from_str(&x.map_err(|e| e.to_string())?) {
            m.push_back(v)
        }
    }
    Ok((r, m))
}
async fn collect_loop(
    state: Arc<RwLock<StatsState>>,
    c: Connection,
    mut raw: VecDeque<Value>,
    mut minute: VecDeque<Value>,
) {
    let mut tick = interval(Duration::from_secs(1));
    let mut previous = raw.back().cloned();
    let mut bucket = previous
        .as_ref()
        .and_then(|v| v["ts"].as_i64())
        .unwrap_or_else(now)
        / 60;
    let mut samples = Vec::new();
    loop {
        tick.tick().await;
        let (old_ticks, old_at, old_gpu, old_refresh, pulse) = match state.read() {
            Ok(g) => (
                g.process_ticks.clone(),
                g.process_sample_at,
                g.gpu_cache.clone(),
                g.last_gpu_refresh,
                g.model_lane_pulse_requested.swap(false, Ordering::AcqRel)
                    || old_elapsed(g.last_model_lane_pulse_unix.load(Ordering::Acquire)),
            ),
            Err(_) => continue,
        };
        let instant = Instant::now();
        let elapsed = old_at.map(|at| instant.saturating_duration_since(at));
        let mut cache = old_gpu;
        let due = old_refresh.map_or(true, |at| at.elapsed() >= Duration::from_secs(60));
        let mut refreshed = old_refresh;
        if has_nvidia_gpu() && due {
            let fresh = tokio::task::spawn_blocking(refresh_nvidia_gpu_cache)
                .await
                .ok()
                .flatten()
                .and_then(|(ok, text)| {
                    if ok {
                        Some(nvidia_gpu_output(&text))
                    } else {
                        None
                    }
                })
                .filter(|v| !v.is_null());
            if fresh.is_some() {
                cache = fresh
            }
            refreshed = Some(instant)
        }
        let p = previous.clone();
        let c2 = cache.clone();
        let t2 = old_ticks.clone();
        let (v, ticks) = match tokio::task::spawn_blocking(move || {
            snapshot_with_state(p.as_ref(), &t2, elapsed, c2.as_ref())
        })
        .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };
        let lanes = if pulse {
            let x = tokio::task::spawn_blocking(scan_model_lanes)
                .await
                .unwrap_or_default();
            if let Ok(g) = state.read() {
                g.last_model_lane_pulse_unix
                    .store(now() as u64, Ordering::Release)
            }
            Some(x)
        } else {
            None
        };
        let b = v["ts"].as_i64().unwrap_or(0) / 60;
        if b != bucket && !samples.is_empty() {
            let q = aggregate(bucket, &samples);
            let _ = persist_minute(&c, &q);
            minute.push_back(q);
            while minute.len() > MINUTE_LIMIT {
                minute.pop_front();
            }
            samples.clear();
            bucket = b
        }
        samples.push(v.clone());
        raw.push_back(v.clone());
        while raw.len() > RAW_LIMIT {
            raw.pop_front();
        }
        let _ = persist(&c, &v);
        if let Ok(mut g) = state.write() {
            g.raw = raw.clone();
            g.minute = minute.clone();
            g.process_ticks = ticks;
            g.process_sample_at = Some(instant);
            g.gpu_cache = cache;
            g.last_gpu_refresh = refreshed;
            if let Some(x) = lanes {
                g.model_lanes = x
            }
        }
        previous = Some(v)
    }
}
fn old_elapsed(last: u64) -> bool {
    now().max(0) as u64 >= last.saturating_add(MODEL_LANE_PULSE_INTERVAL)
}
pub fn start() {
    if STATE.get().is_some() {
        return;
    }
    match open_db().and_then(|c| load_state(&c).map(|(r, m)| (c, r, m))) {
        Ok((c, r, m)) => {
            let state = Arc::new(RwLock::new(StatsState {
                raw: r.clone(),
                minute: m.clone(),
                model_lanes: Vec::new(),
                last_model_lane_pulse_unix: AtomicU64::new(0),
                model_lane_pulse_requested: AtomicBool::new(false),
                error: None,
                process_ticks: BTreeMap::new(),
                process_sample_at: None,
                gpu_cache: None,
                last_gpu_refresh: None,
            }));
            let _ = STATE.set(state.clone());
            tokio::spawn(collect_loop(state, c, r, m));
        }
        Err(e) => {
            let _ = STATE.set(Arc::new(RwLock::new(StatsState {
                raw: VecDeque::new(),
                minute: VecDeque::new(),
                model_lanes: Vec::new(),
                last_model_lane_pulse_unix: AtomicU64::new(0),
                model_lane_pulse_requested: AtomicBool::new(false),
                error: Some(format!("{UNAVAILABLE}: {e}")),
                process_ticks: BTreeMap::new(),
                process_sample_at: None,
                gpu_cache: None,
                last_gpu_refresh: None,
            })));
        }
    }
}
fn state() -> Result<Arc<RwLock<StatsState>>, String> {
    STATE
        .get()
        .cloned()
        .ok_or_else(|| format!("{UNAVAILABLE}: not started"))
}
pub fn snapshot() -> Value {
    snapshot_with_state(None, &BTreeMap::new(), None, None).0
}
pub fn current() -> Result<Value, String> {
    let s = state()?;
    let g = s.read().map_err(|_| format!("{UNAVAILABLE}: state lock"))?;
    if let Some(e) = &g.error {
        return Err(e.clone());
    }
    let mut current = g
        .raw
        .back()
        .cloned()
        .ok_or_else(|| format!("{UNAVAILABLE}: no samples yet"))?;
    current["model_lanes"] = json!(g.model_lanes);
    Ok(current)
}
pub fn request_model_lane_pulse() -> Result<Value, String> {
    let s = state()?;
    let g = s.read().map_err(|_| format!("{UNAVAILABLE}: state lock"))?;
    g.model_lane_pulse_requested.store(true, Ordering::Release);
    Ok(json!(g.model_lanes))
}
pub fn history() -> Result<Value, String> {
    let s = state()?;
    let g = s.read().map_err(|_| format!("{UNAVAILABLE}: state lock"))?;
    if let Some(e) = &g.error {
        return Err(e.clone());
    }
    Ok(
        json!({"schema":"caduceus.appliance.stats.history.v1","retention":{"rawSeconds":3600,"rawMaxPoints":RAW_LIMIT,"minuteSeconds":604800,"minuteMaxPoints":MINUTE_LIMIT},"consolidation":{"raw":"one-second samples","minute":{"averages":["load.one","load.five","load.fifteen","temperature.celsius","gpu.utilizationPercent","gpu.temperatureCelsius","memory.usedBytes","memory.usedBytesSwap","network.throughput","disk.throughput"],"lastValue":["cumulative counters","point-in-time gauges/lists: interfaces,tcp,temperature.bySource,fans,gpu,disk.usage,disk.io,processes"]}},"tiers":{"raw":g.raw,"minute":g.minute}}),
    )
}
