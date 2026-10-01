//! Native, persistent per-host appliance telemetry.
use crate::shared::config;
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::CString,
    fs::{self, File},
    io::Read,
    net::TcpStream,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock, RwLock,
    },
    thread::{self, JoinHandle},
    time::Instant,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[cfg(leaf_storage_disk_census)]
#[path = "disk_census.rs"]
pub(crate) mod disk_census;

const RAW_RETENTION_SECONDS: i64 = 3600;
const MINUTE_RETENTION_SECONDS: i64 = 604_800;
const RAW_HISTORY_DEFAULT_LIMIT: usize = 3600;
const MINUTE_HISTORY_DEFAULT_LIMIT: usize = 10_080;
const HISTORY_LIMIT_MAX: usize = 20_000;
const UNAVAILABLE: &str = "collector unavailable";
struct StatsState {
    latest: Option<Arc<str>>,
    latest_ts: i64,
    model_lanes: Vec<Value>,
    last_model_lane_pulse_unix: AtomicU64,
    model_lane_pulse_requested: AtomicBool,
    error: Option<String>,
    gpu_cache: Option<Value>,
    last_gpu_refresh: Option<Instant>,
}
static STATE: OnceLock<Arc<RwLock<StatsState>>> = OnceLock::new();
static DATABASE: OnceLock<Result<Mutex<Connection>, String>> = OnceLock::new();
static RAW_PENDING: OnceLock<Mutex<VecDeque<PendingRaw>>> = OnceLock::new();
static COLLECTOR: OnceLock<Mutex<Option<(Arc<AtomicBool>, JoinHandle<Result<(), String>>)>>> =
    OnceLock::new();
const MODEL_LANE_PULSE_INTERVAL: u64 = 86_400;
const MODEL_LANE_TIMEOUT: Duration = Duration::from_millis(400);

#[derive(Clone)]
struct PendingRaw {
    ts: i64,
    sequence: u64,
    data: Arc<str>,
}

fn db_path() -> PathBuf {
    config::path("var/lib/caduceus/stats.sqlite3")
}
fn open_db() -> Result<&'static Mutex<Connection>, String> {
    match DATABASE.get_or_init(|| open_db_once().map(Mutex::new)) {
        Ok(connection) => Ok(connection),
        Err(error) => Err(error.clone()),
    }
}

fn open_db_once() -> Result<Connection, String> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let c = Connection::open(path).map_err(|e| e.to_string())?;
    c.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY; PRAGMA journal_size_limit=8388608; CREATE TABLE IF NOT EXISTS raw_samples (id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS minute_samples (id INTEGER PRIMARY KEY, bucket INTEGER NOT NULL, data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS self_benchmark (id INTEGER PRIMARY KEY, bucket INTEGER NOT NULL, data TEXT NOT NULL); CREATE INDEX IF NOT EXISTS raw_ts ON raw_samples(ts); CREATE INDEX IF NOT EXISTS minute_bucket ON minute_samples(bucket); CREATE INDEX IF NOT EXISTS self_benchmark_bucket ON self_benchmark(bucket); CREATE TABLE IF NOT EXISTS ruyi (mac TEXT PRIMARY KEY, row TEXT NOT NULL, last_seen INTEGER NOT NULL);",
    ).map_err(|e| e.to_string())?;
    c.execute_batch("CREATE TABLE IF NOT EXISTS ruyi_perspective (mac TEXT PRIMARY KEY, json TEXT NOT NULL, received_at INTEGER NOT NULL);")
        .map_err(|e| e.to_string())?;
    Ok(c)
}

fn open_db_read_only() -> Result<Connection, String> {
    open_db()?;
    Connection::open_with_flags(db_path(), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|error| error.to_string())
}

pub fn ruyi_upsert(mac: &str, row_json: &str, last_seen: i64) -> Result<(), String> {
    ruyi_put(mac, row_json, last_seen, None)
}

pub fn ruyi_put(
    mac: &str,
    row_json: &str,
    received_at: i64,
    perspective: Option<&str>,
) -> Result<(), String> {
    let mut c = open_db()?
        .lock()
        .map_err(|_| "stats database lock poisoned".to_string())?;
    let tx = c.transaction().map_err(|e| e.to_string())?;
    tx.execute(
        "INSERT INTO ruyi(mac,row,last_seen) VALUES(?1,?2,?3) ON CONFLICT(mac) DO UPDATE SET row=excluded.row,last_seen=excluded.last_seen",
        params![mac, row_json, received_at],
    ).map_err(|e| e.to_string())?;
    match perspective {
        Some(json) => {
            tx.execute(
            "INSERT INTO ruyi_perspective(mac,json,received_at) VALUES(?1,?2,?3) ON CONFLICT(mac) DO UPDATE SET json=excluded.json,received_at=excluded.received_at",
            params![mac, json, received_at],
        ).map_err(|e| e.to_string())?;
        }
        None => {
            tx.execute("DELETE FROM ruyi_perspective WHERE mac=?1", [mac])
                .map_err(|e| e.to_string())?;
        }
    }
    tx.commit().map_err(|e| e.to_string())
}

pub struct RuyiSnapshot {
    pub rows: Vec<(String, String, i64)>,
    pub perspectives: Vec<(String, String, i64)>,
}

/// Both halves of a GET observe the same SQLite snapshot, even during PUT/DELETE.
pub fn ruyi_snapshot() -> Result<RuyiSnapshot, String> {
    let mut c = open_db()?
        .lock()
        .map_err(|_| "stats database lock poisoned".to_string())?;
    let tx = c.transaction().map_err(|e| e.to_string())?;
    let read = |sql: &str| -> Result<Vec<(String, String, i64)>, String> {
        let mut statement = tx.prepare(sql).map_err(|e| e.to_string())?;
        let rows = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(|e| e.to_string())?;
        rows.map(|row| row.map_err(|e| e.to_string())).collect()
    };
    let rows = read("SELECT mac,row,last_seen FROM ruyi ORDER BY mac")?;
    let perspectives = read("SELECT mac,json,received_at FROM ruyi_perspective ORDER BY mac")?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(RuyiSnapshot { rows, perspectives })
}

pub fn ruyi_row(mac: &str) -> Result<Option<String>, String> {
    open_db()?
        .lock()
        .map_err(|_| "stats database lock poisoned".to_string())?
        .query_row("SELECT row FROM ruyi WHERE mac=?1", [mac], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())
}

/// Remove only the registered row and its author's perspective, never peer evidence.
pub fn ruyi_delete(mac: &str) -> Result<Option<String>, String> {
    let mut c = open_db()?
        .lock()
        .map_err(|_| "stats database lock poisoned".to_string())?;
    let tx = c
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|e| e.to_string())?;
    let row: Option<String> = tx
        .query_row("SELECT row FROM ruyi WHERE mac=?1", [mac], |row| row.get(0))
        .optional()
        .map_err(|e| e.to_string())?;
    let Some(row) = row else {
        return Ok(None);
    };
    let value: Value = serde_json::from_str(&row).map_err(|e| e.to_string())?;
    let hostname = value
        .get("hostname")
        .and_then(Value::as_str)
        .ok_or("caduceus-ruyi-row-invalid")?
        .to_owned();
    tx.execute("DELETE FROM ruyi WHERE mac=?1", [mac])
        .map_err(|e| e.to_string())?;
    tx.execute("DELETE FROM ruyi_perspective WHERE mac=?1", [mac])
        .map_err(|e| e.to_string())?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(Some(hostname))
}

fn ruyi_list_result() -> Result<Vec<(String, String, i64)>, String> {
    let c = open_db()?
        .lock()
        .map_err(|_| "stats database lock poisoned".to_string())?;
    let mut statement = c
        .prepare("SELECT mac,row,last_seen FROM ruyi ORDER BY mac")
        .map_err(|e| e.to_string())?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|e| e.to_string())?;
    rows.map(|row| row.map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()
}

pub fn ruyi_list() -> Result<Vec<(String, String, i64)>, String> {
    ruyi_list_result()
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CpuCounters {
    total: u64,
    idle: u64,
    iowait: u64,
}

fn parse_cpu_counters(stat: &str) -> Option<CpuCounters> {
    let line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let fields = line.split_whitespace().skip(1).collect::<Vec<_>>();
    if fields.len() < 8 {
        return None;
    }
    let counters = fields
        .iter()
        .map(|field| field.parse::<u64>().ok())
        .collect::<Option<Vec<_>>>()?;
    // Linux reports guest and guest_nice inside user and nice already; sum
    // user..steal only to avoid counting either guest counter twice.
    let total = counters[..8]
        .iter()
        .try_fold(0u64, |sum, counter| sum.checked_add(*counter))?;
    Some(CpuCounters {
        total,
        idle: counters[3],
        iowait: counters[4],
    })
}

fn cpu_usage_percent(previous: Option<CpuCounters>, current: Option<CpuCounters>) -> Value {
    let (Some(previous), Some(current)) = (previous, current) else {
        return Value::Null;
    };
    let (Some(total), Some(idle), Some(iowait)) = (
        current.total.checked_sub(previous.total),
        current.idle.checked_sub(previous.idle),
        current.iowait.checked_sub(previous.iowait),
    ) else {
        // A reset or stale counter snapshot is not a meaningful interval.
        return Value::Null;
    };
    if total == 0 {
        return Value::Null;
    }
    // Linux iowait is included in idle. Treating it as idle (not busy) makes
    // the reported value CPU execution pressure, rather than blocked time.
    let idle_delta = idle.saturating_add(iowait);
    let busy = total.saturating_sub(idle_delta.min(total));
    json!((busy as f64 * 100.0 / total as f64).clamp(0.0, 100.0))
}

fn parse_io_pressure(contents: &str) -> Option<(f64, f64)> {
    let mut some = None;
    let mut full = None;
    for line in contents.lines() {
        let mut fields = line.split_whitespace();
        let kind = fields.next()?;
        let mut avg10 = None;
        for field in fields {
            if let Some(value) = field.strip_prefix("avg10=") {
                avg10 = value
                    .parse::<f64>()
                    .ok()
                    .filter(|value| value.is_finite() && (0.0..=100.0).contains(value));
                break;
            }
        }
        match (kind, avg10) {
            ("some", Some(value)) => some = Some(value),
            ("full", Some(value)) => full = Some(value),
            _ => return None,
        }
    }
    Some((some?, full?))
}

fn io_pressure() -> Value {
    let Some(contents) = read_text("/proc/pressure/io") else {
        return json!({"someAvg10":Value::Null,"fullAvg10":Value::Null});
    };
    match parse_io_pressure(&contents) {
        Some((some, full)) => json!({"someAvg10":some,"fullAvg10":full}),
        None => json!({"someAvg10":Value::Null,"fullAvg10":Value::Null}),
    }
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
struct ThermalCache {
    discovered_at: Option<Instant>,
    sources: Vec<(PathBuf, &'static str)>,
    other_values: Vec<(f64, &'static str)>,
    storage_values: Vec<(f64, &'static str)>,
    other_sampled_at: i64,
    storage_sampled_at: i64,
    other_refreshed_at: Option<Instant>,
    storage_refreshed_at: Option<Instant>,
}

impl Default for ThermalCache {
    fn default() -> Self {
        Self {
            discovered_at: None,
            sources: Vec::new(),
            other_values: Vec::new(),
            storage_values: Vec::new(),
            other_sampled_at: 0,
            storage_sampled_at: 0,
            other_refreshed_at: None,
            storage_refreshed_at: None,
        }
    }
}

fn discover_thermal_sources() -> Vec<(PathBuf, &'static str)> {
    let mut sources = BTreeMap::new();
    if let Ok(entries) = fs::read_dir("/sys/class/thermal") {
        for entry in entries.flatten() {
            if entry.file_name().to_string_lossy().starts_with("thermal_zone") {
                let path = entry.path().join("temp");
                let label = read_text(&entry.path().join("type").to_string_lossy())
                    .map(|name| thermal_label(&name))
                    .unwrap_or("other");
                sources.insert(path, label);
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/sys/class/hwmon") {
        for entry in entries.flatten() {
            let label = read_text(&entry.path().join("name").to_string_lossy())
                .map(|name| thermal_label(&name))
                .unwrap_or("other");
            if let Ok(files) = fs::read_dir(entry.path()) {
                for file in files.flatten() {
                    let name = file.file_name().to_string_lossy().to_string();
                    if name.starts_with("temp") && name.ends_with("_input") {
                        sources.insert(file.path(), label);
                    }
                }
            }
        }
    }
    sources.into_iter().collect()
}

fn read_temperature_sources(
    sources: &[(PathBuf, &'static str)],
    storage: bool,
) -> Vec<(f64, &'static str)> {
    sources
        .iter()
        .filter(|(_, label)| (*label == "storage") == storage)
        .filter_map(|(path, label)| {
            let value = fs::read_to_string(path).ok()?.trim().parse::<f64>().ok()? / 1000.0;
            value.is_finite().then_some((value, *label))
        })
        .collect()
}

fn temperatures(cache: &mut ThermalCache) -> (Value, i64, i64) {
    let rediscovered = cache
        .discovered_at
        .map_or(true, |at| at.elapsed() >= Duration::from_secs(60));
    if rediscovered {
        cache.sources = discover_thermal_sources();
        cache.discovered_at = Some(Instant::now());
        cache.other_refreshed_at = None;
        cache.storage_refreshed_at = None;
    }
    if cache
        .other_refreshed_at
        .map_or(true, |at| at.elapsed() >= Duration::from_secs(1))
    {
        cache.other_values = read_temperature_sources(&cache.sources, false);
        cache.other_sampled_at = now();
        cache.other_refreshed_at = Some(Instant::now());
    }
    if cache
        .storage_refreshed_at
        .map_or(true, |at| at.elapsed() >= Duration::from_secs(30))
    {
        cache.storage_values = read_temperature_sources(&cache.sources, true);
        cache.storage_sampled_at = now();
        cache.storage_refreshed_at = Some(Instant::now());
    }
    let mut values = Vec::new();
    let mut by_source = Vec::new();
    for (value, label) in &cache.other_values {
        values.push(*value);
        by_source.push(json!({"label":label,"celsius":value,"sampledAt":cache.other_sampled_at}));
    }
    for (value, label) in &cache.storage_values {
        values.push(*value);
        by_source.push(json!({"label":label,"celsius":value,"sampledAt":cache.storage_sampled_at}));
    }
    let value = if values.is_empty() {
        Value::Null
    } else {
        json!({"celsius": values.iter().sum::<f64>() / values.len() as f64, "sources": values.len(), "bySource": by_source})
    };
    (value, cache.other_sampled_at, cache.storage_sampled_at)
}

#[derive(Default)]
struct FanCache {
    discovered_at: Option<Instant>,
    paths: Vec<(String, PathBuf)>,
}

fn fans(cache: &mut FanCache) -> Value {
    if cache
        .discovered_at
        .map_or(true, |at| at.elapsed() >= Duration::from_secs(60))
    {
        let mut paths = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/class/hwmon") {
            for entry in entries.flatten() {
                let Some(label) = read_text(&entry.path().join("name").to_string_lossy()) else {
                    continue;
                };
                if let Ok(files) = fs::read_dir(entry.path()) {
                    for file in files.flatten() {
                        let name = file.file_name().to_string_lossy().to_string();
                        if name.starts_with("fan") && name.ends_with("_input") {
                            paths.push((label.trim().to_owned(), file.path()));
                        }
                    }
                }
            }
        }
        cache.paths = paths;
        cache.discovered_at = Some(Instant::now());
    }
    let out = cache
        .paths
        .iter()
        .filter_map(|(label, path)| {
            let rpm = fs::read_to_string(path).ok()?.trim().parse::<f64>().ok()?;
            rpm.is_finite().then(|| json!({"label":label,"rpm":rpm}))
        })
        .collect::<Vec<_>>();
    if out.is_empty() {
        Value::Null
    } else {
        json!(out)
    }
}
#[derive(Default)]
struct InterfaceCache {
    discovered_at: Option<Instant>,
    paths: Vec<(String, PathBuf)>,
}

fn excluded_interface(name: &str) -> bool {
    name == "lo"
        || name == "docker0"
        || name.starts_with("br-")
        || name.starts_with("virbr")
        || name.starts_with("vnet")
        || name.starts_with("zt")
}

fn network(cache: &mut InterfaceCache) -> Value {
    if cache
        .discovered_at
        .map_or(true, |at| at.elapsed() >= Duration::from_secs(60))
    {
        cache.paths = fs::read_dir("/sys/class/net")
            .ok()
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                (!excluded_interface(&name)).then(|| {
                    (name, entry.path().join("operstate"))
                })
            })
            .collect();
        cache.paths.sort_by(|a, b| a.0.cmp(&b.0));
        cache.discovered_at = Some(Instant::now());
    }
    let mut list = Vec::new();
    let counters = read_text("/proc/net/dev").unwrap_or_default();
    let counters = counters
        .lines()
        .skip(2)
        .filter_map(|line| {
            let (name, rest) = line.split_once(':')?;
            let fields = rest.split_whitespace().collect::<Vec<_>>();
            (fields.len() >= 9).then(|| {
                (
                    name.trim().to_owned(),
                    (
                        fields[0].parse::<u64>().unwrap_or(0),
                        fields[8].parse::<u64>().unwrap_or(0),
                    ),
                )
            })
        })
        .collect::<BTreeMap<_, _>>();
    for (name, operstate) in &cache.paths {
        if let Some((rx, tx)) = counters.get(name) {
            let state = fs::read_to_string(operstate).ok().map(|value| value.trim().to_owned());
            list.push(json!({"name":name,"rxBytes":rx,"txBytes":tx,"operstate":state}));
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
struct GpuSysfsDevice {
    metrics: Vec<(String, PathBuf)>,
    temperatures: Vec<PathBuf>,
    fans: Vec<(PathBuf, PathBuf)>,
}

#[derive(Default)]
struct GpuSysfsCache {
    discovered_at: Option<Instant>,
    devices: Vec<GpuSysfsDevice>,
    nvidia_present: bool,
}

impl GpuSysfsCache {
    fn refresh_discovery_if_due(&mut self) {
        if !self
            .discovered_at
            .map_or(true, |at| at.elapsed() >= Duration::from_secs(60))
        {
            return;
        }
        let proc_nvidia = fs::read_dir("/proc/driver/nvidia/gpus")
            .ok()
            .and_then(|mut entries| entries.next())
            .is_some();
        let mut devices = Vec::new();
        let mut nvidia_present = proc_nvidia;
        if let Ok(entries) = fs::read_dir("/sys/class/drm") {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.strip_prefix("card").map_or(false, |number| {
                    !number.is_empty() && number.chars().all(|c| c.is_ascii_digit())
                }) {
                    continue;
                }
                let device = entry.path().join("device");
                let Some(vendor) = read_text(&device.join("vendor").to_string_lossy()) else {
                    continue;
                };
                nvidia_present |= vendor.trim().eq_ignore_ascii_case("0x10de");
                let metrics = [
                    ("gpu_busy_percent", "utilizationPercent"),
                    ("mem_info_vram_used", "memoryUsedBytes"),
                    ("mem_info_vram_total", "memoryTotalBytes"),
                ]
                .into_iter()
                .map(|(file, key)| (key.to_owned(), device.join(file)))
                .collect();
                let mut temperatures = Vec::new();
                let mut fans = Vec::new();
                if let Ok(hwmon) = fs::read_dir(device.join("hwmon")) {
                    for hwmon_entry in hwmon.flatten() {
                        if let Ok(files) = fs::read_dir(hwmon_entry.path()) {
                            for file in files.flatten() {
                                let filename = file.file_name().to_string_lossy().to_string();
                                if filename.starts_with("temp") && filename.ends_with("_input") {
                                    temperatures.push(file.path());
                                } else if filename.starts_with("pwm") && filename.ends_with("_max") {
                                    fans.push((
                                        file.path().with_file_name(filename.trim_end_matches("_max")),
                                        file.path(),
                                    ));
                                }
                            }
                        }
                    }
                }
                devices.push(GpuSysfsDevice {
                    metrics,
                    temperatures,
                    fans,
                });
            }
        }
        self.devices = devices;
        self.nvidia_present = nvidia_present;
        self.discovered_at = Some(Instant::now());
    }

    fn sample(&mut self) -> Value {
        self.refresh_discovery_if_due();
        let mut out = serde_json::Map::new();
        let mut temperatures = Vec::new();
        for device in &self.devices {
            for (key, path) in &device.metrics {
                if let Some(value) = fs::read_to_string(path)
                    .ok()
                    .and_then(|value| value.trim().parse::<u64>().ok())
                {
                    out.insert(key.clone(), json!(value));
                }
            }
            for path in &device.temperatures {
                if let Some(value) = fs::read_to_string(path)
                    .ok()
                    .and_then(|value| value.trim().parse::<f64>().ok())
                    .filter(|value| value.is_finite())
                {
                    temperatures.push(value / 1000.0);
                }
            }
            for (pwm, maximum) in &device.fans {
                let max = fs::read_to_string(maximum)
                    .ok()
                    .and_then(|value| value.trim().parse::<f64>().ok())
                    .filter(|value| value.is_finite() && *value > 0.0);
                let value = fs::read_to_string(pwm)
                    .ok()
                    .and_then(|value| value.trim().parse::<f64>().ok())
                    .filter(|value| value.is_finite());
                if let (Some(value), Some(max)) = (value, max) {
                    out.insert("fanPercent".into(), json!(value * 100.0 / max));
                }
            }
        }
        if let Some(value) = temperatures.first() {
            out.insert("temperatureCelsius".into(), json!(*value));
        }
        if out.is_empty() {
            Value::Null
        } else {
            Value::Object(out)
        }
    }
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
fn gpu(cached: Option<&Value>, sysfs: &mut GpuSysfsCache) -> Value {
    let mut out = match cached {
        Some(Value::Object(metrics)) => metrics.clone(),
        _ => serde_json::Map::new(),
    };
    if let Value::Object(metrics) = sysfs.sample() {
        for (key, value) in metrics {
            out.insert(key, value);
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
fn mount_owner_from(mountinfo: &str, path: &str) -> Option<(String, String)> {
    let mut best = None;
    for line in mountinfo.lines() {
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
#[derive(Default)]
struct MountCache {
    refreshed_at: Option<Instant>,
    contents: String,
}

impl MountCache {
    fn refresh_if_due(&mut self) -> &str {
        if self
            .refreshed_at
            .map_or(true, |at| at.elapsed() >= Duration::from_secs(60))
        {
            self.contents = read_text("/proc/self/mountinfo").unwrap_or_default();
            self.refreshed_at = Some(Instant::now());
        }
        &self.contents
    }
}

fn disk_usage(mountinfo: &str) -> Value {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for path in ["/", "/home", "/vault", "/mnt/nas"] {
        let Some((total, used, available)) = statvfs_bytes(path) else {
            continue;
        };
        let (fsname, mount) =
            mount_owner_from(mountinfo, path).unwrap_or_else(|| ("unknown".into(), path.into()));
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
const PROC_STAT_BUFFER_SIZE: usize = 4096;

fn processes(
    previous: &BTreeMap<u32, u64>,
    elapsed: Option<Duration>,
    stat_buffer: &mut Vec<u8>,
    statm_buffer: &mut String,
) -> (Value, BTreeMap<u32, u64>) {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) }.max(1) as u64;
    let mut next = BTreeMap::new();
    let mut candidates = Vec::new();
    if let Ok(es) = fs::read_dir("/proc") {
        for e in es.flatten() {
            let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else {
                continue;
            };
            stat_buffer.resize(PROC_STAT_BUFFER_SIZE, 0);
            let Ok(mut stat_file) = File::open(e.path().join("stat")) else {
                continue;
            };
            let Ok(bytes_read) = stat_file.read(stat_buffer.as_mut_slice()) else {
                continue;
            };
            if bytes_read == 0 {
                continue;
            }
            stat_buffer.truncate(bytes_read);
            let stat = String::from_utf8_lossy(&stat_buffer[..]);
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
            let command = stat[open + 1..close].to_string();
            let cpu = match (previous.get(&pid), elapsed) {
                (Some(old), Some(dt)) if dt.as_secs_f64() > 0.0 => {
                    ticks.saturating_sub(*old) as f64 / hz / dt.as_secs_f64() * 100.0
                }
                _ => 0.0,
            };
            let rss_pages = f
                .get(21)
                .and_then(|field| field.parse::<i64>().ok())
                .unwrap_or(0);
            if !["ps", "sh", "bash", "sudo", "python3"].contains(&command.as_str())
                && (cpu > 0.0 || rss_pages > 0)
            {
                candidates.push((pid, command, cpu, ticks, e.path()));
            }
        }
    }
    candidates.sort_by(|a, b| {
        b.2.partial_cmp(&a.2)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| b.3.cmp(&a.3))
            .then_with(|| a.0.cmp(&b.0))
    });
    let rows = candidates
        .into_iter()
        .take(10)
        .map(|(_, command, cpu, _, path)| {
            statm_buffer.clear();
            let rss = File::open(path.join("statm"))
                .and_then(|mut file| file.read_to_string(statm_buffer))
                .ok()
                .and_then(|_| statm_buffer.split_whitespace().nth(1)?.parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(page);
            json!({"command":command,"cpuPercent":cpu,"rssBytes":rss,"processCount":1})
        })
        .collect::<Vec<_>>();
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

fn proc_status_value(status: &str, key: &str) -> Option<u64> {
    status.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name != key {
            return None;
        }
        value.split_whitespace().next()?.parse().ok()
    })
}

fn proc_stat_fields(stat: &str) -> Option<(u64, u64, u64)> {
    let close = stat.rfind(')')?;
    let fields: Vec<_> = stat[close + 2..].split_whitespace().collect();
    if fields.len() <= 19 {
        return None;
    }
    Some((
        fields[11].parse().ok()?,
        fields[12].parse().ok()?,
        fields[19].parse().ok()?,
    ))
}

fn proc_maps_metrics(maps: &str) -> (u64, u64) {
    const LARGE_ANON: u64 = 64 * 1024 * 1024;
    let mut large_anonymous = 0u64;
    let mut arenas = 0u64;
    for line in maps.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        let Some(range) = fields.first() else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        let size = end.saturating_sub(start);
        if fields.get(1) == Some(&"rw-p") && fields.len() == 5 && size >= LARGE_ANON {
            large_anonymous = large_anonymous.saturating_add(1);
        }
        if fields.last() == Some(&"[heap]") {
            arenas = arenas.saturating_add(1);
        }
    }
    (large_anonymous, arenas.min(1024))
}

fn proc_uptime_seconds() -> Option<f64> {
    read_text("/proc/uptime")
        .and_then(|value| value.split_whitespace().next()?.parse::<f64>().ok())
        .filter(|value| value.is_finite() && *value >= 0.0)
}

fn file_bytes(path: &PathBuf) -> u64 {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .unwrap_or(0)
}

fn db_file_bytes() -> (u64, u64) {
    let path = db_path();
    (
        file_bytes(&path),
        file_bytes(&PathBuf::from(format!("{}-wal", path.display()))),
    )
}

#[derive(Default)]
struct SelfMetricsCache {
    refreshed_at: Option<Instant>,
    fd_count: u64,
    anon_mappings_over_64_mib: u64,
    fd_sampled_at: i64,
    maps_sampled_at: i64,
}

impl SelfMetricsCache {
    fn refresh_if_due(&mut self) {
        if self
            .refreshed_at
            .map_or(true, |at| at.elapsed() >= Duration::from_secs(60))
        {
            self.fd_count = fs::read_dir("/proc/self/fd")
                .map(|entries| entries.flatten().count() as u64)
                .unwrap_or(0)
                .min(65_536);
            let maps = read_text("/proc/self/maps").unwrap_or_default();
            self.anon_mappings_over_64_mib = proc_maps_metrics(&maps).0;
            let sampled_at = now();
            self.fd_sampled_at = sampled_at;
            self.maps_sampled_at = sampled_at;
            self.refreshed_at = Some(Instant::now());
        }
    }
}

fn self_sample(
    doors: Value,
    tick_millis: u64,
    persist_millis: u64,
    previous_ticks: Option<u64>,
    elapsed: Option<Duration>,
    cache: &mut SelfMetricsCache,
) -> (Value, Option<u64>, u64, i64, i64) {
    cache.refresh_if_due();
    let status = read_text("/proc/self/status").unwrap_or_default();
    let stat = read_text("/proc/self/stat").and_then(|value| proc_stat_fields(&value));
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let (user_ticks, system_ticks, start_ticks) = stat.unwrap_or((0, 0, 0));
    let total_ticks = user_ticks.saturating_add(system_ticks);
    let cpu_percent = match (previous_ticks, elapsed) {
        (Some(previous), Some(elapsed)) if elapsed.as_secs_f64() > 0.0 => {
            (total_ticks.saturating_sub(previous) as f64 / hz / elapsed.as_secs_f64() * 100.0)
                .clamp(0.0, 100_000.0)
        }
        _ => 0.0,
    };
    let uptime_seconds = proc_uptime_seconds()
        .map(|uptime| (uptime - start_ticks as f64 / hz).max(0.0))
        .unwrap_or(0.0);
    let rss = proc_status_value(&status, "VmRSS")
        .unwrap_or(0)
        .saturating_mul(1024);
    let hwm = proc_status_value(&status, "VmHWM")
        .unwrap_or(0)
        .saturating_mul(1024);
    let swap = proc_status_value(&status, "VmSwap")
        .unwrap_or(0)
        .saturating_mul(1024);
    let data = proc_status_value(&status, "VmData")
        .unwrap_or(0)
        .saturating_mul(1024);
    let threads = proc_status_value(&status, "Threads")
        .unwrap_or(0)
        .min(65_536);
    let (db_bytes, wal_bytes) = db_file_bytes();
    (
        json!({
            "pid": std::process::id(),
            "uptimeSeconds": uptime_seconds,
            "rssBytes": rss,
            "hwmBytes": hwm,
            "swapBytes": swap,
            "dataBytes": data,
            "threads": threads,
            "fdCount": cache.fd_count,
            "cpuPercent": cpu_percent,
            "tickMillis": tick_millis,
            "persistMillis": persist_millis,
            "dbBytes": db_bytes,
            "walBytes": wal_bytes,
            "anonMappingsOver64MiB": cache.anon_mappings_over_64_mib,
            "doors": doors,
        }),
        Some(total_ticks),
        rss,
        cache.maps_sampled_at,
        cache.fd_sampled_at,
    )
}

#[derive(Default)]
struct ProcessCache {
    sampled_at: Option<Instant>,
    sampled_ts: i64,
    value: Value,
    ticks: BTreeMap<u32, u64>,
    stat_buffer: Vec<u8>,
    statm_buffer: String,
}

impl ProcessCache {
    fn refresh_if_due(&mut self) {
        let instant = Instant::now();
        if self
            .sampled_at
            .map_or(true, |at| at.elapsed() >= Duration::from_secs(5))
        {
            let elapsed = self.sampled_at.map(|at| instant.saturating_duration_since(at));
            let (value, ticks) = processes(
                &self.ticks,
                elapsed,
                &mut self.stat_buffer,
                &mut self.statm_buffer,
            );
            self.value = value;
            self.ticks = ticks;
            self.sampled_at = Some(Instant::now());
            self.sampled_ts = now();
        }
    }
}

#[derive(Default)]
struct TcpCache {
    refreshed_at: Option<Instant>,
    sampled_ts: i64,
    value: Value,
}

impl TcpCache {
    fn refresh_if_due(&mut self) {
        if self
            .refreshed_at
            .map_or(true, |at| at.elapsed() >= Duration::from_secs(10))
        {
            self.value = tcp();
            self.sampled_ts = now();
            self.refreshed_at = Some(Instant::now());
        }
    }
}

fn snapshot_with_state(
    previous: Option<&Value>,
    process_cache: &mut ProcessCache,
    tcp_cache: &mut TcpCache,
    thermal_cache: &mut ThermalCache,
    fan_cache: &mut FanCache,
    gpu_sysfs_cache: &mut GpuSysfsCache,
    interface_cache: &mut InterfaceCache,
    mount_cache: &mut MountCache,
    self_cache: &mut SelfMetricsCache,
    gpu_cache: Option<&Value>,
    gpu_cache_ts: Option<i64>,
    doors: Value,
    tick_millis: u64,
    persist_millis: u64,
    previous_self_ticks: Option<u64>,
    elapsed: Option<Duration>,
    previous_cpu: Option<CpuCounters>,
) -> (Value, Option<u64>, u64, Option<CpuCounters>) {
    process_cache.refresh_if_due();
    tcp_cache.refresh_if_due();
    let ts = now();
    let cpu_counters = read_text("/proc/stat").and_then(|stat| parse_cpu_counters(&stat));
    let cpu_usage = cpu_usage_percent(previous_cpu, cpu_counters);
    let net = network(interface_cache);
    let mountinfo = mount_cache.refresh_if_due();
    let usage = disk_usage(mountinfo);
    let io = disk_io(&usage);
    let (self_value, self_ticks, self_rss, maps_ts, fd_ts) = self_sample(
        doors,
        tick_millis,
        persist_millis,
        previous_self_ticks,
        elapsed,
        self_cache,
    );
    let (temperature, temperature_ts, storage_temperature_ts) = temperatures(thermal_cache);
    let mut value = json!({
        "schema":"caduceus.appliance.stats.sample.v1",
        "ts":ts,
        "collectedAt":chrono::DateTime::<chrono::Utc>::from_timestamp(ts,0).map(|d|d.to_rfc3339()),
        "cpu":{"usagePercent":cpu_usage},
        "pressure":{"io":io_pressure()},
        "load":load(),
        "temperature":temperature,
        "temperatureTs":temperature_ts,
        "storageTemperatureTs":storage_temperature_ts,
        "fans":fans(fan_cache),
        "gpu":gpu(gpu_cache, gpu_sysfs_cache),
        "gpuCacheTs":gpu_cache_ts,
        "memory":meminfo(),
        "network":{"interfaces":net,"throughput":Value::Null},
        "tcp":tcp_cache.value,
        "tcpTs":tcp_cache.sampled_ts,
        "disk":{"io":io,"usage":usage,"throughput":Value::Null},
        "processes":process_cache.value,
        "processesTs":process_cache.sampled_ts,
        "selfMapsTs":maps_ts,
        "selfFdTs":fd_ts,
        "self":self_value
    });
    if let Some(prev) = previous {
        let dt = (ts - prev.get("ts").and_then(Value::as_i64).unwrap_or(ts)).max(1) as f64;
        let mut throughput = json!({});
        if let (Some(a), Some(b)) = (
            prev.pointer("/network/interfaces")
                .and_then(Value::as_array),
            value
                .pointer("/network/interfaces")
                .and_then(Value::as_array),
        ) {
            let total = |items: &[Value], key: &str| {
                items
                    .iter()
                    .filter_map(|item| item[key].as_u64())
                    .sum::<u64>()
            };
            throughput = json!({
                "rxBytesPerSecond": total(b, "rxBytes").saturating_sub(total(a, "rxBytes")) as f64 / dt,
                "txBytesPerSecond": total(b, "txBytes").saturating_sub(total(a, "txBytes")) as f64 / dt,
            });
        }
        value["network"]["throughput"] = throughput;
        let total = |items: &Value, key: &str| {
            items
                .as_array()
                .map(|array| {
                    array
                        .iter()
                        .filter_map(|row| row[key].as_u64())
                        .sum::<u64>()
                })
                .unwrap_or(0)
        };
        if let (Some(a), Some(b)) = (prev.pointer("/disk/io"), value.pointer("/disk/io")) {
            value["disk"]["throughput"] = json!({
                "readBytesPerSecond": total(b, "readBytes").saturating_sub(total(a, "readBytes")) as f64 / dt,
                "writeBytesPerSecond": total(b, "writeBytes").saturating_sub(total(a, "writeBytes")) as f64 / dt,
            });
        }
    }
    (value, self_ticks, self_rss, cpu_counters)
}

const AGGREGATE_SQL: &str = "SELECT COUNT(*), AVG(json_extract(data, '$.load.one')), AVG(json_extract(data, '$.load.five')), AVG(json_extract(data, '$.load.fifteen')), AVG(json_extract(data, '$.temperature.celsius')), AVG(json_extract(data, '$.gpu.utilizationPercent')), AVG(json_extract(data, '$.gpu.temperatureCelsius')), AVG(json_extract(data, '$.memory.usedBytes')), AVG(json_extract(data, '$.memory.usedBytesSwap')), AVG(json_extract(data, '$.network.throughput.rxBytesPerSecond')), AVG(json_extract(data, '$.network.throughput.txBytesPerSecond')), AVG(json_extract(data, '$.disk.throughput.readBytesPerSecond')), AVG(json_extract(data, '$.disk.throughput.writeBytesPerSecond')), AVG(json_extract(data, '$.self.rssBytes')), MAX(json_extract(data, '$.self.rssBytes')), AVG(json_extract(data, '$.self.tickMillis')), MAX(json_extract(data, '$.self.tickMillis')), AVG(json_extract(data, '$.cpu.usagePercent')), AVG(json_extract(data, '$.pressure.io.someAvg10')), AVG(json_extract(data, '$.pressure.io.fullAvg10')) FROM raw_samples WHERE ts >= ?1 AND ts < ?2";

fn sql_value(value: Option<f64>) -> Value {
    value.map_or(Value::Null, |value| json!(value))
}

fn aggregate(c: &Connection, bucket: i64) -> Result<String, String> {
    let start = bucket.saturating_mul(60);
    let end = start.saturating_add(60);
    let row = c
        .query_row(AGGREGATE_SQL, params![start, end], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<f64>>(1)?,
                row.get::<_, Option<f64>>(2)?,
                row.get::<_, Option<f64>>(3)?,
                row.get::<_, Option<f64>>(4)?,
                row.get::<_, Option<f64>>(5)?,
                row.get::<_, Option<f64>>(6)?,
                row.get::<_, Option<f64>>(7)?,
                row.get::<_, Option<f64>>(8)?,
                row.get::<_, Option<f64>>(9)?,
                row.get::<_, Option<f64>>(10)?,
                row.get::<_, Option<f64>>(11)?,
                row.get::<_, Option<f64>>(12)?,
                row.get::<_, Option<f64>>(13)?,
                row.get::<_, Option<f64>>(14)?,
                row.get::<_, Option<f64>>(15)?,
                row.get::<_, Option<f64>>(16)?,
                row.get::<_, Option<f64>>(17)?,
                row.get::<_, Option<f64>>(18)?,
                row.get::<_, Option<f64>>(19)?,
            ))
        })
        .map_err(|error| error.to_string())?;

    let (
        samples,
        load_one,
        load_five,
        load_fifteen,
        temperature,
        gpu_utilization,
        gpu_temperature,
        memory,
        swap,
        network_rx,
        network_tx,
        disk_read,
        disk_write,
        self_rss,
        self_rss_max,
        self_tick,
        self_tick_max,
        cpu_usage,
        io_some,
        io_full,
    ) = row;
    let result = json!({
        "schema": "caduceus.appliance.stats.minute.v1",
        "bucket": bucket,
        "samples": samples,
        "aggregation": {
            "loadOne": sql_value(load_one),
            "loadFive": sql_value(load_five),
            "loadFifteen": sql_value(load_fifteen),
            "temperatureCelsius": sql_value(temperature),
            "gpuUtilizationPercent": sql_value(gpu_utilization),
            "gpuTemperatureCelsius": sql_value(gpu_temperature),
            "memoryUsedBytes": sql_value(memory),
            "swapUsedBytes": sql_value(swap),
            "networkRxBytesPerSecond": sql_value(network_rx),
            "networkTxBytesPerSecond": sql_value(network_tx),
            "diskReadBytesPerSecond": sql_value(disk_read),
            "diskWriteBytesPerSecond": sql_value(disk_write),
            "selfRssBytes": sql_value(self_rss),
            "selfRssBytesMax": sql_value(self_rss_max),
            "selfTickMillis": sql_value(self_tick),
            "selfTickMillisMax": sql_value(self_tick_max),
            "cpuUsagePercent": sql_value(cpu_usage),
            "ioPressureSomeAvg10": sql_value(io_some),
            "ioPressureFullAvg10": sql_value(io_full),
        },
    })
    .to_string();
    Ok(result)
}

fn prune_retention(c: &Connection, timestamp: i64) -> Result<(), String> {
    let mut raw = c
        .prepare_cached("DELETE FROM raw_samples WHERE ts < ?1")
        .map_err(|error| error.to_string())?;
    raw.execute(params![timestamp.saturating_sub(RAW_RETENTION_SECONDS)])
        .map_err(|error| error.to_string())?;
    drop(raw);

    let before = timestamp
        .saturating_div(60)
        .saturating_sub(MINUTE_RETENTION_SECONDS / 60);
    let mut minute = c
        .prepare_cached("DELETE FROM minute_samples WHERE bucket < ?1")
        .map_err(|error| error.to_string())?;
    minute
        .execute(params![before])
        .map_err(|error| error.to_string())?;
    drop(minute);

    let mut self_benchmark = c
        .prepare_cached("DELETE FROM self_benchmark WHERE bucket < ?1")
        .map_err(|error| error.to_string())?;
    self_benchmark
        .execute(params![before])
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn persist_minute(c: &Connection, bucket: i64, data: &str, benchmark: &str) -> Result<(), String> {
    c.execute(
        "INSERT INTO minute_samples(bucket,data) VALUES(?1,?2)",
        params![bucket, data],
    )
        .map_err(|error| error.to_string())?;
    c.execute(
        "INSERT INTO self_benchmark(bucket,data) VALUES(?1,?2)",
        params![bucket, benchmark],
    )
        .map_err(|error| error.to_string())?;
    Ok(())
}

fn histogram_index(duration: Duration) -> usize {
    match duration.as_millis() {
        0..=1 => 0,
        2..=4 => 1,
        5..=9 => 2,
        10..=24 => 3,
        25..=49 => 4,
        50..=99 => 5,
        100..=249 => 6,
        _ => 7,
    }
}

fn percentile(histogram: &[u64; 8]) -> u64 {
    let total: u64 = histogram.iter().copied().sum();
    if total == 0 {
        return 0;
    }
    let target = (total.saturating_mul(95).saturating_add(99)) / 100;
    let mut seen = 0u64;
    for (index, count) in histogram.iter().copied().enumerate() {
        seen = seen.saturating_add(count);
        if seen >= target {
            return match index {
                0 => 1,
                1 => 4,
                2 => 9,
                3 => 24,
                4 => 49,
                5 => 99,
                6 => 249,
                _ => u64::MAX,
            };
        }
    }
    u64::MAX
}

fn scalar_percentiles(histogram: &[u64; 8]) -> Value {
    let p50 = {
        let total: u64 = histogram.iter().copied().sum();
        if total == 0 {
            0
        } else {
            let target = (total.saturating_add(1)) / 2;
            let mut seen: u64 = 0;
            let mut value = 0;
            for (index, count) in histogram.iter().copied().enumerate() {
                seen = seen.saturating_add(count);
                if seen >= target {
                    value = match index {
                        0 => 1,
                        1 => 4,
                        2 => 9,
                        3 => 24,
                        4 => 49,
                        5 => 99,
                        6 => 249,
                        _ => u64::MAX,
                    };
                    break;
                }
            }
            value
        }
    };
    let p95 = percentile(histogram);
    let max = histogram
        .iter()
        .rposition(|count| *count != 0)
        .map(|index| match index {
            0 => 1,
            1 => 4,
            2 => 9,
            3 => 24,
            4 => 49,
            5 => 99,
            6 => 249,
            _ => u64::MAX,
        })
        .unwrap_or(0);
    json!({"p50Millis":p50,"p95Millis":p95,"maxMillis":max})
}

fn route_percentiles(histogram: &[u64; 32]) -> (u64, u64, u64) {
    let total: u64 = histogram.iter().copied().sum();
    if total == 0 {
        return (0, 0, 0);
    }
    let quantile = |fraction: u64| {
        let target = (total.saturating_mul(fraction).saturating_add(99)) / 100;
        let mut seen = 0u64;
        for (index, count) in histogram.iter().copied().enumerate() {
            seen = seen.saturating_add(count);
            if seen >= target {
                return if index == 0 {
                    1
                } else {
                    (1u64 << (index + 1)).saturating_sub(1)
                };
            }
        }
        u64::MAX
    };
    let max = histogram
        .iter()
        .rposition(|count| *count != 0)
        .map(|index| {
            if index == 0 {
                1
            } else {
                (1u64 << (index + 1)).saturating_sub(1)
            }
        })
        .unwrap_or(0);
    (quantile(50), quantile(95), max)
}

fn route_benchmark(doors: &crate::routes::leaf_appliance_stats::DoorSnapshot) -> Value {
    let mut result = serde_json::Map::new();
    for (index, label) in crate::routes::leaf_appliance_stats::ROUTE_LABELS
        .iter()
        .enumerate()
    {
        let (p50, p95, max) = route_percentiles(&doors.latency_log2[index]);
        result.insert(
            (*label).to_owned(),
            json!({
                "requests": doors.requests[index],
                "errors": doors.errors[index],
                "p50Millis": p50,
                "p95Millis": p95,
                "maxMillis": max,
            }),
        );
    }
    Value::Object(result)
}

fn benchmark(
    bucket: i64,
    tick_histogram: &[u64; 8],
    persist_histogram: &[u64; 8],
    rss_start: u64,
    rss_end: u64,
    rss_max: u64,
    skipped_ticks: u64,
    anon_mappings_over_64_mib: u64,
    doors: &crate::routes::leaf_appliance_stats::DoorSnapshot,
    c: &Connection,
) -> Result<String, String> {
    let (db_bytes, wal_bytes) = db_file_bytes();
    let raw_rows = c
        .query_row("SELECT COUNT(*) FROM raw_samples", [], |row| {
            row.get::<_, u64>(0)
        })
        .map_err(|error| error.to_string())?;
    let minute_rows = c
        .query_row("SELECT COUNT(*) FROM minute_samples", [], |row| {
            row.get::<_, u64>(0)
        })
        .map_err(|error| error.to_string())?;
    let value = json!({
        "schema": "caduceus.self.benchmark.v1",
        "bucket": bucket,
        "tick": scalar_percentiles(tick_histogram),
        "skippedTicks": skipped_ticks,
        "persist": scalar_percentiles(persist_histogram),
        "rss": {
            "startBytes": rss_start,
            "endBytes": rss_end,
            "deltaBytes": rss_end.saturating_sub(rss_start),
            "maxBytes": rss_max,
        },
        "db": {
            "bytes": db_bytes,
            "walBytes": wal_bytes,
            "rawRows": raw_rows,
            "minuteRows": minute_rows,
        },
        "arena": {
            "anonMappingsOver64MiB": anon_mappings_over_64_mib,
        },
        "doors": route_benchmark(doors),
        "mallocTrim": true,
    });
    Ok(value.to_string())
}

fn collector_error(state: &Arc<RwLock<StatsState>>, error: String) {
    state
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .error = Some(format!("{UNAVAILABLE}: {error}"));
}

fn clear_collector_error(state: &Arc<RwLock<StatsState>>) {
    state
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .error = None;
}

struct FlushResult {
    committed: bool,
    error: Option<String>,
}

fn flush_rollover(
    database: &'static Mutex<Connection>,
    pending: &'static Mutex<VecDeque<PendingRaw>>,
    first_bucket: i64,
    through_bucket: i64,
    tick_histogram: &[u64; 8],
    persist_histogram: &[u64; 8],
    rss_start: u64,
    rss_end: u64,
    rss_max: u64,
    skipped_ticks: u64,
    anon_mappings_over_64_mib: u64,
    doors: &crate::routes::leaf_appliance_stats::DoorSnapshot,
) -> FlushResult {
    let mut pending = pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut connection = match database.lock() {
        Ok(connection) => connection,
        Err(_) => {
            return FlushResult {
                committed: false,
                error: Some("stats database lock poisoned".to_owned()),
            }
        }
    };
    let transaction = match connection
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
    {
        Ok(transaction) => transaction,
        Err(error) => {
            return FlushResult {
                committed: false,
                error: Some(error.to_string()),
            }
        }
    };
    let first_bucket = first_bucket.max(
        through_bucket.saturating_sub(MINUTE_RETENTION_SECONDS / 60),
    );
    let write_result = (|| -> Result<(), String> {
        for sample in pending.iter() {
            transaction
                .execute(
                    "INSERT INTO raw_samples(ts,data) VALUES(?1,?2)",
                    params![sample.ts, sample.data.as_ref()],
                )
                .map_err(|error| error.to_string())?;
        }
        let empty_histogram = [0u64; 8];
        let empty_doors = crate::routes::leaf_appliance_stats::DoorSnapshot::default();
        for bucket in first_bucket..through_bucket {
            let minute = aggregate(&transaction, bucket)?;
            let (ticks, persists, start, end, max, skipped, bucket_doors) = if bucket == first_bucket {
                (
                    tick_histogram,
                    persist_histogram,
                    rss_start,
                    rss_end,
                    rss_max,
                    skipped_ticks,
                    doors,
                )
            } else {
                (
                    &empty_histogram,
                    &empty_histogram,
                    0,
                    0,
                    0,
                    0,
                    &empty_doors,
                )
            };
            let benchmark = benchmark(
                bucket,
                ticks,
                persists,
                start,
                end,
                max,
                skipped,
                anon_mappings_over_64_mib,
                bucket_doors,
                &transaction,
            )?;
            persist_minute(&transaction, bucket, &minute, &benchmark)?;
        }
        prune_retention(&transaction, now())?;
        Ok(())
    })();
    if let Err(error) = write_result {
        drop(transaction);
        return FlushResult {
            committed: false,
            error: Some(error),
        };
    }
    if let Err(error) = transaction.commit() {
        return FlushResult {
            committed: false,
            error: Some(error.to_string()),
        };
    }
    pending.clear();
    let checkpoint_error = connection
        .execute_batch("PRAGMA wal_checkpoint(PASSIVE);")
        .err()
        .map(|error| error.to_string());
    #[cfg(target_os = "linux")]
    unsafe {
        libc::malloc_trim(0);
    }
    FlushResult {
        committed: true,
        error: checkpoint_error,
    }
}

fn collect_loop(
    state: Arc<RwLock<StatsState>>,
    database: &'static Mutex<Connection>,
    pending: &'static Mutex<VecDeque<PendingRaw>>,
    stopping: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut next = Instant::now() + Duration::from_secs(1);
    let mut previous: Option<Value> = None;
    let mut previous_self_ticks: Option<u64> = None;
    let mut previous_cpu: Option<CpuCounters> = None;
    let mut previous_persist_millis: Option<u64> = None;
    let mut bucket = now() / 60;
    let mut tick_histogram = [0u64; 8];
    let mut persist_histogram = [0u64; 8];
    let mut bucket_rss_start = 0u64;
    let mut bucket_rss_end = 0u64;
    let mut bucket_rss_max = 0u64;
    let mut minute_doors = crate::routes::leaf_appliance_stats::DoorSnapshot::default();
    let mut process_cache = ProcessCache::default();
    let mut tcp_cache = TcpCache::default();
    let mut thermal_cache = ThermalCache::default();
    let mut fan_cache = FanCache::default();
    let mut gpu_sysfs_cache = GpuSysfsCache::default();
    let mut interface_cache = InterfaceCache::default();
    let mut mount_cache = MountCache::default();
    let mut self_cache = SelfMetricsCache::default();
    let mut gpu_cache = None;
    let mut gpu_cache_ts = None;
    let mut last_gpu_refresh: Option<Instant> = None;
    let mut skipped_ticks = 0u64;
    let mut collector_healthy = true;
    loop {
        if stopping.load(Ordering::Acquire) {
            let flush = flush_rollover(
                database,
                pending,
                bucket,
                bucket,
                &tick_histogram,
                &persist_histogram,
                bucket_rss_start,
                bucket_rss_end,
                bucket_rss_max,
                skipped_ticks,
                self_cache.anon_mappings_over_64_mib,
                &minute_doors,
            );
            if let Some(error) = flush.error {
                collector_error(&state, error.clone());
                return Err(error);
            }
            if !flush.committed {
                return Err("stats shutdown flush did not commit".to_owned());
            }
            clear_collector_error(&state);
            return Ok(());
        }
        let behind = Instant::now().saturating_duration_since(next);
        if behind > Duration::from_secs(1) {
            // Stalled (suspend, slow tick, scheduler): resnap instead of bursting catch-up samples.
            skipped_ticks = skipped_ticks.saturating_add(behind.as_secs());
            next = Instant::now();
        }
        let delay = next.saturating_duration_since(Instant::now());
        if !delay.is_zero() {
            thread::park_timeout(delay);
        }
        if stopping.load(Ordering::Acquire) {
            continue;
        }
        next += Duration::from_secs(1);
        let instant = Instant::now();
        let elapsed = process_cache
            .sampled_at
            .map(|at| instant.saturating_duration_since(at));
        let pulse = match state.read() {
            Ok(guard) => {
                guard
                    .model_lane_pulse_requested
                    .swap(false, Ordering::AcqRel)
                    || old_elapsed(guard.last_model_lane_pulse_unix.load(Ordering::Acquire))
            }
            Err(_) => false,
        };
        gpu_sysfs_cache.refresh_discovery_if_due();
        if gpu_sysfs_cache.nvidia_present
            && last_gpu_refresh.map_or(true, |at| at.elapsed() >= Duration::from_secs(60))
        {
            if let Some((ok, output)) = refresh_nvidia_gpu_cache() {
                if ok {
                    let value = nvidia_gpu_output(&output);
                    if !value.is_null() {
                        gpu_cache = Some(value);
                        gpu_cache_ts = Some(now());
                    }
                }
            }
            last_gpu_refresh = Some(instant);
        }
        if pulse {
            let lanes = scan_model_lanes();
            if let Ok(guard) = state.read() {
                guard
                    .last_model_lane_pulse_unix
                    .store(now() as u64, Ordering::Release);
            }
            if let Ok(mut guard) = state.write() {
                guard.model_lanes = lanes;
            }
        }

        let current_bucket = now() / 60;
        if current_bucket > bucket {
            let flush = flush_rollover(
                database,
                pending,
                bucket,
                bucket.saturating_add(1),
                &tick_histogram,
                &persist_histogram,
                bucket_rss_start,
                bucket_rss_end,
                bucket_rss_max,
                skipped_ticks,
                self_cache.anon_mappings_over_64_mib,
                &minute_doors,
            );
            if flush.committed {
                bucket = current_bucket;
                tick_histogram = [0u64; 8];
                persist_histogram = [0u64; 8];
                bucket_rss_start = 0;
                bucket_rss_end = 0;
                bucket_rss_max = 0;
                minute_doors = crate::routes::leaf_appliance_stats::DoorSnapshot::default();
                skipped_ticks = 0;
            }
            match flush.error {
                Some(error) => {
                    collector_healthy = false;
                    collector_error(&state, error);
                }
                None if flush.committed => {
                    collector_healthy = true;
                    clear_collector_error(&state);
                }
                None => {
                    collector_healthy = false;
                    collector_error(&state, "stats rollover did not commit".to_owned());
                }
            }
        }
        let door_snapshot = crate::routes::leaf_appliance_stats::snapshot_and_reset();
        minute_doors.add_assign(&door_snapshot);
        let doors = door_snapshot.as_value();
        let sample_started = Instant::now();
        let (mut value, self_ticks, self_rss, cpu_counters) = snapshot_with_state(
            previous.as_ref(),
            &mut process_cache,
            &mut tcp_cache,
            &mut thermal_cache,
            &mut fan_cache,
            &mut gpu_sysfs_cache,
            &mut interface_cache,
            &mut mount_cache,
            &mut self_cache,
            gpu_cache.as_ref(),
            gpu_cache_ts,
            doors,
            0,
            previous_persist_millis.unwrap_or(0),
            previous_self_ticks,
            elapsed,
            previous_cpu,
        );
        let sample_millis = sample_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        value["self"]["tickMillis"] = json!(sample_millis);
        let tick_bin = histogram_index(Duration::from_millis(sample_millis));
        tick_histogram[tick_bin] = tick_histogram[tick_bin].saturating_add(1);
        previous_self_ticks = self_ticks;
        previous_cpu = cpu_counters;
        if bucket_rss_start == 0 {
            bucket_rss_start = self_rss;
        }
        bucket_rss_end = self_rss;
        bucket_rss_max = bucket_rss_max.max(self_rss);

        let data: Arc<str> = Arc::from(value.to_string());
        let ts = value["ts"].as_i64().unwrap_or_else(now);
        let persist_started = Instant::now();
        {
            let mut tail = pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let sequence = tail
                .back()
                .map_or(0, |sample| sample.sequence.saturating_add(1));
            tail.push_back(PendingRaw {
                ts,
                sequence,
                data: Arc::clone(&data),
            });
        }
        let persist_millis = persist_started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let persist_bin = histogram_index(Duration::from_millis(persist_millis));
        persist_histogram[persist_bin] = persist_histogram[persist_bin].saturating_add(1);
        previous_persist_millis = Some(persist_millis);
        if collector_healthy {
            clear_collector_error(&state);
        }
        {
            let mut guard = state
                .write()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.latest = Some(Arc::clone(&data));
            guard.latest_ts = ts;
            guard.gpu_cache = gpu_cache.clone();
            guard.last_gpu_refresh = last_gpu_refresh;
        }
        previous = Some(value);
    }
}

fn old_elapsed(last: u64) -> bool {
    now().max(0) as u64 >= last.saturating_add(MODEL_LANE_PULSE_INTERVAL)
}

pub fn start() {
    if STATE.get().is_some() {
        return;
    }
    let state = Arc::new(RwLock::new(StatsState {
        latest: None,
        latest_ts: 0,
        model_lanes: Vec::new(),
        last_model_lane_pulse_unix: AtomicU64::new(0),
        model_lane_pulse_requested: AtomicBool::new(false),
        error: None,
        gpu_cache: None,
        last_gpu_refresh: None,
    }));
    let _ = STATE.set(Arc::clone(&state));
    let pending = RAW_PENDING.get_or_init(|| Mutex::new(VecDeque::new()));
    let collector = COLLECTOR.get_or_init(|| Mutex::new(None));
    match open_db() {
        Ok(database) => {
            let stopping = Arc::new(AtomicBool::new(false));
            match thread::Builder::new()
                .name("caduceus-stats".to_owned())
                .spawn({
                    let state = Arc::clone(&state);
                    let stopping = Arc::clone(&stopping);
                    move || collect_loop(state, database, pending, stopping)
                })
            {
                Ok(handle) => {
                    *collector
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner()) =
                        Some((stopping, handle));
                }
                Err(error) => collector_error(&state, error.to_string()),
            }
        }
        Err(error) => collector_error(&state, error),
    }
    #[cfg(leaf_storage_disk_census)]
    disk_census::start();
}

pub fn stop() -> Result<(), String> {
    let Some(collector) = COLLECTOR.get() else {
        return Ok(());
    };
    let handle = {
        let mut collector = collector
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        collector.take().map(|(stopping, handle)| {
            stopping.store(true, Ordering::Release);
            handle.thread().unpark();
            handle
        })
    };
    match handle {
        Some(handle) => handle
            .join()
            .map_err(|_| "stats collector thread panicked".to_owned())?,
        None => Ok(()),
    }
}

fn state() -> Result<Arc<RwLock<StatsState>>, String> {
    STATE
        .get()
        .cloned()
        .ok_or_else(|| format!("{UNAVAILABLE}: not started"))
}

pub fn snapshot() -> Value {
    let mut process_cache = ProcessCache::default();
    let mut tcp_cache = TcpCache::default();
    let mut thermal_cache = ThermalCache::default();
    let mut fan_cache = FanCache::default();
    let mut gpu_sysfs_cache = GpuSysfsCache::default();
    let mut interface_cache = InterfaceCache::default();
    let mut mount_cache = MountCache::default();
    let mut self_cache = SelfMetricsCache::default();
    snapshot_with_state(
        None,
        &mut process_cache,
        &mut tcp_cache,
        &mut thermal_cache,
        &mut fan_cache,
        &mut gpu_sysfs_cache,
        &mut interface_cache,
        &mut mount_cache,
        &mut self_cache,
        None,
        None,
        crate::routes::leaf_appliance_stats::door_stats(false),
        0,
        0,
        None,
        None,
        None,
    )
    .0
}

fn splice_model_lanes(raw: &str, model_lanes: &[Value]) -> String {
    let encoded = serde_json::to_string(model_lanes).unwrap_or_else(|_| "[]".to_owned());
    let Some(end) = raw.rfind('}') else {
        return raw.to_owned();
    };
    let mut output = raw.to_owned();
    output.insert_str(end, &format!(",\"model_lanes\":{encoded}"));
    output
}

pub fn current() -> Result<String, String> {
    let state = state()?;
    let guard = state
        .read()
        .map_err(|_| format!("{UNAVAILABLE}: state lock"))?;
    if let Some(error) = &guard.error {
        return Err(error.clone());
    }
    let latest = guard
        .latest
        .as_deref()
        .ok_or_else(|| format!("{UNAVAILABLE}: no samples yet"))?;
    Ok(splice_model_lanes(latest, &guard.model_lanes))
}

pub fn request_model_lane_pulse() -> Result<Value, String> {
    let state = state()?;
    let guard = state
        .read()
        .map_err(|_| format!("{UNAVAILABLE}: state lock"))?;
    guard
        .model_lane_pulse_requested
        .store(true, Ordering::Release);
    Ok(json!(guard.model_lanes))
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryQuery {
    pub tier: Option<String>,
    pub since: Option<i64>,
    pub until: Option<i64>,
    pub limit: Option<usize>,
}

struct RawHistoryRow {
    ts: i64,
    source: u8,
    order: u64,
    data: String,
}

fn history_raw(
    c: &Connection,
    pending: &[PendingRaw],
    since: i64,
    until: i64,
    limit: usize,
) -> Result<String, String> {
    let mut rows = Vec::with_capacity(limit.min(HISTORY_LIMIT_MAX) + pending.len());
    let mut statement = c
        .prepare("SELECT id,ts,data FROM raw_samples WHERE ts >= ?1 AND ts <= ?2 ORDER BY ts DESC,id DESC")
        .map_err(|error| error.to_string())?;
    let stored = statement
        .query_map(params![since, until], |row| {
            Ok(RawHistoryRow {
                ts: row.get(1)?,
                source: 0,
                order: row.get::<_, i64>(0)?.max(0) as u64,
                data: row.get(2)?,
            })
        })
        .map_err(|error| error.to_string())?;
    for row in stored {
        rows.push(row.map_err(|error| error.to_string())?);
    }
    rows.extend(
        pending
            .iter()
            .filter(|row| row.ts >= since && row.ts <= until)
            .map(|row| RawHistoryRow {
                ts: row.ts,
                source: 1,
                order: row.sequence,
                data: row.data.to_string(),
            }),
    );
    rows.sort_by(|a, b| {
        a.ts.cmp(&b.ts)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.order.cmp(&b.order))
    });
    let mut unique: Vec<RawHistoryRow> = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(previous) = unique.last_mut() {
            if previous.ts == row.ts {
                *previous = row;
                continue;
            }
        }
        unique.push(row);
    }
    let mut rows = unique;
    if rows.len() > limit {
        rows.drain(..rows.len() - limit);
    }
    let capacity = rows.iter().map(|row| row.data.len() + 1).sum::<usize>() + 2;
    let mut output = String::with_capacity(capacity);
    output.push('[');
    for (index, row) in rows.iter().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(&row.data);
    }
    output.push(']');
    Ok(output)
}

fn history_array(
    c: &Connection,
    sql: &str,
    since: i64,
    until: i64,
    limit: usize,
) -> Result<String, String> {
    // The SQL selects newest-first so a limit keeps the most recent rows;
    // the array is emitted oldest-first without parsing any stored JSON.
    let mut statement = c.prepare(sql).map_err(|error| error.to_string())?;
    let rows = statement
        .query_map(params![since, until, limit], |row| row.get::<_, String>(0))
        .map_err(|error| error.to_string())?;
    let mut collected: Vec<String> = Vec::with_capacity(limit.min(HISTORY_LIMIT_MAX));
    for row in rows {
        collected.push(row.map_err(|error| error.to_string())?);
    }
    let bytes = collected.iter().map(|row| row.len() + 1).sum::<usize>();
    let mut output = String::with_capacity(bytes.saturating_add(2));
    output.push('[');
    for (index, row) in collected.iter().rev().enumerate() {
        if index != 0 {
            output.push(',');
        }
        output.push_str(row);
    }
    output.push(']');
    Ok(output)
}

pub fn history_with_query(query: HistoryQuery) -> Result<String, String> {
    let tier = query.tier.as_deref().unwrap_or("both");
    if !matches!(tier, "raw" | "minute" | "both" | "self") {
        return Err(format!("{UNAVAILABLE}: invalid history tier"));
    }
    let raw_limit = query
        .limit
        .unwrap_or(RAW_HISTORY_DEFAULT_LIMIT)
        .clamp(1, HISTORY_LIMIT_MAX);
    let minute_limit = query
        .limit
        .unwrap_or(MINUTE_HISTORY_DEFAULT_LIMIT)
        .clamp(1, HISTORY_LIMIT_MAX);
    let limit_window = match query.limit {
        Some(limit) => json!(limit.clamp(1, HISTORY_LIMIT_MAX)),
        None => json!({"raw": RAW_HISTORY_DEFAULT_LIMIT, "minute": MINUTE_HISTORY_DEFAULT_LIMIT, "self": MINUTE_HISTORY_DEFAULT_LIMIT}),
    };
    let until = query.until.unwrap_or_else(now);
    let default_retention = if tier == "raw" {
        RAW_RETENTION_SECONDS
    } else {
        MINUTE_RETENTION_SECONDS
    };
    let since = query
        .since
        .unwrap_or_else(|| until.saturating_sub(default_retention));
    let raw_since = since.max(until.saturating_sub(RAW_RETENTION_SECONDS));
    let minute_points = MINUTE_RETENTION_SECONDS / 60;
    let pending = RAW_PENDING.get_or_init(|| Mutex::new(VecDeque::new()));
    let pending_snapshot = if matches!(tier, "raw" | "both") {
        let pending_guard = pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending_guard.iter().cloned().collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let database = open_db_read_only()?;
    let raw = if matches!(tier, "raw" | "both") {
        history_raw(&database, &pending_snapshot, raw_since, until, raw_limit)?
    } else {
        "[]".to_owned()
    };
    let minute = if matches!(tier, "minute" | "both") {
        history_array(
            &database,
            "SELECT data FROM minute_samples WHERE bucket >= (?1 / 60) AND bucket <= (?2 / 60) ORDER BY bucket DESC,id DESC LIMIT ?3",
            since,
            until,
            minute_limit,
        )?
    } else {
        "[]".to_owned()
    };
    let self_benchmark = if tier == "self" {
        history_array(
            &database,
            "SELECT data FROM self_benchmark WHERE bucket >= (?1 / 60) AND bucket <= (?2 / 60) ORDER BY bucket DESC,id DESC LIMIT ?3",
            since,
            until,
            minute_limit,
        )?
    } else {
        "[]".to_owned()
    };
    Ok(format!(
        "{{\"schema\":\"caduceus.appliance.stats.history.v1\",\"retention\":{{\"rawSeconds\":{RAW_RETENTION_SECONDS},\"rawMaxPoints\":{RAW_RETENTION_SECONDS},\"minuteSeconds\":{MINUTE_RETENTION_SECONDS},\"minuteMaxPoints\":{minute_points},\"selfSeconds\":{MINUTE_RETENTION_SECONDS},\"selfMaxPoints\":{minute_points}}},\"consolidation\":{{\"raw\":\"sqlite-backed one-second samples\",\"minute\":{{\"averages\":[\"load.one\",\"load.five\",\"load.fifteen\",\"temperature.celsius\",\"gpu.utilizationPercent\",\"gpu.temperatureCelsius\",\"memory.usedBytes\",\"memory.usedBytesSwap\",\"network.throughput\",\"disk.throughput\",\"self.rssBytes\",\"self.tickMillis\",\"cpu.usagePercent\",\"pressure.io.someAvg10\",\"pressure.io.fullAvg10\"]}}}},\"window\":{{\"tier\":{},\"since\":{},\"until\":{},\"limit\":{}}},\"tiers\":{{\"raw\":{},\"minute\":{},\"self\":{}}}}}",
        serde_json::to_string(tier).unwrap_or_else(|_| "\"both\"".to_owned()),
        since,
        until,
        limit_window,
        raw,
        minute,
        self_benchmark,
    ))
}

pub fn history(query: HistoryQuery) -> Result<String, String> {
    history_with_query(query)
}

#[cfg(test)]
mod cpu_pressure_tests {
    use super::*;

    #[test]
    fn cpu_delta_excludes_iowait_and_guest_double_counting() {
        let previous = parse_cpu_counters("cpu 10 2 3 50 5 1 1 1 99 88\n").unwrap();
        let current = parse_cpu_counters("cpu 20 4 5 60 10 2 2 2 109 98\n").unwrap();
        assert_eq!(current.total - previous.total, 32);
        assert_eq!(cpu_usage_percent(None, Some(current)), Value::Null);
        assert_eq!(cpu_usage_percent(Some(previous), Some(current)), json!(100.0 * 17.0 / 32.0));
        assert_eq!(cpu_usage_percent(Some(current), Some(previous)), Value::Null);
    }

    #[test]
    fn io_pressure_requires_both_well_formed_averages() {
        let pressure = parse_io_pressure(
            "some avg10=1.25 avg60=2.00 avg300=3.00 total=4\nfull avg10=0.50 avg60=1.00 avg300=1.50 total=2\n",
        )
        .unwrap();
        assert_eq!(pressure, (1.25, 0.5));
        assert!(parse_io_pressure("some avg10=1 avg60=2\n").is_none());
        assert!(parse_io_pressure("some avg10=NaN\nfull avg10=1\n").is_none());
    }
}
