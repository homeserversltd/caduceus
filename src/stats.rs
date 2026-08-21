//! Native, persistent per-host appliance telemetry.
use crate::shared::config;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::{
    collections::{BTreeSet, VecDeque},
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, OnceLock, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::interval;

const RAW_LIMIT: usize = 3600;
const MINUTE_LIMIT: usize = 10_080;
const UNAVAILABLE: &str = "collector unavailable";
struct StatsState {
    raw: VecDeque<Value>,
    minute: VecDeque<Value>,
    error: Option<String>,
}
static STATE: OnceLock<Arc<RwLock<StatsState>>> = OnceLock::new();

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
fn temperatures() -> Value {
    let mut paths = BTreeSet::new();
    if let Ok(entries) = fs::read_dir("/sys/class/thermal") {
        for e in entries.flatten() {
            if e.file_name().to_string_lossy().starts_with("thermal_zone") {
                paths.insert(e.path().join("temp"));
            }
        }
    }
    if let Ok(entries) = fs::read_dir("/sys/class/hwmon") {
        for e in entries.flatten() {
            if let Ok(ts) = fs::read_dir(e.path()) {
                for t in ts.flatten() {
                    let n = t.file_name().to_string_lossy().to_string();
                    if n.starts_with("temp") && n.ends_with("_input") {
                        paths.insert(t.path());
                    }
                }
            }
        }
    }
    let values: Vec<f64> = paths
        .into_iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .filter_map(|v| v.trim().parse::<f64>().ok())
        .map(|v| v / 1000.0)
        .collect();
    if values.is_empty() {
        Value::Null
    } else {
        json!({"celsius": values.iter().sum::<f64>() / values.len() as f64, "sources": values.len()})
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
fn command(command: &str, args: &[&str]) -> Option<String> {
    let mut c = Command::new(command);
    c.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = c.spawn().ok()?;
    let start = std::time::Instant::now();
    loop {
        if child.try_wait().ok()?.is_some() {
            return String::from_utf8(child.wait_with_output().ok()?.stdout).ok();
        }
        if start.elapsed() > Duration::from_millis(900) {
            let _ = child.kill();
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn disk_usage() -> Value {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    if let Some(s) = command("df", &["-B1", "-P", "/", "/home", "/vault", "/mnt/nas"]) {
        for l in s.lines().skip(1) {
            let p: Vec<_> = l.split_whitespace().collect();
            if p.len() >= 6 && seen.insert(p[5].to_string()) {
                out.push(json!({"filesystem":p[0],"path":p[5],"totalBytes":p[1].parse::<u64>().unwrap_or(0),"usedBytes":p[2].parse::<u64>().unwrap_or(0),"availableBytes":p[3].parse::<u64>().unwrap_or(0),"usePercent":p[4]}));
            }
        }
    }
    json!(out)
}
fn processes() -> Value {
    let mut out = Vec::new();
    let skip = ["ps", "sh", "bash", "sudo", "python3"];
    if let Some(s) = command("ps", &["-eo", "comm,pcpu,rss", "--sort=-pcpu"]) {
        for l in s.lines().skip(1) {
            let p: Vec<_> = l.split_whitespace().collect();
            if p.len() >= 3 {
                let cpu = number(p[1]).unwrap_or(0.0);
                let rss = p[2].parse::<u64>().unwrap_or(0) * 1024;
                if !skip.contains(&p[0]) && (cpu > 0.0 || rss > 0) {
                    out.push(
                        json!({"command":p[0],"cpuPercent":cpu,"rssBytes":rss,"processCount":1}),
                    );
                }
                if out.len() >= 10 {
                    break;
                }
            }
        }
    }
    json!(out)
}
fn snapshot(previous: Option<&Value>) -> Value {
    let ts = now();
    let net = network();
    let usage = disk_usage();
    let io = disk_io(&usage);
    let mut v = json!({"schema":"caduceus.appliance.stats.sample.v1","ts":ts,"collectedAt":chrono::DateTime::<chrono::Utc>::from_timestamp(ts,0).map(|d|d.to_rfc3339()),"load":load(),"temperature":temperatures(),"memory":meminfo(),"network":{"interfaces":net,"throughput":Value::Null},"tcp":tcp(),"disk":{"io":io,"usage":usage,"throughput":Value::Null},"processes":processes()});
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
    v
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
    json!({"schema":"caduceus.appliance.stats.minute.v1","bucket":bucket,"samples":samples.len(),"aggregation":{"loadOne":avg(samples,"/load/one"),"loadFive":avg(samples,"/load/five"),"loadFifteen":avg(samples,"/load/fifteen"),"temperatureCelsius":avg(samples,"/temperature/celsius"),"memoryUsedBytes":avg(samples,"/memory/usedBytes"),"swapUsedBytes":avg(samples,"/memory/usedBytesSwap"),"networkRxBytesPerSecond":avg(samples,"/network/throughput/rxBytesPerSecond"),"networkTxBytesPerSecond":avg(samples,"/network/throughput/txBytesPerSecond"),"diskReadBytesPerSecond":avg(samples,"/disk/throughput/readBytesPerSecond"),"diskWriteBytesPerSecond":avg(samples,"/disk/throughput/writeBytesPerSecond")},"last":samples.last()})
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
        let p = previous.clone();
        let v = match tokio::task::spawn_blocking(move || snapshot(p.as_ref())).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let b = v["ts"].as_i64().unwrap_or(0) / 60;
        if b != bucket && !samples.is_empty() {
            let coarse = aggregate(bucket, &samples);
            let _ = persist_minute(&c, &coarse);
            minute.push_back(coarse);
            while minute.len() > MINUTE_LIMIT {
                minute.pop_front();
            }
            samples.clear();
            bucket = b;
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
        }
        previous = Some(v);
    }
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
                error: None,
            }));
            let _ = STATE.set(state.clone());
            tokio::spawn(collect_loop(state, c, r, m));
        }
        Err(e) => {
            let _ = STATE.set(Arc::new(RwLock::new(StatsState {
                raw: VecDeque::new(),
                minute: VecDeque::new(),
                error: Some(format!("{UNAVAILABLE}: {e}")),
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
pub fn current() -> Result<Value, String> {
    let s = state()?;
    let g = s.read().map_err(|_| format!("{UNAVAILABLE}: state lock"))?;
    if let Some(e) = &g.error {
        return Err(e.clone());
    }
    g.raw
        .back()
        .cloned()
        .ok_or_else(|| format!("{UNAVAILABLE}: no samples yet"))
}
pub fn history() -> Result<Value, String> {
    let s = state()?;
    let g = s.read().map_err(|_| format!("{UNAVAILABLE}: state lock"))?;
    if let Some(e) = &g.error {
        return Err(e.clone());
    }
    Ok(
        json!({"schema":"caduceus.appliance.stats.history.v1","retention":{"rawSeconds":3600,"rawMaxPoints":RAW_LIMIT,"minuteSeconds":604800,"minuteMaxPoints":MINUTE_LIMIT},"consolidation":{"raw":"one-second samples","minute":{"averages":["load.one","load.five","load.fifteen","temperature.celsius","memory.usedBytes","memory.usedBytesSwap","network.throughput","disk.throughput"],"lastValue":["cumulative counters","point-in-time gauges/lists: interfaces,tcp,disk.usage,disk.io,processes"]}},"tiers":{"raw":g.raw,"minute":g.minute}}),
    )
}
