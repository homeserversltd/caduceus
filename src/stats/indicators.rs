//! Native, independently cached blocks for the Coronatio indicator surface.
#[path = "internet.rs"]
pub(crate) mod internet;

use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpStream},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, RwLock,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const POWER_DISCOVERY_TTL: Duration = Duration::from_secs(60);
const TAILSCALE_CADENCE: Duration = Duration::from_secs(5);
const INTERNET_CADENCE: Duration = Duration::from_secs(7);
const SERVICES_CADENCE: Duration = Duration::from_secs(5);
const VPN_CADENCE: Duration = Duration::from_secs(5);
#[cfg(leaf_transmission_status)]
const TRANSMISSION_STATUS_TIMEOUT: Duration = VPN_CADENCE;
const PUBLIC_IP_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const PUBLIC_IP_RETRY: Duration = Duration::from_secs(300);
const CONFIG_MAX_BYTES: u64 = 1024 * 1024;
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_millis(900);
const SYSTEMCTL_OUTPUT_MAX: usize = 256 * 1024;
const LOCAL_HTTP_HEADER_MAX: usize = 16 * 1024;
const LOCAL_HTTP_BODY_MAX: usize = 256 * 1024;
const LOCAL_HTTP_TIMEOUT: Duration = Duration::from_secs(2);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(7);
const DNS_MESSAGE_MAX: usize = 4096;

const POKE_TAILSCALE: u32 = 1 << 0;
const POKE_INTERNET: u32 = 1 << 1;
const POKE_SERVICES: u32 = 1 << 2;
const POKE_POWER: u32 = 1 << 3;
const POKE_VPN: u32 = 1 << 4;

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}

fn signal_value(signal: &Option<String>) -> Value {
    signal.clone().map_or(Value::Null, Value::String)
}

fn named_signal(value: &str) -> Option<String> {
    Some(value.to_owned())
}

#[derive(Clone)]
struct TailnetObservation {
    ts: i64,
    backend_state: Option<String>,
    ips: Vec<String>,
    tailnet: Option<String>,
    login_url: Option<String>,
    first_missing_signal: Option<String>,
}

impl TailnetObservation {
    fn unavailable(signal: &str) -> Self {
        Self {
            ts: now_ts(),
            backend_state: None,
            ips: Vec::new(),
            tailnet: None,
            login_url: None,
            first_missing_signal: named_signal(signal),
        }
    }
}

#[derive(Clone)]
struct InternetObservation {
    ts: i64,
    status: Option<String>,
    source: Option<&'static str>,
    first_missing_signal: Option<String>,
}

impl InternetObservation {
    fn unavailable(signal: &str) -> Self {
        Self {
            ts: now_ts(),
            status: None,
            source: None,
            first_missing_signal: named_signal(signal),
        }
    }
}

#[derive(Clone)]
struct PublicIpObservation {
    ts: i64,
    ip: Option<String>,
    first_missing_signal: Option<String>,
}

impl PublicIpObservation {
    fn unavailable(signal: &str) -> Self {
        Self {
            ts: now_ts(),
            ip: None,
            first_missing_signal: named_signal(signal),
        }
    }
}

#[derive(Clone, Default)]
struct UnitObservation {
    active_state: Option<String>,
    enabled: Option<bool>,
    first_missing_signal: Option<String>,
}

#[derive(Clone)]
struct PortalObservation {
    name: String,
    units: Vec<String>,
    status: String,
    first_missing_signal: Option<String>,
}

#[derive(Clone)]
struct ServicesObservation {
    ts: i64,
    rows: Vec<PortalObservation>,
    units: BTreeMap<String, UnitObservation>,
    transmission_unit: Option<String>,
    first_missing_signal: Option<String>,
}

impl ServicesObservation {
    fn unavailable(signal: &str) -> Self {
        Self {
            ts: now_ts(),
            rows: Vec::new(),
            units: BTreeMap::new(),
            transmission_unit: None,
            first_missing_signal: named_signal(signal),
        }
    }
}

#[derive(Clone)]
struct CacheSet {
    tailscale: TailnetObservation,
    internet: InternetObservation,
    public_ip: PublicIpObservation,
    services: ServicesObservation,
    vpn: VpnObservation,
}

impl CacheSet {
    fn new() -> Self {
        Self {
            tailscale: TailnetObservation::unavailable(
                "caduceus-stats-tailscale-not-sampled",
            ),
            internet: InternetObservation::unavailable(
                "caduceus-stats-internet-not-sampled",
            ),
            public_ip: PublicIpObservation::unavailable(
                "caduceus-stats-public-ip-not-sampled",
            ),
            services: ServicesObservation::unavailable(
                "caduceus-stats-services-not-sampled",
            ),
            vpn: VpnObservation::unavailable("caduceus-stats-vpn-not-sampled"),
        }
    }
}

struct WorkerControl {
    stopping: AtomicBool,
    forced: AtomicBool,
    thread: Mutex<Option<thread::Thread>>,
}

impl WorkerControl {
    fn new() -> Self {
        Self {
            stopping: AtomicBool::new(false),
            forced: AtomicBool::new(true),
            thread: Mutex::new(None),
        }
    }

    fn wake(&self) {
        self.forced.store(true, Ordering::Release);
        if let Some(thread) = self
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
        {
            thread.unpark();
        }
    }
}

struct Worker {
    control: Arc<WorkerControl>,
    handle: Option<JoinHandle<()>>,
}

const WORKER_PANIC_RETRY: Duration = Duration::from_secs(5);

fn spawn_worker<F>(name: &str, mut job: F) -> Result<Worker, String>
where
    F: FnMut() -> Duration + Send + 'static,
{
    let control = Arc::new(WorkerControl::new());
    let worker_control = Arc::clone(&control);
    let handle = thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            *worker_control
                .thread
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(thread::current());
            let mut next = Instant::now();
            loop {
                if worker_control.stopping.load(Ordering::Acquire) {
                    break;
                }
                if worker_control.forced.swap(false, Ordering::AcqRel) || Instant::now() >= next {
                    // A panicking job keeps its thread: retry next cycle; the block ts shows staleness.
                    let delay = std::panic::catch_unwind(std::panic::AssertUnwindSafe(&mut job))
                        .unwrap_or(WORKER_PANIC_RETRY);
                    next = Instant::now() + delay;
                    continue;
                }
                thread::park_timeout(next.saturating_duration_since(Instant::now()));
            }
        })
        .map_err(|error| format!("caduceus-stats-worker-spawn-failed: {error}"))?;
    Ok(Worker {
        control,
        handle: Some(handle),
    })
}

#[derive(Clone)]
struct EnergyCounter {
    name: String,
    energy_path: PathBuf,
    range_path: PathBuf,
}

#[derive(Clone)]
struct PackageMeters {
    package_name: String,
    package: EnergyCounter,
    core_uncore: Option<(EnergyCounter, EnergyCounter)>,
}

#[derive(Clone)]
struct EnergyReading {
    name: String,
    path: String,
    energy_uj: u64,
    range_uj: u64,
}

#[derive(Default)]
struct PowerCache {
    discovered_at: Option<Instant>,
    packages: Vec<PackageMeters>,
    previous: BTreeMap<String, (u64, u64)>,
    previous_at: Option<Instant>,
    topology: Vec<String>,
}

impl PowerCache {
    fn sample(&mut self) -> Value {
        if self
            .discovered_at
            .map_or(true, |at| at.elapsed() >= POWER_DISCOVERY_TTL)
        {
            match discover_packages() {
                Ok(packages) => self.packages = packages,
                Err(_) => {
                    self.packages.clear();
                }
            }
            self.discovered_at = Some(Instant::now());
        }

        if self.packages.is_empty() {
            self.previous.clear();
            self.previous_at = None;
            self.topology.clear();
            return json!({
                "watts": null,
                "sources": [],
                "ts": now_ts(),
                "firstMissingSignal": "caduceus-stats-power-rapl-unavailable"
            });
        }

        let mut readings = Vec::new();
        for package in &self.packages {
            let read_pair = package.core_uncore.as_ref().and_then(|(core, uncore)| {
                let core_reading = read_energy_counter(core).ok()?;
                let uncore_reading = read_energy_counter(uncore).ok()?;
                Some(vec![core_reading, uncore_reading])
            });
            let package_reading = match read_pair {
                Some(pair) => pair,
                None => match read_energy_counter(&package.package) {
                    Ok(reading) => vec![reading],
                    Err(_) => {
                        self.previous.clear();
                        self.previous_at = None;
                        self.topology.clear();
                        return json!({
                            "watts": null,
                            "sources": [],
                            "ts": now_ts(),
                            "firstMissingSignal": "caduceus-stats-power-counter-unavailable"
                        });
                    }
                },
            };
            readings.extend(package_reading.into_iter().map(|mut reading| {
                reading.name = format!("{}.{}", package.package_name, reading.name);
                reading
            }));
        }
        readings.sort_by(|left, right| left.path.cmp(&right.path));
        let topology = readings
            .iter()
            .map(|reading| reading.path.clone())
            .collect::<Vec<_>>();
        let sources = readings
            .iter()
            .map(|reading| json!({"name":reading.name,"path":reading.path}))
            .collect::<Vec<_>>();
        let current = readings
            .iter()
            .map(|reading| {
                (
                    reading.path.clone(),
                    (reading.energy_uj, reading.range_uj),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let ts = now_ts();
        let baseline_signal = if self.topology != topology {
            Some("caduceus-stats-power-topology-changed")
        } else if self.previous.is_empty() || self.previous_at.is_none() {
            Some("caduceus-stats-power-baseline-required")
        } else {
            None
        };
        if let Some(signal) = baseline_signal {
            self.topology = topology;
            self.previous = current;
            self.previous_at = Some(Instant::now());
            return json!({
                "watts": null,
                "sources": sources,
                "ts": ts,
                "firstMissingSignal": signal
            });
        }

        let mut delta_total = 0u128;
        for reading in &readings {
            let Some((previous_energy, previous_range)) = self.previous.get(&reading.path) else {
                self.previous = current;
                self.previous_at = Some(Instant::now());
                self.topology = topology;
                return json!({
                    "watts": null,
                    "sources": sources,
                    "ts": ts,
                    "firstMissingSignal": "caduceus-stats-power-topology-changed"
                });
            };
            if *previous_range != reading.range_uj {
                self.previous = current;
                self.previous_at = Some(Instant::now());
                self.topology = topology;
                return json!({
                    "watts": null,
                    "sources": sources,
                    "ts": ts,
                    "firstMissingSignal": "caduceus-stats-power-counter-range-changed"
                });
            }
            let delta = if reading.energy_uj >= *previous_energy {
                Some(reading.energy_uj - *previous_energy)
            } else if reading.range_uj > 0
                && (*previous_energy as f64 / reading.range_uj as f64) >= 0.8
                && (reading.energy_uj as f64 / reading.range_uj as f64) <= 0.2
            {
                Some(
                    reading
                        .range_uj
                        .saturating_sub(*previous_energy)
                        .saturating_add(reading.energy_uj),
                )
            } else {
                None
            };
            let Some(delta) = delta else {
                self.previous = current;
                self.previous_at = Some(Instant::now());
                return json!({
                    "watts": null,
                    "sources": sources,
                    "ts": ts,
                    "firstMissingSignal": "caduceus-stats-power-counter-reset"
                });
            };
            delta_total = delta_total.saturating_add(u128::from(delta));
        }
        let elapsed = self
            .previous_at
            .map(|at| at.elapsed().as_secs_f64())
            .unwrap_or_default();
        self.previous = current;
        self.previous_at = Some(Instant::now());
        self.topology = topology;
        if elapsed <= 0.0 || !elapsed.is_finite() {
            return json!({
                "watts": null,
                "sources": sources,
                "ts": ts,
                "firstMissingSignal": "caduceus-stats-power-sample-interval-invalid"
            });
        }
        let watts = (delta_total as f64 / 1_000_000.0) / elapsed;
        if !watts.is_finite() {
            return json!({
                "watts": null,
                "sources": sources,
                "ts": ts,
                "firstMissingSignal": "caduceus-stats-power-delta-invalid"
            });
        }
        json!({
            "watts": watts,
            "sources": sources,
            "ts": ts,
            "firstMissingSignal": null
        })
    }
}

fn read_energy_counter(counter: &EnergyCounter) -> Result<EnergyReading, ()> {
    let energy_uj = fs::read_to_string(&counter.energy_path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .ok_or(())?;
    let range_uj = fs::read_to_string(&counter.range_path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .ok_or(())?;
    Ok(EnergyReading {
        name: counter.name.clone(),
        path: counter.energy_path.to_string_lossy().to_string(),
        energy_uj,
        range_uj,
    })
}

fn make_energy_counter(name: String, directory: &Path) -> EnergyCounter {
    EnergyCounter {
        name,
        energy_path: directory.join("energy_uj"),
        range_path: directory.join("max_energy_range_uj"),
    }
}

fn discover_packages() -> Result<Vec<PackageMeters>, ()> {
    let root = PathBuf::from("/sys/class/powercap");
    let entries = fs::read_dir(&root).map_err(|_| ())?;
    let mut packages = Vec::new();
    for entry in entries.flatten() {
        let file_name = entry.file_name().to_string_lossy().to_string();
        let Some(id) = file_name.strip_prefix("intel-rapl:") else {
            continue;
        };
        if id.is_empty() || !id.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let directory = entry.path();
        let package_name = fs::read_to_string(directory.join("name"))
            .ok()
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| format!("package-{id}"));
        let package = make_energy_counter(package_name.clone(), &directory);
        let mut core = None;
        let mut uncore = None;
        if let Ok(children) = fs::read_dir(&root) {
            for child in children.flatten() {
                let child_name = child.file_name().to_string_lossy().to_string();
                let Some(suffix) = child_name.strip_prefix(&format!("{file_name}:")) else {
                    continue;
                };
                if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_digit()) {
                    continue;
                }
                let domain = fs::read_to_string(child.path().join("name"))
                    .ok()
                    .map(|name| name.trim().to_ascii_lowercase());
                match domain.as_deref() {
                    Some("core") if core.is_none() => {
                        core = Some(make_energy_counter("core".to_owned(), &child.path()));
                    }
                    Some("uncore") if uncore.is_none() => {
                        uncore = Some(make_energy_counter("uncore".to_owned(), &child.path()));
                    }
                    _ => {}
                }
            }
        }
        packages.push(PackageMeters {
            package_name,
            package,
            core_uncore: core.zip(uncore),
        });
    }
    packages.sort_by(|left, right| left.package_name.cmp(&right.package_name));
    Ok(packages)
}

#[derive(Clone)]
struct VpnObservation {
    ts: i64,
    vpn_status: Option<String>,
    transmission_status: Option<String>,
    on: Option<bool>,
    protocol: Option<String>,
    forward_port: Value,
    first_missing_signal: Option<String>,
}

impl VpnObservation {
    fn unavailable(signal: &str) -> Self {
        Self {
            ts: now_ts(),
            vpn_status: Some("unavailable".to_owned()),
            transmission_status: Some("unavailable".to_owned()),
            on: None,
            protocol: None,
            forward_port: Value::Null,
            first_missing_signal: named_signal(signal),
        }
    }
}

#[cfg(leaf_transmission_status)]
fn read_vpn() -> VpnObservation {
    if crate::routes::profile_routes::ACTIVE_PROFILE != "homeserver" {
        return VpnObservation::unavailable("caduceus-stats-vpn-profile-not-homeserver");
    }

    match crate::shared::policy::allows_command("transmission status") {
        Ok(true) => {}
        Ok(false) => {
            return VpnObservation::unavailable("caduceus-stats-vpn-command-not-allowed");
        }
        Err(_) => return VpnObservation::unavailable("caduceus-profile-missing"),
    }

    let receipt =
        match crate::routes::transmission_status_onness::read(TRANSMISSION_STATUS_TIMEOUT) {
            Ok(receipt) => receipt,
            Err(signal) => return VpnObservation::unavailable(&signal),
        };

    let conditions = receipt.get("conditions");
    let vpn_running = ["namespace", "tunnel", "forward"].into_iter().all(|name| {
        conditions
            .and_then(|conditions| conditions.get(name))
            .and_then(Value::as_bool)
            == Some(true)
    });
    let daemon_running = conditions
        .and_then(|conditions| conditions.get("daemon"))
        .and_then(Value::as_bool)
        == Some(true);
    let on = receipt.get("on").and_then(Value::as_bool);
    let first_missing_signal = if on == Some(true) {
        None
    } else {
        receipt
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    let forward_port = receipt
        .get("forwardPort")
        .filter(|value| value.as_i64().is_some() || value.as_u64().is_some())
        .cloned()
        .unwrap_or(Value::Null);
    VpnObservation {
        ts: now_ts(),
        vpn_status: Some(if vpn_running { "running" } else { "stopped" }.to_owned()),
        transmission_status: Some(
            if daemon_running { "running" } else { "stopped" }.to_owned(),
        ),
        on,
        protocol: receipt
            .get("protocol")
            .and_then(Value::as_str)
            .map(str::to_owned),
        forward_port,
        first_missing_signal,
    }
}

#[cfg(not(leaf_transmission_status))]
fn read_vpn() -> VpnObservation {
    VpnObservation::unavailable("caduceus-stats-vpn-profile-not-homeserver")
}

pub(crate) struct Collector {
    shared: Arc<RwLock<CacheSet>>,
    workers: Vec<Worker>,
    tailscale_worker: Option<Arc<WorkerControl>>,
    internet_worker: Option<Arc<WorkerControl>>,
    services_worker: Option<Arc<WorkerControl>>,
    vpn_worker: Option<Arc<WorkerControl>>,
    power: PowerCache,
}

impl Collector {
    pub(crate) fn start() -> Self {
        let shared = Arc::new(RwLock::new(CacheSet::new()));
        let mut workers = Vec::new();
        let mut tailscale_worker = None;
        let mut internet_worker = None;
        let mut services_worker = None;
        let mut vpn_worker = None;

        {
            let shared = Arc::clone(&shared);
            let fallback = Arc::clone(&shared);
            match spawn_worker("caduceus-stats-tailscale", move || {
                let observation = read_tailscale();
                shared
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .tailscale = observation;
                TAILSCALE_CADENCE
            }) {
                Ok(worker) => {
                    tailscale_worker = Some(Arc::clone(&worker.control));
                    workers.push(worker);
                }
                Err(_) => {
                    fallback
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .tailscale = TailnetObservation::unavailable(
                        "caduceus-stats-tailscale-worker-unavailable",
                    );
                }
            }
        }
        {
            let shared = Arc::clone(&shared);
            let fallback = Arc::clone(&shared);
            let mut internet = internet::Sampler::new();
            match spawn_worker("caduceus-stats-internet", move || {
                let observation = internet.observe();
                shared
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .internet = observation;
                internet.cadence()
            }) {
                Ok(worker) => {
                    internet_worker = Some(Arc::clone(&worker.control));
                    workers.push(worker);
                }
                Err(_) => {
                    fallback
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .internet = InternetObservation::unavailable(
                        "caduceus-stats-internet-worker-unavailable",
                    );
                }
            }
        }
        {
            let shared = Arc::clone(&shared);
            let fallback = Arc::clone(&shared);
            match spawn_worker("caduceus-stats-services", move || {
                let observation = collect_services();
                shared
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .services = observation;
                SERVICES_CADENCE
            }) {
                Ok(worker) => {
                    services_worker = Some(Arc::clone(&worker.control));
                    workers.push(worker);
                }
                Err(_) => {
                    fallback
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .services = ServicesObservation::unavailable(
                        "caduceus-stats-services-worker-unavailable",
                    );
                }
            }
        }
        {
            let shared = Arc::clone(&shared);
            let fallback = Arc::clone(&shared);
            match spawn_worker("caduceus-stats-vpn", move || {
                let observation = read_vpn();
                shared
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .vpn = observation;
                VPN_CADENCE
            }) {
                Ok(worker) => {
                    vpn_worker = Some(Arc::clone(&worker.control));
                    workers.push(worker);
                }
                Err(_) => {
                    fallback
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .vpn = VpnObservation::unavailable(
                        "caduceus-stats-vpn-worker-unavailable",
                    );
                }
            }
        }
        {
            let shared = Arc::clone(&shared);
            let fallback = Arc::clone(&shared);
            match spawn_worker("caduceus-stats-public-ip", move || {
                let observation = read_public_ip();
                let next = if observation.ip.is_some() {
                    PUBLIC_IP_TTL
                } else {
                    PUBLIC_IP_RETRY
                };
                shared
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .public_ip = observation;
                next
            }) {
                Ok(worker) => workers.push(worker),
                Err(_) => {
                    fallback
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .public_ip = PublicIpObservation::unavailable(
                        "caduceus-stats-public-ip-worker-unavailable",
                    );
                }
            }
        }

        Self {
            shared,
            workers,
            tailscale_worker,
            internet_worker,
            services_worker,
            vpn_worker,
            power: PowerCache::default(),
        }
    }

    pub(crate) fn wake(&mut self, mask: u32) {
        if mask & POKE_TAILSCALE != 0 {
            if let Some(worker) = &self.tailscale_worker {
                worker.wake();
            }
        }
        if mask & POKE_INTERNET != 0 {
            if let Some(worker) = &self.internet_worker {
                worker.wake();
            }
        }
        if mask & POKE_SERVICES != 0 {
            if let Some(worker) = &self.services_worker {
                worker.wake();
            }
        }
        if mask & POKE_VPN != 0 {
            if let Some(worker) = &self.vpn_worker {
                worker.wake();
            }
        }
        if mask & POKE_POWER != 0 {
            self.power.discovered_at = None;
        }
    }

    pub(crate) fn sample(&mut self, interfaces: &Value) -> (Value, Value) {
        let power = self.power.sample();
        let caches = self
            .shared
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let (tailscale_guest, tailscale_admin) = tailscale_blocks(&caches.tailscale, interfaces, &caches.services);
        let internet = internet::project(&caches.internet);
        let internet_guest = json!({
            "status": internet.status,
            "source": internet.source,
            "ts": internet.ts,
            "firstMissingSignal": signal_value(&internet.first_missing_signal)
        });
        let services_guest = services_guest(&caches.services);
        let vpn_guest = json!({
            "vpnStatus": caches.vpn.vpn_status,
            "transmissionStatus": caches.vpn.transmission_status,
            "on": caches.vpn.on,
            "protocol": caches.vpn.protocol,
            "forwardPort": caches.vpn.forward_port,
            "ts": caches.vpn.ts,
            "firstMissingSignal": signal_value(&caches.vpn.first_missing_signal)
        });
        let public_ip_admin = json!({
            "publicIp": caches.public_ip.ip,
            "ts": caches.public_ip.ts,
            "firstMissingSignal": signal_value(&caches.public_ip.first_missing_signal)
        });
        let services_admin = services_admin(&caches.services);
        let vpn_admin = vpn_admin(&caches.services);
        let admin = json!({
            "schema": "caduceus.appliance.stats.admin.v1",
            "ok": true,
            "ts": now_ts(),
            "power": {
                "watts": power["watts"].clone(),
                "sources": power["sources"].clone(),
                "ts": power["ts"].clone(),
                "firstMissingSignal": power["firstMissingSignal"].clone()
            },
            "tailscale": tailscale_admin,
            "internet": public_ip_admin,
            "services": services_admin,
            "vpn": vpn_admin
        });
        (
            json!({
                "power": power,
                "tailscale": tailscale_guest,
                "internet": internet_guest,
                "services": services_guest,
                "vpn": vpn_guest
            }),
            admin,
        )
    }

    pub(crate) fn stop(&mut self) -> Result<(), String> {
        for worker in &self.workers {
            worker.control.stopping.store(true, Ordering::Release);
            if let Some(thread) = worker
                .control
                .thread
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref()
            {
                thread.unpark();
            }
        }
        let mut first_error = None;
        for worker in &mut self.workers {
            if let Some(handle) = worker.handle.take() {
                if handle.join().is_err() && first_error.is_none() {
                    first_error = Some("caduceus-stats-indicator-worker-panicked".to_owned());
                }
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Collector {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

pub(crate) fn poke_mask(block: &str) -> Result<u32, String> {
    match block.trim() {
        "power" => Ok(POKE_POWER),
        "tailscale" => Ok(POKE_TAILSCALE),
        "internet" => Ok(POKE_INTERNET),
        "services" => Ok(POKE_SERVICES),
        "vpn" => Ok(POKE_VPN),
        _ => Err("caduceus-stats-indicator-block-invalid".to_owned()),
    }
}

fn services_guest(observation: &ServicesObservation) -> Value {
    let up = observation
        .rows
        .iter()
        .filter(|row| row.status == "up")
        .count();
    let rows = observation
        .rows
        .iter()
        .map(|row| {
            json!({
                "name": row.name,
                "units": row.units,
                "status": row.status,
                "firstMissingSignal": signal_value(&row.first_missing_signal)
            })
        })
        .collect::<Vec<_>>();
    json!({
        "rows": rows,
        "counts": {"up": up, "total": observation.rows.len()},
        "ts": observation.ts,
        "firstMissingSignal": signal_value(&observation.first_missing_signal)
    })
}

fn services_admin(observation: &ServicesObservation) -> Value {
    let units = observation
        .units
        .iter()
        .map(|(unit, state)| {
            json!({
                "unit": unit,
                "enabled": state.enabled,
                "firstMissingSignal": signal_value(&state.first_missing_signal)
            })
        })
        .collect::<Vec<_>>();
    json!({
        "units": units,
        "ts": observation.ts,
        "firstMissingSignal": signal_value(&observation.first_missing_signal)
    })
}

fn vpn_admin(observation: &ServicesObservation) -> Value {
    let unit = observation.transmission_unit.as_deref();
    let state = unit.and_then(|unit| observation.units.get(unit));
    let (enabled, signal) = match (unit, state) {
        (Some(_), Some(state)) => (state.enabled, state.first_missing_signal.clone()),
        (Some(_), None) => (
            None,
            named_signal("caduceus-stats-services-unit-unobserved"),
        ),
        (None, _) => (
            None,
            named_signal("caduceus-stats-vpn-transmission-unit-not-declared"),
        ),
    };
    json!({
        "transmissionUnit": unit,
        "enabled": enabled,
        "ts": observation.ts,
        "firstMissingSignal": signal_value(&signal)
    })
}

fn tailscale_blocks(
    observation: &TailnetObservation,
    interfaces: &Value,
    services: &ServicesObservation,
) -> (Value, Value) {
    let row = interfaces.as_array().and_then(|rows| {
        rows.iter().find(|row| row.get("name").and_then(Value::as_str) == Some("tailscale0"))
    });
    let interface_up = row.is_some_and(|row| {
        row.get("isUp").and_then(Value::as_bool) == Some(true)
            && row.get("lowerUp").and_then(Value::as_bool) == Some(true)
    });
    let tailscale_ip = primary_tailscale_ipv4(&observation.ips);
    let has_ip = tailscale_ip.is_some();
    let (status, interface, status_signal) = if observation.first_missing_signal.is_some() {
        ("absent", false, observation.first_missing_signal.clone())
    } else {
        match observation.backend_state.as_deref() {
            Some("NeedsLogin") | Some("NeedsAuth") => ("needs-login", false, None),
            Some("Running") if interface_up && has_ip => ("connected", true, None),
            Some("Running") if !interface_up => (
                "disconnected",
                false,
                named_signal("caduceus-stats-tailscale-interface-unavailable"),
            ),
            Some("Running") => (
                "disconnected",
                false,
                named_signal("caduceus-stats-tailscale-ip-unavailable"),
            ),
            Some("Stopped") | Some("NoState") | Some("Starting") => {
                ("disconnected", false, None)
            }
            _ => (
                "absent",
                false,
                named_signal("caduceus-stats-tailscale-backend-state-unobserved"),
            ),
        }
    };
    let guest = json!({
        "status": status,
        "interface": interface,
        "ts": observation.ts,
        "firstMissingSignal": signal_value(&status_signal)
    });
    let admin_signal = observation
        .first_missing_signal
        .clone()
        .or_else(|| status_signal.clone());
    let tailscaled = services.units.get("tailscaled.service");
    let enabled = tailscaled.and_then(|unit| unit.enabled);
    let enabled_signal = tailscaled
        .and_then(|unit| unit.first_missing_signal.clone())
        .or_else(|| {
            tailscaled
                .is_none()
                .then(|| "caduceus-stats-services-unit-unobserved".to_owned())
        });
    let admin = json!({
        "ip": tailscale_ip,
        "tailnet": observation.tailnet,
        "loginUrl": observation.login_url,
        "isEnabled": enabled,
        "enabledFirstMissingSignal": signal_value(&enabled_signal),
        "ts": observation.ts,
        "firstMissingSignal": signal_value(&admin_signal)
    });
    (guest, admin)
}

fn primary_tailscale_ipv4(ips: &[String]) -> Option<&str> {
    ips.iter()
        .find(|ip| {
            ip.parse::<Ipv4Addr>()
                .map(is_tailscale_ipv4)
                .unwrap_or(false)
        })
        .map(String::as_str)
}

fn is_tailscale_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    octets[0] == 100 && (64..=127).contains(&octets[1])
}

fn read_tailscale() -> TailnetObservation {
    let socket = Path::new("/var/run/tailscale/tailscaled.sock");
    match tailscale_localapi(socket) {
        Ok(body) => parse_tailscale(&body).unwrap_or_else(|| {
            TailnetObservation::unavailable("caduceus-stats-tailscale-localapi-response-invalid")
        }),
        Err(signal) => TailnetObservation::unavailable(signal),
    }
}

fn tailscale_localapi(path: &Path) -> Result<Value, &'static str> {
    let deadline = Instant::now() + LOCAL_HTTP_TIMEOUT;
    let mut stream = connect_unix_stream(path, deadline)
        .map_err(|_| "caduceus-stats-tailscale-localapi-unavailable")?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("caduceus-stats-tailscale-localapi-unavailable");
    }
    stream
        .set_write_timeout(Some(remaining))
        .map_err(|_| "caduceus-stats-tailscale-localapi-unavailable")?;
    stream
        .write_all(b"GET /localapi/v0/status?peers=false HTTP/1.1\r\nHost: local-tailscaled.sock\r\nConnection: close\r\n\r\n")
        .map_err(|_| "caduceus-stats-tailscale-localapi-unavailable")?;
    let (status, body) = read_http_response(&mut stream, deadline)
        .map_err(|_| "caduceus-stats-tailscale-localapi-response-invalid")?;
    if status != 200 {
        return Err("caduceus-stats-tailscale-localapi-http-failed");
    }
    serde_json::from_slice(&body).map_err(|_| "caduceus-stats-tailscale-localapi-response-invalid")
}

fn connect_unix_stream(path: &Path, deadline: Instant) -> io::Result<UnixStream> {
    let pathname = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if pathname.is_empty()
        || pathname.len() >= address.sun_path.len()
        || pathname.contains(&0)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix socket pathname is invalid or too long",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(pathname) {
        *destination = *source as libc::c_char;
    }

    let raw_fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    let address_len = (std::mem::size_of::<libc::sa_family_t>() + pathname.len() + 1)
        as libc::socklen_t;
    let result = unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
            address_len,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINPROGRESS) {
            wait_for_unix_connect(socket.as_raw_fd(), deadline)?;
        } else {
            // AF_UNIX EAGAIN means the listen backlog is full; do not wait or retry.
            return Err(error);
        }
    }

    let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if flags & libc::O_NONBLOCK != 0
        && unsafe {
            libc::fcntl(
                socket.as_raw_fd(),
                libc::F_SETFL,
                flags & !libc::O_NONBLOCK,
            )
        } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(UnixStream::from(socket))
}

fn wait_for_unix_connect(fd: RawFd, deadline: Instant) -> io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Unix socket connect deadline elapsed",
            ));
        }
        let fractional_millisecond = remaining.subsec_nanos() % 1_000_000 != 0;
        let timeout_ms = remaining
            .as_millis()
            .saturating_add(if fractional_millisecond { 1 } else { 0 })
            .max(1)
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLOUT,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Unix socket connect deadline elapsed",
            ));
        }

        let mut socket_error: libc::c_int = 0;
        let mut option_length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                (&mut socket_error as *mut libc::c_int).cast(),
                &mut option_length,
            )
        };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        if socket_error != 0 {
            return Err(io::Error::from_raw_os_error(socket_error));
        }
        return Ok(());
    }
}

fn set_read_deadline(stream: &UnixStream, deadline: Instant) -> io::Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::new(io::ErrorKind::TimedOut, "deadline elapsed"));
    }
    stream.set_read_timeout(Some(remaining))
}

fn read_line_limited(
    stream: &mut UnixStream,
    deadline: Instant,
    max: usize,
) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        set_read_deadline(stream, deadline)?;
        let mut byte = [0u8; 1];
        stream.read_exact(&mut byte)?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
        if line.len() > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
    }
}

fn read_exact_deadline(
    stream: &mut UnixStream,
    deadline: Instant,
    mut bytes: &mut [u8],
) -> io::Result<()> {
    while !bytes.is_empty() {
        set_read_deadline(stream, deadline)?;
        let count = stream.read(bytes)?;
        if count == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "short body"));
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}

fn read_chunked_body(
    stream: &mut UnixStream,
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line = read_line_limited(stream, deadline, 128)?;
        let text = std::str::from_utf8(&line[..line.len().saturating_sub(2)])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size encoding"))?;
        let size_text = text.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "chunk size invalid"))?;
        if size == 0 {
            let mut trailer_bytes = 0usize;
            loop {
                let trailer = read_line_limited(stream, deadline, LOCAL_HTTP_HEADER_MAX)?;
                trailer_bytes = trailer_bytes.saturating_add(trailer.len());
                if trailer_bytes > LOCAL_HTTP_HEADER_MAX {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "trailers too large"));
                }
                if trailer == b"\r\n" {
                    return Ok(body);
                }
            }
        }
        if body.len().saturating_add(size) > LOCAL_HTTP_BODY_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
        let start = body.len();
        body.resize(start + size, 0);
        read_exact_deadline(stream, deadline, &mut body[start..])?;
        let mut end = [0u8; 2];
        read_exact_deadline(stream, deadline, &mut end)?;
        if end != *b"\r\n" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk ending invalid"));
        }
    }
}

fn read_http_response(
    stream: &mut UnixStream,
    deadline: Instant,
) -> io::Result<(u16, Vec<u8>)> {
    let status_line = read_line_limited(stream, deadline, 4096)?;
    let status_text = std::str::from_utf8(&status_line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "status encoding"))?;
    let mut status_parts = status_text.split_whitespace();
    let version = status_parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP version invalid"));
    }
    let status = status_parts
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "HTTP status invalid"))?;
    let mut headers = BTreeMap::new();
    let mut header_bytes = status_line.len();
    loop {
        let line = read_line_limited(stream, deadline, LOCAL_HTTP_HEADER_MAX)?;
        header_bytes = header_bytes.saturating_add(line.len());
        if header_bytes > LOCAL_HTTP_HEADER_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "headers too large"));
        }
        if line == b"\r\n" {
            break;
        }
        let text = std::str::from_utf8(&line[..line.len().saturating_sub(2)])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "header encoding"))?;
        let (name, value) = text
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "header malformed"))?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_ascii_lowercase());
    }
    let chunked = headers
        .get("transfer-encoding")
        .is_some_and(|value| value.split(',').any(|item| item.trim() == "chunked"));
    let content_length = headers
        .get("content-length")
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "content length invalid"))
        })
        .transpose()?;
    if chunked && content_length.is_some() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "ambiguous framing"));
    }
    let body = if chunked {
        read_chunked_body(stream, deadline)?
    } else if let Some(length) = content_length {
        if length > LOCAL_HTTP_BODY_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
        }
        let mut body = vec![0u8; length];
        read_exact_deadline(stream, deadline, &mut body)?;
        body
    } else {
        let mut body = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            set_read_deadline(stream, deadline)?;
            match stream.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    if body.len().saturating_add(count) > LOCAL_HTTP_BODY_MAX {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "body too large"));
                    }
                    body.extend_from_slice(&buffer[..count]);
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        body
    };
    Ok((status, body))
}

fn parse_tailscale(value: &Value) -> Option<TailnetObservation> {
    let backend = value.get("BackendState")?.as_str()?.to_owned();
    let self_value = value.get("Self");
    let ips = self_value
        .and_then(|value| value.get("TailscaleIPs"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let tailnet = value
        .pointer("/CurrentTailnet/Name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .or_else(|| {
            value
                .get("MagicDNSSuffix")
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
        })
        .map(str::to_owned);
    let login_url = value
        .get("AuthURL")
        .and_then(Value::as_str)
        .filter(|url| !url.trim().is_empty())
        .map(str::to_owned);
    Some(TailnetObservation {
        ts: now_ts(),
        backend_state: Some(backend),
        ips,
        tailnet,
        login_url,
        first_missing_signal: None,
    })
}

fn probe_internet() -> InternetObservation {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
    let hosts = [
        Ipv4Addr::new(1, 1, 1, 1),
        Ipv4Addr::new(8, 8, 8, 8),
        Ipv4Addr::new(208, 67, 222, 222),
    ];
    for host in hosts {
        if TcpStream::connect_timeout(&SocketAddr::from((host, 53)), CONNECT_TIMEOUT).is_ok() {
            return InternetObservation {
                ts: now_ts(),
                status: Some("connected".to_owned()),
                source: Some("public-probe"),
                first_missing_signal: None,
            };
        }
    }
    InternetObservation {
        ts: now_ts(),
        status: Some("disconnected".to_owned()),
        source: Some("public-probe"),
        first_missing_signal: named_signal("caduceus-stats-internet-tcp53-unreachable"),
    }
}

fn read_public_ip() -> PublicIpObservation {
    let response = dns_query(
        Ipv4Addr::new(208, 67, 222, 222),
        "myip.opendns.com",
        Instant::now() + DNS_QUERY_TIMEOUT,
    );
    match response {
        Ok(response) if response.rcode == 0 => response
            .ipv4_answer
            .filter(|ip| is_public_ipv4(*ip))
            .map(|ip| PublicIpObservation {
                ts: now_ts(),
                ip: Some(ip.to_string()),
                first_missing_signal: None,
            })
            .unwrap_or_else(|| {
                PublicIpObservation::unavailable(
                    "caduceus-stats-public-ip-answer-unavailable",
                )
            }),
        _ => PublicIpObservation::unavailable("caduceus-stats-public-ip-lookup-unavailable"),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

struct DnsResponse {
    rcode: u8,
    ipv4_answer: Option<Ipv4Addr>,
}

static DNS_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn dns_query(
    resolver: Ipv4Addr,
    name: &str,
    deadline: Instant,
) -> Result<DnsResponse, ()> {
    let id = (DNS_ID.fetch_add(1, Ordering::Relaxed) as u16)
        ^ (now_ts() as u16)
        ^ (std::process::id() as u16);
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err(());
        }
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    let address = SocketAddr::from((resolver, 53));
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(());
    }
    let mut stream = TcpStream::connect_timeout(&address, timeout).map_err(|_| ())?;
    if stream.peer_addr().ok() != Some(address) {
        return Err(());
    }
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(());
    }
    stream.set_write_timeout(Some(timeout)).map_err(|_| ())?;
    stream.set_read_timeout(Some(timeout)).map_err(|_| ())?;
    let length = u16::try_from(message.len()).map_err(|_| ())?;
    stream.write_all(&length.to_be_bytes()).map_err(|_| ())?;
    stream.write_all(&message).map_err(|_| ())?;
    let mut length_bytes = [0u8; 2];
    stream.read_exact(&mut length_bytes).map_err(|_| ())?;
    let length = usize::from(u16::from_be_bytes(length_bytes));
    if !(12..=DNS_MESSAGE_MAX).contains(&length) {
        return Err(());
    }
    let mut response = vec![0u8; length];
    stream.read_exact(&mut response).map_err(|_| ())?;
    parse_dns_response(&response, id, name)
}

fn read_dns_name(message: &[u8], offset: usize) -> Result<(String, usize), ()> {
    let mut labels = Vec::new();
    let mut position = offset;
    let mut consumed = None;
    let mut visited = BTreeSet::new();
    let mut jumps = 0usize;
    loop {
        let length = *message.get(position).ok_or(())?;
        if length & 0xc0 == 0xc0 {
            let second = *message.get(position + 1).ok_or(())?;
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
            if pointer >= message.len() || !visited.insert(pointer) || jumps >= 16 {
                return Err(());
            }
            consumed.get_or_insert(position + 2);
            position = pointer;
            jumps += 1;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(());
        }
        position += 1;
        if length == 0 {
            return Ok((labels.join("."), consumed.unwrap_or(position)));
        }
        let length = usize::from(length);
        let end = position.checked_add(length).ok_or(())?;
        let label = message.get(position..end).ok_or(())?;
        if label.iter().any(|byte| !byte.is_ascii_graphic()) {
            return Err(());
        }
        labels.push(String::from_utf8(label.to_ascii_lowercase()).map_err(|_| ())?);
        position = end;
    }
}

fn parse_dns_response(message: &[u8], expected_id: u16, question_name: &str) -> Result<DnsResponse, ()> {
    if message.len() < 12 || u16::from_be_bytes([message[0], message[1]]) != expected_id {
        return Err(());
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x8000 == 0 || flags & 0x7800 != 0 || flags & 0x0200 != 0 {
        return Err(());
    }
    let questions = u16::from_be_bytes([message[4], message[5]]) as usize;
    let answers = u16::from_be_bytes([message[6], message[7]]) as usize;
    let authorities = u16::from_be_bytes([message[8], message[9]]) as usize;
    let additionals = u16::from_be_bytes([message[10], message[11]]) as usize;
    if questions != 1 || answers.saturating_add(authorities).saturating_add(additionals) > 128 {
        return Err(());
    }
    let (qname, mut offset) = read_dns_name(message, 12)?;
    if !qname.eq_ignore_ascii_case(question_name) {
        return Err(());
    }
    if message.get(offset..offset + 4) != Some(&[0, 1, 0, 1]) {
        return Err(());
    }
    offset += 4;
    let mut ipv4_answer = None;
    let total_records = answers + authorities + additionals;
    for record_index in 0..total_records {
        let (_, next) = read_dns_name(message, offset)?;
        offset = next;
        let fixed_end = offset.checked_add(10).ok_or(())?;
        let fixed = message.get(offset..fixed_end).ok_or(())?;
        let record_type = u16::from_be_bytes([fixed[0], fixed[1]]);
        let class = u16::from_be_bytes([fixed[2], fixed[3]]);
        let data_length = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        offset = fixed_end;
        let data_end = offset.checked_add(data_length).ok_or(())?;
        let data = message.get(offset..data_end).ok_or(())?;
        if record_index < answers && record_type == 1 && class == 1 && data_length == 4 {
            ipv4_answer = Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
        }
        offset = data_end;
    }
    if offset > message.len() {
        return Err(());
    }
    Ok(DnsResponse {
        rcode: (flags & 0x000f) as u8,
        ipv4_answer,
    })
}

#[derive(Clone)]
struct PortalDraft {
    name: String,
    units: Vec<String>,
    invalid: bool,
}

fn collect_services() -> ServicesObservation {
    let shown = match crate::shared::config::show_json() {
        Ok(value) => value,
        Err(_) => {
            return ServicesObservation::unavailable(
                "caduceus-stats-services-config-unavailable",
            )
        }
    };
    let Some(portals) = shown
        .get("document")
        .and_then(|document| document.pointer("/tabs/portals/data/portals"))
        .and_then(Value::as_array)
    else {
        return ServicesObservation::unavailable("caduceus-stats-services-portals-unavailable");
    };
    let mut drafts = Vec::new();
    let mut unique_units = BTreeSet::new();
    let mut transmission_unit = None;
    let mut config_signal = None;
    for portal in portals {
        let Some(portal) = portal.as_object() else {
            config_signal.get_or_insert_with(|| {
                "caduceus-stats-services-config-entry-invalid".to_owned()
            });
            continue;
        };
        let Some(services_value) = portal.get("services") else {
            config_signal.get_or_insert_with(|| {
                "caduceus-stats-services-config-entry-invalid".to_owned()
            });
            continue;
        };
        let Some(services) = services_value.as_array() else {
            config_signal.get_or_insert_with(|| {
                "caduceus-stats-services-config-entry-invalid".to_owned()
            });
            continue;
        };
        if services.is_empty() {
            continue;
        }
        let name = portal
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty() && name.len() <= 160)
            .map(str::to_owned)
            .unwrap_or_else(|| "unnamed portal".to_owned());
        let mut units = BTreeSet::new();
        let mut invalid = false;
        for service in services {
            let Some(service) = service.as_str() else {
                invalid = true;
                continue;
            };
            let service = service.trim();
            if service.is_empty() {
                invalid = true;
                continue;
            }
            if !crate::routes::control_service::safe_service_name(service)
                || service.starts_with('-')
            {
                invalid = true;
                continue;
            }
            let unit = crate::routes::control_service::normalize_systemd_service(service);
            if !unit.ends_with(".service") || unit.len() > 255 {
                invalid = true;
                continue;
            }
            if transmission_unit.is_none()
                && service.to_ascii_lowercase().contains("transmission")
            {
                transmission_unit = Some(unit.clone());
            }
            units.insert(unit.clone());
            unique_units.insert(unit);
        }
        if units.is_empty() {
            invalid = true;
        }
        if invalid && config_signal.is_none() {
            config_signal = named_signal("caduceus-stats-services-config-entry-invalid");
        }
        drafts.push(PortalDraft {
            name,
            units: units.into_iter().collect(),
            invalid,
        });
    }
    if drafts.is_empty() {
        return ServicesObservation::unavailable(
            config_signal
                .as_deref()
                .unwrap_or("caduceus-stats-services-portals-empty"),
        );
    }
    unique_units.insert("tailscaled.service".to_owned());
    if unique_units.len() > 256 {
        return ServicesObservation::unavailable("caduceus-stats-services-unit-limit-exceeded");
    }
    let command = systemctl_show(&unique_units.into_iter().collect::<Vec<_>>());
    let (states, command_signal) = match command {
        Ok(states) => (states, None),
        Err(signal) => (BTreeMap::new(), Some(signal.to_owned())),
    };
    let mut units = BTreeMap::new();
    let mut first_missing_signal = config_signal.or(command_signal.clone());
    for draft in &drafts {
        for unit in &draft.units {
            let observation = states.get(unit).cloned().unwrap_or_else(|| {
                UnitObservation {
                    active_state: None,
                    enabled: None,
                    first_missing_signal: named_signal(
                        "caduceus-stats-services-unit-unobserved",
                    ),
                }
            });
            if first_missing_signal.is_none() && observation.active_state.is_none() {
                first_missing_signal = observation.first_missing_signal.clone();
            }
            units.insert(unit.clone(), observation);
        }
    }
    let tailscaled = states.get("tailscaled.service").cloned().unwrap_or_else(|| {
        UnitObservation {
            active_state: None,
            enabled: None,
            first_missing_signal: named_signal("caduceus-stats-services-unit-unobserved"),
        }
    });
    units.insert("tailscaled.service".to_owned(), tailscaled);

    let rows = drafts
        .into_iter()
        .map(|draft| {
            let missing = draft.units.iter().any(|unit| {
                units
                    .get(unit)
                    .map_or(true, |state| state.active_state.is_none())
            });
            let status = if draft.invalid || missing {
                "unknown"
            } else {
                let active = draft
                    .units
                    .iter()
                    .filter(|unit| {
                        units
                            .get(*unit)
                            .and_then(|state| state.active_state.as_deref())
                            == Some("active")
                    })
                    .count();
                let down = draft.units.iter().any(|unit| {
                    units
                        .get(unit)
                        .and_then(|state| state.active_state.as_deref())
                        != Some("active")
                });
                if active == draft.units.len() && !draft.units.is_empty() {
                    "up"
                } else if active > 0 && down {
                    "partial"
                } else {
                    "down"
                }
            };
            let signal = if draft.invalid {
                named_signal("caduceus-stats-services-config-entry-invalid")
            } else if missing {
                Some(command_signal.clone().unwrap_or_else(|| {
                    "caduceus-stats-services-unit-unobserved".to_owned()
                }))
            } else {
                None
            };
            PortalObservation {
                name: draft.name,
                units: draft.units,
                status: status.to_owned(),
                first_missing_signal: signal,
            }
        })
        .collect::<Vec<_>>();
    if first_missing_signal.is_none() {
        first_missing_signal = rows
            .iter()
            .find_map(|row| row.first_missing_signal.clone());
    }
    ServicesObservation {
        ts: now_ts(),
        rows,
        units,
        transmission_unit,
        first_missing_signal,
    }
}

fn systemctl_show(units: &[String]) -> Result<BTreeMap<String, UnitObservation>, &'static str> {
    if units.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut command = Command::new("systemctl");
    command
        .args([
            "show",
            "--no-pager",
            "--plain",
            "-p",
            "Id",
            "-p",
            "ActiveState",
            "-p",
            "UnitFileState",
            "-p",
            "LoadState",
        ])
        .args(units)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command
        .spawn()
        .map_err(|_| "caduceus-stats-services-systemctl-unavailable")?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or("caduceus-stats-services-systemctl-output-unavailable")?;
    let fd = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err("caduceus-stats-services-systemctl-output-unavailable");
    }
    let started = Instant::now();
    let mut output = Vec::new();
    let mut exited = None;
    let mut eof = false;
    loop {
        let mut buffer = [0u8; 8192];
        match stdout.read(&mut buffer) {
            Ok(0) => eof = true,
            Ok(count) => {
                if output.len().saturating_add(count) > SYSTEMCTL_OUTPUT_MAX {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("caduceus-stats-services-systemctl-output-too-large");
                }
                output.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("caduceus-stats-services-systemctl-output-failed");
            }
        }
        if exited.is_none() {
            match child.try_wait() {
                Ok(status) => exited = status,
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("caduceus-stats-services-systemctl-wait-failed");
                }
            }
        }
        if exited.is_some() && eof {
            break;
        }
        if started.elapsed() >= SYSTEMCTL_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err("caduceus-stats-services-systemctl-timeout");
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !exited.is_some_and(|status| status.success()) {
        return Err("caduceus-stats-services-systemctl-failed");
    }
    parse_systemctl_show(&output)
}

fn parse_systemctl_show(bytes: &[u8]) -> Result<BTreeMap<String, UnitObservation>, &'static str> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| "caduceus-stats-services-systemctl-output-invalid")?;
    let mut groups = Vec::<BTreeMap<String, String>>::new();
    let mut current = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            if !current.is_empty() {
                groups.push(std::mem::take(&mut current));
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err("caduceus-stats-services-systemctl-output-invalid");
        };
        current.insert(key.to_owned(), value.to_owned());
    }
    if !current.is_empty() {
        groups.push(current);
    }
    let mut result = BTreeMap::new();
    for group in groups {
        let Some(id) = group.get("Id").filter(|id| !id.is_empty()) else {
            continue;
        };
        let not_found = group.get("LoadState").map(String::as_str) == Some("not-found");
        let active_state = group
            .get("ActiveState")
            .filter(|value| !value.is_empty() && !not_found)
            .cloned();
        let (enabled, enabled_signal) = match group.get("UnitFileState").map(String::as_str) {
            Some("enabled" | "enabled-runtime" | "linked" | "linked-runtime") => {
                (Some(true), None)
            }
            Some(
                "disabled" | "masked" | "masked-runtime" | "static" | "indirect"
                | "generated" | "transient",
            ) => (Some(false), None),
            _ => (
                None,
                named_signal("caduceus-stats-services-unit-enabled-state-unobserved"),
            ),
        };
        let first_missing_signal = if not_found {
            named_signal("caduceus-stats-services-unit-not-found")
        } else if active_state.is_none() {
            named_signal("caduceus-stats-services-unit-state-unobserved")
        } else {
            enabled_signal
        };
        result.insert(
            id.clone(),
            UnitObservation {
                active_state,
                enabled,
                first_missing_signal,
            },
        );
    }
    Ok(result)
}
