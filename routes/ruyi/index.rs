use axum::extract::Path;
use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Error, ErrorKind, Write};
use std::{
    fs,
    net::Ipv4Addr,
    path::Path as FsPath,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinSet,
    time::{timeout, Duration, Instant},
};

use crate::routes::leaf_schema::row_schema;
const TEXT_MAX: usize = 64;
const MAX_PROJECTION_BYTES: u64 = 1024 * 1024;
const CADUCEUS_DEFAULT_PORT: u16 = 8787;
const RUYI_PEER_TIMEOUT: Duration = Duration::from_millis(500);
const MAX_PEER_RESPONSE_BYTES: usize = 64 * 1024;

fn peer_probe_port() -> u16 {
    #[cfg(debug_assertions)]
    if let Some(port) = std::env::var("CADUCEUS_RUYI_TEST_PEER_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .filter(|port| *port != 0)
    {
        return port;
    }
    CADUCEUS_DEFAULT_PORT
}

#[derive(Clone, Deserialize, Serialize)]
struct RuyiLastUpdate {
    run_id: String,
    converged: bool,
}

#[derive(Clone, Deserialize, Serialize)]
struct RuyiRow {
    schema: String,
    mac: String,
    hostname: String,
    canonical_name: String,
    ipv4: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    caduceus_port: Option<u16>,
    ipv4_source: Option<String>,
    profile: String,
    gui_face: Option<String>,
    caduceus_sha: String,
    env_sha: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rustc_version: Option<String>,
    harmonia_sha: String,
    syzygy_sha: Option<String>,
    #[serde(default)]
    last_seen: u64,
    last_update: RuyiLastUpdate,
}

#[derive(Serialize)]
struct RuyiSeat {
    mac: String,
    hostname: String,
    ipv4: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ipv4_source: Option<String>,
}

#[derive(Clone, Serialize)]
struct DiscoveredRuyiRow {
    schema: String,
    mac: String,
    hostname: String,
    canonical_name: String,
    ipv4: String,
    ipv4_source: String,
    profile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gui_face: Option<String>,
    caduceus_sha: String,
    env_sha: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    rustc_version: Option<String>,
    harmonia_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    syzygy_sha: Option<String>,
    last_seen: u64,
    last_update: Option<RuyiLastUpdate>,
    discovered_via: String,
}

#[derive(Clone, Serialize)]
#[serde(untagged)]
enum RuyiStaff {
    Announced(RuyiRow),
    Discovered(DiscoveredRuyiRow),
}

impl RuyiStaff {
    fn mac(&self) -> &str {
        match self {
            Self::Announced(row) => &row.mac,
            Self::Discovered(row) => &row.mac,
        }
    }

}

#[derive(Serialize)]
struct RuyiListBody {
    schema: &'static str,
    ok: bool,
    service: &'static str,
    seat: RuyiSeat,
    staves: Vec<RuyiStaff>,
    perspectives: BTreeMap<String, Value>,
    trust: Vec<Value>,
    dns_unresolved: Vec<Value>,
}

fn error(
    status: StatusCode,
    signal: &'static str,
) -> (StatusCode, Json<crate::gate::ApiErrorBody>) {
    (
        status,
        Json(crate::gate::ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: "ruyi".to_owned(),
            first_missing_signal: signal.to_owned(),
        }),
    )
}

fn valid_mac(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 17
        && bytes.iter().enumerate().all(|(index, byte)| {
            if index % 3 == 2 {
                *byte == b':'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
            }
        })
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= TEXT_MAX
}

fn valid_row(row: &RuyiRow, path_mac: &str) -> bool {
    row.schema == row_schema()
        && path_mac == row.mac
        && valid_mac(path_mac)
        && valid_hostname(&row.hostname)
        && crate::shared::seat_identity::resolver_target(&row.hostname).as_deref()
            == Some(row.canonical_name.as_str())
        && row.ipv4.parse::<Ipv4Addr>().is_ok()
        && row.caduceus_port.map_or(true, |port| port != 0)
        && valid_hostname(&row.profile)
        && matches!(
            row.gui_face.as_deref(),
            None | Some("Hyprland") | Some("Arcadia") | Some("Coronatio")
        )
        && valid_hex(&row.caduceus_sha, 40)
        && valid_hex(&row.env_sha, 64)
        && valid_hex(&row.harmonia_sha, 40)
        && row
            .syzygy_sha
            .as_deref()
            .map_or(true, |sha| valid_hex(sha, 64))
        && valid_bounded_text(&row.last_update.run_id)
}

fn server_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn current_identity() -> crate::shared::seat_identity::SeatIdentity {
    let hostname = crate::shared::seat_identity::local_hostname();
    let dns_ipv4 = crate::shared::seat_identity::resolve_home_arpa_ipv4(&hostname);
    let bind_ipv4 = crate::shared::config::declared_bind()
        .ok()
        .and_then(|bind| match bind.ip() {
            std::net::IpAddr::V4(ipv4) => Some(ipv4),
            std::net::IpAddr::V6(_) => None,
        });
    crate::shared::seat_identity::current(dns_ipv4, bind_ipv4)
}

fn bounded_read(path: &FsPath) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_PROJECTION_BYTES {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn canonical_dns_name(value: &str) -> Option<(String, String)> {
    let name = value.trim().trim_end_matches('.').to_ascii_lowercase();
    let hostname = if name == "home.arpa" {
        "home"
    } else {
        let hostname = name.strip_suffix(".home.arpa")?;
        (hostname != "home").then_some(hostname)?
    };
    valid_hostname(hostname).then(|| {
        crate::shared::seat_identity::resolver_target(hostname)
            .map(|canonical_name| (canonical_name, hostname.to_owned()))
    })?
}

fn local_data_record(line: &str) -> Option<(String, String, Ipv4Addr)> {
    let (directive, remainder) = line.trim().split_once(':')?;
    if !directive.eq_ignore_ascii_case("local-data") {
        return None;
    }
    let remainder = remainder.trim();
    let record = if let Some(stripped) = remainder.strip_prefix('"') {
        stripped.split_once('"')?.0
    } else {
        remainder.split('#').next()?.trim()
    };
    let mut fields = record.split_whitespace();
    let name = fields.next()?;
    let mut record_type = fields.next()?;
    if record_type.eq_ignore_ascii_case("IN") {
        record_type = fields.next()?;
    }
    if !record_type.eq_ignore_ascii_case("A") {
        return None;
    }
    let ipv4 = fields.next()?.parse().ok()?;
    let (canonical_name, hostname) = canonical_dns_name(name)?;
    Some((canonical_name, hostname, ipv4))
}

fn unbound_records(root: &FsPath) -> Vec<(String, String, Ipv4Addr)> {
    let mut paths = Vec::new();
    let root_file = root.join("unbound.conf");
    if bounded_read(&root_file).is_some() {
        paths.push(root_file);
    }
    let directory = root.join("unbound.conf.d");
    let mut entries: Vec<_> = fs::read_dir(directory)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.flatten())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "conf")
                && fs::symlink_metadata(entry.path())
                    .is_ok_and(|metadata| metadata.file_type().is_file())
        })
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    paths.extend(entries.into_iter().map(|entry| entry.path()));
    paths
        .into_iter()
        .flat_map(|path| bounded_read(&path).into_iter())
        .flat_map(|text| {
            text.lines()
                .filter_map(local_data_record)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn unbound_dns_view(root: &FsPath) -> Option<Vec<(String, String, Ipv4Addr)>> {
    let records = unbound_records(root);
    (!records.is_empty()).then_some(records)
}

fn unbound_ipv4_for_hostname(
    records: &[(String, String, Ipv4Addr)],
    hostname: &str,
) -> Option<Ipv4Addr> {
    let canonical_name = crate::shared::seat_identity::resolver_target(hostname)?;
    records.iter().find_map(|(name, dns_hostname, ipv4)| {
        (name == &canonical_name && dns_hostname == hostname).then_some(*ipv4)
    })
}

async fn fetch_peer(host: &str, port: u16, path: &str) -> std::io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect((host, port)).await?;
    stream.set_nodelay(true)?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            break;
        }
        response.extend_from_slice(&buffer[..count]);
        if response.len() > MAX_PEER_RESPONSE_BYTES {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "ruyi peer response too large",
            ));
        }
    }
    Ok(response)
}

fn valid_peer_beam(response: &[u8]) -> bool {
    let Some(body_start) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&response[..body_start]) else {
        return false;
    };
    let Some(status) = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
    else {
        return false;
    };
    if status != "200" {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&response[body_start + 4..]) else {
        return false;
    };
    crate::routes::leaf_schema::accepts("caduceus.beam.v1", &value)
        && value.get("ok").and_then(Value::as_bool) == Some(true)
        && value.get("service").and_then(Value::as_str) == Some("caduceus")
}

async fn probe_peer(row: RuyiRow) -> Option<String> {
    let host = if row.ipv4.parse::<Ipv4Addr>().is_ok() {
        row.ipv4.as_str()
    } else {
        row.canonical_name.as_str()
    };
    let port = row.caduceus_port.unwrap_or_else(peer_probe_port);
    let answered = timeout(RUYI_PEER_TIMEOUT, async {
        let response = fetch_peer(host, port, "/api/v1/beam").await?;
        Ok::<_, std::io::Error>(valid_peer_beam(&response))
    }).await.ok()?.ok()?;
    answered.then_some(row.mac)
}

fn normalized_mac(value: &str) -> Option<String> {
    let compact = value.trim().replace('-', ":").to_ascii_lowercase();
    let parts: Vec<_> = compact.split(':').collect();
    (parts.len() == 6 && parts.iter().all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit())))
        .then(|| parts.join(":"))
}

#[derive(Clone)]
struct KeaCandidate { mac: String, address: Ipv4Addr, hostname: String, fallback_hostname: Option<String> }

async fn probe_candidate(
    candidate: KeaCandidate,
    dns: Vec<(String, String, Ipv4Addr)>,
    peer_port: u16,
) -> Option<DiscoveredRuyiRow> {
    let host = candidate.address.to_string();
    let deadline = Instant::now() + RUYI_PEER_TIMEOUT;
    let beam_bytes = timeout(
        RUYI_PEER_TIMEOUT,
        fetch_peer(&host, peer_port, "/api/v1/beam"),
    )
    .await
    .ok()?
    .ok()?;
    if !valid_peer_beam(&beam_bytes) { return None; }
    let beam = response_json_200(&beam_bytes)?;
    // Peer roster enrichment is optional. A valid beam already establishes a candidate;
    // cap both requests together so this sweep cannot consume two full peer timeouts.
    let seat_host = match deadline.checked_duration_since(Instant::now()) {
        Some(remaining) if !remaining.is_zero() => timeout(
            remaining,
            fetch_peer(&host, peer_port, "/api/v1/ruyi"),
        )
            .await.ok().and_then(Result::ok).and_then(|bytes| response_json_200(&bytes))
            .filter(|roster| {
                crate::routes::leaf_schema::accepts_form(row_schema(), "roster", roster)
                    && roster.get("ok").and_then(Value::as_bool) == Some(true)
                    && roster.get("service").and_then(Value::as_str) == Some("caduceus")
            })
            .and_then(|roster| roster.get("seat").and_then(|seat| seat.get("hostname")).and_then(Value::as_str).map(str::to_owned)),
        _ => None,
    };
    let hostname = seat_host.filter(|name| valid_hostname(name))
        .or_else(|| valid_hostname(&candidate.hostname).then(|| candidate.hostname.clone()))
        .or_else(|| candidate.fallback_hostname.filter(|name| valid_hostname(name)))?;
    if !valid_hostname(&hostname) { return None; }
    let canonical_name = crate::shared::seat_identity::resolver_target(&hostname)?;
    let (ipv4, source) = unbound_ipv4_for_hostname(&dns, &hostname)
        .map(|ip| (ip, "dns"))
        .unwrap_or((candidate.address, "declared"));
    let profile = beam.get("profile")?.as_str()?.to_owned();
    let caduceus_sha = beam.get("caduceus_sha")?.as_str()?.to_owned();
    let env_sha = beam.get("env_sha")?.as_str()?.to_owned();
    let gui_face = beam.get("gui_face").and_then(Value::as_str).map(str::to_owned);
    let rustc_version = beam.get("rustc_version").and_then(Value::as_str).map(str::to_owned);
    let syzygy_sha = beam.get("syzygy_sha").and_then(Value::as_str).map(str::to_owned);
    Some(DiscoveredRuyiRow { schema: row_schema().to_owned(), mac: candidate.mac, hostname, canonical_name, ipv4: ipv4.to_string(), ipv4_source: source.to_owned(), profile, gui_face, caduceus_sha, env_sha, rustc_version, harmonia_sha: None, syzygy_sha, last_seen: server_now(), last_update: None, discovered_via: "lease-sweep".to_owned() })
}

fn response_json_200(response: &[u8]) -> Option<Value> {
    let split = response.windows(4).position(|window| window == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&response[..split]).ok()?;
    if headers.lines().next()?.split_whitespace().nth(1)? != "200" { return None; }
    serde_json::from_slice(&response[split+4..]).ok()
}

async fn put(
    Path(path_mac): Path<String>,
    payload: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<RuyiRow>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let Json(value) =
        payload.map_err(|_| error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"))?;
    if !crate::routes::leaf_schema::accepts_form(row_schema(), "row", &value) {
        return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"));
    }
    if value.get("mac").and_then(Value::as_str) != Some(path_mac.as_str()) {
        return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-mac-mismatch"));
    }
    let perspective = value.get("perspective").filter(|value| !value.is_null());
    if let Some(perspective) = perspective {
        if !crate::routes::leaf_schema::accepts("harmonia.ruyi-perspective.v1", perspective) {
            return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"));
        }
        if perspective["self"].get("mac").and_then(Value::as_str) != Some(path_mac.as_str()) {
            return Err(error(
                StatusCode::BAD_REQUEST,
                "caduceus-ruyi-perspective-mac-mismatch",
            ));
        }
        if !crate::routes::leaf_schema::accepts_form(row_schema(), "row", &perspective["self"]) {
            return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"));
        }
        let own_row: RuyiRow = serde_json::from_value(perspective["self"].clone())
            .map_err(|_| error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"))?;
        if !valid_row(&own_row, &path_mac) {
            return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"));
        }
    }
    let perspective_json = perspective.map(Value::to_string);
    let mut row: RuyiRow = serde_json::from_value(value)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"))?;
    if !valid_row(&row, &path_mac) {
        return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"));
    }
    let canonical_name = crate::shared::seat_identity::resolver_target(&row.hostname)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"))?;
    row.ipv4_source = Some("declared".to_owned());
    if let Some(dns_ipv4) = unbound_dns_view(&crate::shared::config::path("etc/unbound"))
        .and_then(|records| unbound_ipv4_for_hostname(&records, &row.hostname))
    {
        row.ipv4 = dns_ipv4.to_string();
        row.ipv4_source = Some("dns".to_owned());
    }
    row.canonical_name = canonical_name;
    row.last_seen = server_now();
    let row_json = serde_json::to_string(&row).map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-ruyi-store-failed",
        )
    })?;
    crate::stats::ruyi_put(
        &row.mac,
        &row_json,
        row.last_seen as i64,
        perspective_json.as_deref(),
    )
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-ruyi-store-failed",
        )
    })?;
    Ok((StatusCode::OK, Json(row)))
}

async fn list() -> Result<Json<RuyiListBody>, (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let stored = crate::stats::ruyi_snapshot().map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-store-failed"))?;
    let mut announced = Vec::with_capacity(stored.rows.len());
    for (_, row_json, last_seen) in stored.rows {
        let value: Value = serde_json::from_str(&row_json).map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        if !crate::routes::leaf_schema::accepts_form(row_schema(), "row", &value) { return Err(error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid")); }
        let mut row: RuyiRow = serde_json::from_value(value).map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        row.last_seen = u64::try_from(last_seen).map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        announced.push(row);
    }
    let mut perspectives = BTreeMap::new();
    let mut received = BTreeMap::new();
    for (mac, bytes, received_at) in stored.perspectives {
        let value = serde_json::from_str(&bytes).map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        received.insert(mac.clone(), u64::try_from(received_at).map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?);
        perspectives.insert(mac, value);
    }
    let identity = current_identity();
    let self_mac = identity.mac.clone();
    let dns = unbound_records(&crate::shared::config::path("etc/unbound"));
    let mut candidates = BTreeMap::<String, KeaCandidate>::new();
    if let (Ok(leases), Ok(reservations)) = (crate::routes::native_kea_read::read_leases(), crate::routes::native_kea_read::read_reservations()) {
        for lease in leases {
            if let (Some(mac), Ok(address)) = (normalized_mac(&lease.mac), lease.ip.parse::<Ipv4Addr>()) {
                candidates.insert(mac.clone(), KeaCandidate { mac, address, hostname: lease.hostname, fallback_hostname: None });
            }
        }
        for reservation in reservations {
            if let (Some(mac), Ok(address)) = (normalized_mac(&reservation.mac), reservation.ip.parse::<Ipv4Addr>()) {
                match candidates.entry(mac.clone()) {
                    std::collections::btree_map::Entry::Vacant(entry) => { entry.insert(KeaCandidate { mac, address, hostname: reservation.hostname, fallback_hostname: None }); }
                    std::collections::btree_map::Entry::Occupied(mut entry) => {
                        if valid_hostname(&reservation.hostname) { entry.get_mut().fallback_hostname = Some(reservation.hostname); }
                    }
                }
            }
        }
    }
    let stored_macs: BTreeSet<_> = announced.iter().map(|row| row.mac.to_ascii_lowercase()).collect();
    candidates.retain(|mac, _| !stored_macs.contains(mac) && self_mac.as_deref() != Some(mac.as_str()));
    let mut staves: Vec<RuyiStaff> = announced.iter().cloned().map(RuyiStaff::Announced).collect();
    let mut probes = JoinSet::new();
    for row in announced.iter().filter(|row| self_mac.as_deref() != Some(row.mac.as_str())).cloned() {
        probes.spawn(async move { (Some(probe_peer(row).await), None) });
    }
    let peer_port = peer_probe_port();
    for candidate in candidates.into_values() {
        let dns = dns.clone();
        probes.spawn(async move { (None, probe_candidate(candidate, dns, peer_port).await) });
    }
    let mut answered = BTreeSet::new();
    if let Some(mac) = self_mac.as_ref() { if announced.iter().any(|row| &row.mac == mac) { answered.insert(mac.clone()); } }
    while let Some(result) = probes.join_next().await {
        if let Ok((stored_result, discovered_result)) = result {
            if let Some(Some(mac)) = stored_result { answered.insert(mac); }
            if let Some(row) = discovered_result { answered.insert(row.mac.clone()); staves.push(RuyiStaff::Discovered(row)); }
        }
    }
    staves.retain(|row| matches!(row, RuyiStaff::Discovered(_)) || answered.contains(row.mac()));
    perspectives.retain(|mac, _| answered.contains(mac));
    received.retain(|mac, _| answered.contains(mac));
    let discovered_macs: BTreeSet<_> = staves.iter().filter_map(|staff| match staff { RuyiStaff::Discovered(row) => Some(row.mac.clone()), _ => None }).collect();
    let trust_rows: Vec<_> = staves
        .iter()
        .map(|staff| match staff {
            RuyiStaff::Announced(row) => TrustRow {
                mac: row.mac.clone(),
                caduceus_sha: row.caduceus_sha.clone(),
                env_sha: row.env_sha.clone(),
                syzygy_sha: row.syzygy_sha.clone(),
                last_seen: row.last_seen,
            },
            RuyiStaff::Discovered(row) => TrustRow {
                mac: row.mac.clone(),
                caduceus_sha: row.caduceus_sha.clone(),
                env_sha: row.env_sha.clone(),
                syzygy_sha: row.syzygy_sha.clone(),
                last_seen: row.last_seen,
            },
        })
        .collect();
    let trust = derive_trust(&trust_rows, &perspectives, &received, &discovered_macs);
    let dns_unresolved = if !dns.is_empty() { staves.iter().filter_map(|staff| {
        let value = match staff { RuyiStaff::Announced(row) => (row.mac.as_str(), row.hostname.as_str(), row.canonical_name.as_str(), row.ipv4.as_str(), row.ipv4_source.as_deref()), RuyiStaff::Discovered(row) => (row.mac.as_str(), row.hostname.as_str(), row.canonical_name.as_str(), row.ipv4.as_str(), Some(row.ipv4_source.as_str())) };
        (value.4 == Some("declared")).then(|| json!({"mac":value.0,"hostname":value.1,"canonical_name":value.2,"ipv4":value.3}))
    }).collect() } else { Vec::new() };
    Ok(Json(RuyiListBody { schema: row_schema(), ok: true, service: "caduceus", seat: RuyiSeat {
        mac: identity.mac.unwrap_or_else(|| "unknown".to_owned()), hostname: crate::shared::seat_identity::local_hostname(),
        ipv4: identity.ipv4.map(|ipv4| ipv4.to_string()).unwrap_or_else(|| "unknown".to_owned()), ipv4_source: identity.ipv4_source.map(str::to_owned),
    }, staves, perspectives, trust, dns_unresolved }))
}

struct TrustRow {
    mac: String,
    caduceus_sha: String,
    env_sha: String,
    syzygy_sha: Option<String>,
    last_seen: u64,
}

fn agrees(target: &TrustRow, evidence: &Value) -> bool {
    match target.syzygy_sha.as_deref() {
        Some(sha) => evidence.get("syzygy_sha").and_then(Value::as_str) == Some(sha),
        None => evidence.get("beam_pair").is_some_and(|pair| {
            pair.get("caduceus_sha").and_then(Value::as_str) == Some(target.caduceus_sha.as_str())
                && pair.get("env_sha").and_then(Value::as_str) == Some(target.env_sha.as_str())
        }),
    }
}

/// Trust is a projection of the registered roster, never a second stored roster.
/// A body's own row attests itself; seen[target] supplies its peer attestations.
fn derive_trust(
    staves: &[TrustRow],
    perspectives: &BTreeMap<String, Value>,
    received: &BTreeMap<String, u64>,
    discovered: &BTreeSet<String>,
) -> Vec<Value> {
    staves
        .iter()
        .map(|target| {
            let mut witnesses = if discovered.contains(&target.mac) { BTreeSet::new() } else { BTreeSet::from([target.mac.clone()]) };
            let mut first_seen = target.last_seen;
            let mut last_seen = target.last_seen;
            let mut last_event = target.last_seen;
            for witness in staves {
                let Some(perspective) = perspectives.get(&witness.mac) else {
                    continue;
                };
                let fallback = perspective
                    .get("written_at")
                    .and_then(Value::as_u64)
                    .or_else(|| received.get(&witness.mac).copied())
                    .unwrap_or(witness.last_seen);
                let Some(peer) = perspective
                    .get("seen")
                    .and_then(|seen| seen.get(&target.mac))
                else {
                    continue;
                };
                // Malformed optional observations remain raw but cannot become attestations.
                if peer.get("mac").and_then(Value::as_str) != Some(target.mac.as_str()) {
                    continue;
                }
                let at = peer
                    .get("last_checked_in_at")
                    .and_then(Value::as_u64)
                    .unwrap_or(fallback);
                last_event = last_event.max(at);
                if agrees(target, peer) {
                    witnesses.insert(witness.mac.clone());
                    first_seen = first_seen.min(at);
                    last_seen = last_seen.max(at);
                }
                if let Some(lineage) = peer.get("lineage").and_then(Value::as_array) {
                    for event in lineage {
                        let Some(at) = event.get("seen_at").and_then(Value::as_u64) else {
                            continue;
                        };
                        last_event = last_event.max(at);
                        // A historical sighting has no env_sha; it cannot prove a BeamPair.
                        if target.syzygy_sha.as_deref().is_some_and(|sha| {
                            event.get("syzygy_sha").and_then(Value::as_str) == Some(sha)
                        }) {
                            first_seen = first_seen.min(at);
                            last_seen = last_seen.max(at);
                        }
                    }
                }
            }
            json!({"mac":target.mac,"syzygy_sha":target.syzygy_sha,
            "beam_pair":{"caduceus_sha":target.caduceus_sha,"env_sha":target.env_sha},
            "agree":witnesses.len(),"of":staves.len(),"witnesses":witnesses,
            "first_seen":first_seen,"last_seen":last_seen,"last_event":last_event})
        })
        .collect()
}

pub(crate) fn local_syzygy() -> Result<Option<String>, String> {
    let Some(mac) = current_identity().mac else {
        return Ok(None);
    };
    let Some(row) = crate::stats::ruyi_row(&mac)? else {
        return Ok(None);
    };
    let row: RuyiRow =
        serde_json::from_str(&row).map_err(|_| "caduceus-ruyi-row-invalid".to_owned())?;
    Ok(row.syzygy_sha)
}

async fn remove(
    Path(mac): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    if !valid_mac(&mac) {
        return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"));
    }
    // The native log records actual removals only; an absent row writes no line.
    let log_path = crate::shared::config::path("var/log/appliance/appliance.log");
    let hostname = crate::stats::ruyi_delete(&mac)
        .map_err(|_| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "caduceus-ruyi-store-failed",
            )
        })?
        .ok_or_else(|| error(StatusCode::NOT_FOUND, "caduceus-ruyi-row-absent"))?;
    let append = || -> std::io::Result<()> {
        if let Some(parent) = log_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;
        writeln!(
            log,
            "ruyi removed mac={} hostname={}",
            mac,
            serde_json::to_string(&hostname).unwrap()
        )
    };
    // A log failure is reported as partial failure, never as a successful deletion receipt.
    append().map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-ruyi-removed-log-failed",
        )
    })?;
    Ok(Json(json!({"schema":row_schema(),"ok":true,"removed":mac})))
}

pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/ruyi/:mac", axum::routing::put(put).delete(remove))
        .route("/api/v1/ruyi", axum::routing::get(list))
}
