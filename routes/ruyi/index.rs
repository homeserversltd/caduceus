use axum::extract::Path;
use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs,
    net::Ipv4Addr,
    path::Path as FsPath,
    time::{SystemTime, UNIX_EPOCH},
};

const ROW_SCHEMA: &str = "caduceus.ruyi.v1";
const TEXT_MAX: usize = 64;
const MAX_PROJECTION_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuyiLastUpdate {
    run_id: String,
    converged: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuyiRow {
    schema: String,
    mac: String,
    hostname: String,
    canonical_name: String,
    ipv4: String,
    profile: String,
    gui_face: Option<String>,
    caduceus_sha: String,
    env_sha: String,
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
}

#[derive(Serialize)]
struct RuyiListBody {
    schema: &'static str,
    ok: bool,
    service: &'static str,
    seat: RuyiSeat,
    staves: Vec<RuyiRow>,
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
    row.schema == ROW_SCHEMA
        && path_mac == row.mac
        && valid_mac(path_mac)
        && valid_hostname(&row.hostname)
        && row.canonical_name == format!("{}.home.arpa", row.hostname)
        && row.ipv4.parse::<Ipv4Addr>().is_ok()
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

fn local_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|hostname| hostname.trim().to_owned())
        .filter(|hostname| !hostname.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn local_mac() -> Option<String> {
    let route = fs::read_to_string("/proc/net/route").ok()?;
    let iface = route.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let iface = fields.next()?;
        let destination = fields.next()?;
        (destination == "00000000").then(|| iface.to_owned())
    })?;
    fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .ok()
        .map(|mac| mac.trim().to_owned())
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
    let hostname = name.strip_suffix(".home.arpa")?;
    valid_hostname(hostname).then(|| (format!("{hostname}.home.arpa"), hostname.to_owned()))
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

fn unbound_ipv4_for_hostname(hostname: &str) -> Option<Ipv4Addr> {
    let canonical_name = format!("{hostname}.home.arpa");
    unbound_records(&crate::shared::config::path("etc/unbound"))
        .into_iter()
        .find_map(|(name, dns_hostname, ipv4)| {
            (name == canonical_name && dns_hostname == hostname).then_some(ipv4)
        })
}

async fn put(
    Path(path_mac): Path<String>,
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<RuyiRow>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    if value.get("mac").and_then(Value::as_str) != Some(path_mac.as_str()) {
        return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-mac-mismatch"));
    }
    let mut row: RuyiRow = serde_json::from_value(value)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"))?;
    if !valid_row(&row, &path_mac) {
        return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"));
    }
    row.last_seen = server_now();
    let Some(ipv4) = unbound_ipv4_for_hostname(&row.hostname) else {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "caduceus-ruyi-dns-record-missing",
        ));
    };
    row.ipv4 = ipv4.to_string();
    let row_json = serde_json::to_string(&row).map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-ruyi-store-failed",
        )
    })?;
    crate::stats::ruyi_upsert(&row.mac, &row_json, row.last_seen as i64).map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-ruyi-store-failed",
        )
    })?;
    Ok((StatusCode::OK, Json(row)))
}

async fn list() -> Result<Json<RuyiListBody>, (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let stored = crate::stats::ruyi_list().map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-ruyi-store-failed",
        )
    })?;
    let mut staves = Vec::with_capacity(stored.len());
    for (_, row_json, last_seen) in stored {
        let mut value: Value = serde_json::from_str(&row_json)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        if let Some(object) = value.as_object_mut() {
            object.remove("spine");
        }
        let mut row: RuyiRow = serde_json::from_value(value)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        row.last_seen = u64::try_from(last_seen)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        staves.push(row);
    }
    Ok(Json(RuyiListBody {
        schema: ROW_SCHEMA,
        ok: true,
        service: "caduceus",
        seat: RuyiSeat {
            mac: local_mac().unwrap_or_else(|| "unknown".to_owned()),
            hostname: local_hostname(),
        },
        staves,
    }))
}

pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/ruyi/:mac", axum::routing::put(put))
        .route("/api/v1/ruyi", axum::routing::get(list))
}
