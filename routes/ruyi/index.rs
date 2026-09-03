use axum::extract::Path;
use axum::{extract::ConnectInfo, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

const ROW_SCHEMA: &str = "caduceus.ruyi.v1";
const RESPONSE_SCHEMA: &str = "caduceus.ruyi.v1";
const CADUCEUS_BUILD_SHA: Option<&str> = option_env!("CADUCEUS_BUILD_SHA");

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
    #[serde(default)]
    spine: String,
}

#[derive(Serialize)]
struct RuyiPutBody {
    schema: &'static str,
    ok: bool,
    stored: RuyiRow,
}

#[derive(Serialize)]
struct RuyiSeat {
    mac: Option<String>,
    hostname: String,
    profile: String,
    caduceus_sha: &'static str,
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
    value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_row(row: &RuyiRow, path_mac: &str) -> bool {
    row.schema == ROW_SCHEMA
        && path_mac == row.mac
        && valid_mac(&row.mac)
        && valid_hex(&row.caduceus_sha, 40)
        && valid_hex(&row.env_sha, 64)
        && valid_hex(&row.harmonia_sha, 40)
        && row
            .syzygy_sha
            .as_deref()
            .map_or(true, |sha| valid_hex(sha, 64))
}

fn server_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn local_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|hostname| hostname.trim().to_owned())
        .unwrap_or_else(|_| "unknown".to_owned())
}

fn local_mac() -> Option<String> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    let iface = route.lines().skip(1).find_map(|line| {
        let mut fields = line.split_whitespace();
        let iface = fields.next()?;
        let destination = fields.next()?;
        (destination == "00000000").then(|| iface.to_owned())
    })?;
    std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .ok()
        .map(|mac| mac.trim().to_owned())
}

async fn put(
    Path(path_mac): Path<String>,
    peer: Option<ConnectInfo<crate::gate::ConnectionInfo>>,
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<RuyiPutBody>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let mut row: RuyiRow = serde_json::from_value(value)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"))?;
    if path_mac != row.mac {
        return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-mac-mismatch"));
    }
    if !valid_row(&row, &path_mac) {
        return Err(error(StatusCode::BAD_REQUEST, "caduceus-ruyi-row-invalid"));
    }
    row.last_seen = server_now();
    row.spine = "client-claimed".to_owned();
    if let Some(ConnectInfo(crate::gate::ConnectionInfo::Tcp(address))) = peer {
        if !address.ip().is_loopback() {
            row.ipv4 = address.ip().to_string();
            row.spine = "observed-peer".to_owned();
        }
    }
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
    Ok((
        StatusCode::OK,
        Json(RuyiPutBody {
            schema: RESPONSE_SCHEMA,
            ok: true,
            stored: row,
        }),
    ))
}

async fn list() -> Result<Json<RuyiListBody>, (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let stored = crate::stats::ruyi_list();
    let mut staves = Vec::with_capacity(stored.len());
    for (_, row_json, last_seen) in stored {
        let mut row: RuyiRow = serde_json::from_str(&row_json)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        row.last_seen = u64::try_from(last_seen)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
        staves.push(row);
    }
    Ok(Json(RuyiListBody {
        schema: RESPONSE_SCHEMA,
        ok: true,
        service: "caduceus",
        seat: RuyiSeat {
            mac: local_mac(),
            hostname: local_hostname(),
            profile: std::env::var("CADUCEUS_PROFILE").unwrap_or_else(|_| "unknown".to_owned()),
            caduceus_sha: CADUCEUS_BUILD_SHA.unwrap_or("unset"),
        },
        staves,
    }))
}

pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/ruyi/:mac", axum::routing::put(put))
        .route("/api/v1/ruyi", axum::routing::get(list))
}
