use crate::gate::{gated_body, gated_json, ApiErrorBody};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const STATS_COMMAND: &str = "appliance stats read";
pub(crate) const ROUTE_LABELS: [&str; 6] = [
    "/api/v1/appliance/stats",
    "/api/v1/appliance/stats/history",
    "/api/v1/appliance/model-lanes/pulse",
    "/api/v1/ruyi",
    "/health",
    "other",
];

// Each pair is [requests, responses with status >= 400].  The dimensions
// remain fixed so self-telemetry cannot grow with the route corpus.
static ROUTE_COUNTERS: [[AtomicU64; 2]; 6] = [
    [const { AtomicU64::new(0) }, const { AtomicU64::new(0) }],
    [const { AtomicU64::new(0) }, const { AtomicU64::new(0) }],
    [const { AtomicU64::new(0) }, const { AtomicU64::new(0) }],
    [const { AtomicU64::new(0) }, const { AtomicU64::new(0) }],
    [const { AtomicU64::new(0) }, const { AtomicU64::new(0) }],
    [const { AtomicU64::new(0) }, const { AtomicU64::new(0) }],
];
static ROUTE_LATENCY_LOG2: [[AtomicU64; 32]; 6] = [
    [const { AtomicU64::new(0) }; 32],
    [const { AtomicU64::new(0) }; 32],
    [const { AtomicU64::new(0) }; 32],
    [const { AtomicU64::new(0) }; 32],
    [const { AtomicU64::new(0) }; 32],
    [const { AtomicU64::new(0) }; 32],
];

fn route_index(path: &str) -> usize {
    match path {
        "/api/v1/appliance/stats" | "/api/v1/appliance/stats/current" => 0,
        "/api/v1/appliance/stats/history" => 1,
        "/api/v1/appliance/model-lanes/pulse" => 2,
        "/api/v1/ruyi" => 3,
        "/health" => 4,
        _ if path.starts_with("/api/v1/ruyi/") => 3,
        _ => 5,
    }
}

fn latency_bin(latency: Duration) -> usize {
    let millis = latency.as_millis().min(u128::from(u64::MAX)) as u64;
    if millis == 0 {
        0
    } else {
        (u64::BITS - millis.leading_zeros() - 1).min(31) as usize
    }
}

pub(crate) fn record_request(path: &str, status: axum::http::StatusCode, latency: Duration) {
    let index = route_index(path);
    ROUTE_COUNTERS[index][0].fetch_add(1, Ordering::Relaxed);
    if status.as_u16() >= 400 {
        ROUTE_COUNTERS[index][1].fetch_add(1, Ordering::Relaxed);
    }
    ROUTE_LATENCY_LOG2[index][latency_bin(latency)].fetch_add(1, Ordering::Relaxed);
}

#[derive(Clone, Copy, Default)]
pub(crate) struct DoorSnapshot {
    pub(crate) requests: [u64; 6],
    pub(crate) errors: [u64; 6],
    pub(crate) latency_log2: [[u64; 32]; 6],
}

impl DoorSnapshot {
    pub(crate) fn add_assign(&mut self, other: &Self) {
        for index in 0..ROUTE_LABELS.len() {
            self.requests[index] = self.requests[index].saturating_add(other.requests[index]);
            self.errors[index] = self.errors[index].saturating_add(other.errors[index]);
            for bin in 0..32 {
                self.latency_log2[index][bin] = self.latency_log2[index][bin]
                    .saturating_add(other.latency_log2[index][bin]);
            }
        }
    }

    pub(crate) fn as_value(&self) -> Value {
        let mut doors = serde_json::Map::new();
        for (index, label) in ROUTE_LABELS.iter().enumerate() {
            doors.insert(
                (*label).to_owned(),
                json!({
                    "requests": self.requests[index],
                    "errors": self.errors[index],
                    "latencyLog2": self.latency_log2[index],
                    "latencyUnit": "milliseconds",
                }),
            );
        }
        Value::Object(doors)
    }
}

fn snapshot(reset: bool) -> DoorSnapshot {
    let read = |counter: &AtomicU64| {
        if reset {
            counter.swap(0, Ordering::AcqRel)
        } else {
            counter.load(Ordering::Acquire)
        }
    };
    let mut snapshot = DoorSnapshot::default();
    for index in 0..ROUTE_LABELS.len() {
        snapshot.requests[index] = read(&ROUTE_COUNTERS[index][0]);
        snapshot.errors[index] = read(&ROUTE_COUNTERS[index][1]);
        for bin in 0..32 {
            snapshot.latency_log2[index][bin] = read(&ROUTE_LATENCY_LOG2[index][bin]);
        }
    }
    snapshot
}

/// Read the fixed route self-telemetry map, optionally resetting its interval.
pub(crate) fn door_stats(reset: bool) -> Value {
    snapshot(reset).as_value()
}

pub(crate) fn snapshot_and_reset() -> DoorSnapshot {
    snapshot(true)
}

fn json_response(body: String) -> axum::response::Response {
    axum::response::IntoResponse::into_response((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        axum::body::Body::from(body),
    ))
}

async fn current_http(
) -> Result<axum::response::Response, (axum::http::StatusCode, axum::Json<ApiErrorBody>)> {
    gated_body(STATS_COMMAND, crate::stats::current)
        .await
        .map(json_response)
}

async fn history_http(
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
) -> axum::response::Response {
    match crate::shared::policy::allows_command(STATS_COMMAND) {
        Ok(true) => {
            let axum::extract::Query(query) =
                match axum::extract::Query::<crate::stats::HistoryQuery>::try_from_uri(&uri) {
                    Ok(query) => query,
                    Err(rejection) => {
                        return axum::response::IntoResponse::into_response(rejection);
                    }
                };
            match tokio::task::spawn_blocking(move || crate::stats::history(query)).await {
                Ok(Ok(body)) => json_response(body),
                Ok(Err(error)) => {
                    axum::response::IntoResponse::into_response(crate::gate::service_unavailable(
                        STATS_COMMAND,
                        crate::gate::missing_signal(&error),
                    ))
                }
                Err(error) => {
                    axum::response::IntoResponse::into_response(crate::gate::service_unavailable(
                        STATS_COMMAND,
                        crate::gate::missing_signal(&error.to_string()),
                    ))
                }
            }
        }
        Ok(false) => {
            axum::response::IntoResponse::into_response(crate::gate::api_error(STATS_COMMAND))
        }
        Err(_) => axum::response::IntoResponse::into_response(crate::gate::api_error_signal(
            STATS_COMMAND,
            "caduceus-profile-missing",
        )),
    }
}

async fn pulse_http(
) -> Result<axum::Json<Value>, (axum::http::StatusCode, axum::Json<ApiErrorBody>)> {
    gated_json(STATS_COMMAND, crate::stats::request_model_lane_pulse).await
}

pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/appliance/stats", axum::routing::get(current_http))
        .route(
            "/api/v1/appliance/stats/history",
            axum::routing::get(history_http),
        )
        .route(
            "/api/v1/appliance/model-lanes/pulse",
            axum::routing::post(pulse_http),
        )
}
