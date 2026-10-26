// Household notifications; declarations are facts, never admission authority.
use axum::http::StatusCode;
use axum::{
    body::Body,
    extract::rejection::JsonRejection,
    http::{HeaderMap, Request},
    response::{IntoResponse, Response},
    Json, Router,
};
use rusqlite::{Connection, OpenFlags};
use serde_json::{json, Value};
use std::{collections::BTreeSet, time::Instant};
use tokio::sync::Semaphore;
use tower::ServiceExt;

#[path = "support/house.rs"]
mod house;

const SCHEMA: &str = "caduceus.notifications.v1";
const MAX_BODY: usize = 1024 * 1024;
static READS: Semaphore = Semaphore::const_new(8);
static MUTATIONS: Semaphore = Semaphore::const_new(1);

type Failure = (StatusCode, &'static str);

fn refusal((status, signal): Failure) -> Response {
    (
        status,
        Json(json!({"schema": SCHEMA, "ok": false,
        "firstMissingSignal": signal})),
    )
        .into_response()
}

fn unavailable(signal: &'static str) -> Failure {
    (StatusCode::SERVICE_UNAVAILABLE, signal)
}

fn gateway_profile() -> bool {
    crate::routes::profile_routes::ACTIVE_PROFILE == "homeserver"
        && crate::shared::config::resolved_profile().ok().as_deref() == Some("homeserver")
}

// Reuse the roster's actual live-probe route, not another interpretation of its
// stored announcements, nor an HTTP call to a pinned copy of ourselves.
// This is a semantic projection reader, not a second Ruyi schema. Serde skips
// unknown top-level and row fields without retaining the perspective bodies.
#[derive(serde::Deserialize, serde::Serialize)]
struct Stave {
    #[serde(default)]
    mac: Value,
    #[serde(default)]
    ipv4: Value,
    #[serde(default)]
    caduceus_port: Value,
    #[serde(default)]
    hostname: Value,
    #[serde(default)]
    canonical_name: Value,
    #[serde(default)]
    services: Value,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct RosterProjection {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    seat: Value,
    #[serde(default)]
    staves: Vec<Stave>,
}

struct RosterStream {
    receiver: tokio::sync::mpsc::Receiver<axum::body::Bytes>,
    current: axum::body::Bytes,
}

impl std::io::Read for RosterStream {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.current.is_empty() {
            match self.receiver.blocking_recv() {
                Some(bytes) => self.current = bytes,
                None => return Ok(0),
            }
        }
        let count = output.len().min(self.current.len());
        output[..count].copy_from_slice(&self.current[..count]);
        self.current = self.current.slice(count..);
        Ok(count)
    }
}

async fn roster() -> Result<Value, Failure> {
    use http_body_util::BodyExt;
    let request = Request::builder()
        .uri("/api/v1/ruyi")
        .body(Body::empty())
        .unwrap();
    let response = crate::routes::leaf_ruyi::register(Router::new())
        .oneshot(request)
        .await
        .map_err(|_| unavailable("link-up-roster-unavailable"))?;
    if !response.status().is_success() {
        return Err(unavailable("link-up-roster-unavailable"));
    }
    // One bounded in-flight frame. Do not copy the complete roster into a
    // second byte buffer or deserialize its unrelated perspectives and trust.
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let parser = tokio::task::spawn_blocking(move || {
        serde_json::from_reader::<_, RosterProjection>(RosterStream {
            receiver,
            current: axum::body::Bytes::new(),
        })
    });
    let mut body = response.into_body();
    let mut failed = false;
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => {
                if let Ok(bytes) = frame.into_data() {
                    if sender.send(bytes).await.is_err() {
                        failed = true;
                        break;
                    }
                }
            }
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    drop(sender);
    let projection = parser
        .await
        .map_err(|_| unavailable("link-up-roster-unavailable"))?
        .map_err(|_| unavailable("link-up-roster-unavailable"))?;
    if failed || !projection.ok {
        return Err(unavailable("link-up-roster-unavailable"));
    }
    serde_json::to_value(projection).map_err(|_| unavailable("link-up-roster-unavailable"))
}

fn candidates(roster: &Value) -> Vec<Value> {
    let mut found = std::collections::BTreeMap::new();
    for row in roster["staves"].as_array().into_iter().flatten() {
        let Some(mac) = row["mac"].as_str() else {
            continue;
        };
        let Some(ip) = row["ipv4"]
            .as_str()
            .and_then(|ip| ip.parse::<std::net::Ipv4Addr>().ok())
        else {
            continue;
        };
        for service in row["services"].as_array().into_iter().flatten() {
            if service["kind"] != "face" || service["protocol"] != "http" {
                continue;
            }
            let Some(port) = service["port"]
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .filter(|port| *port > 0)
            else {
                continue;
            };
            let Some(names) = service["names"]
                .as_array()
                .filter(|names| !names.is_empty() && names.iter().all(Value::is_string))
            else {
                continue;
            };
            // The listener identifies the face even if a producer reorders services.
            let id = format!("link-up:{}:{port}", mac.to_ascii_lowercase());
            found.entry(id.clone()).or_insert_with(|| json!({
                "id": id, "kind": "house-link-up", "state": "pending",
                "title": format!("Connect {} to your house", row["hostname"].as_str().unwrap_or("this device")),
                "from": {"hostname": row["hostname"], "canonical_name": row["canonical_name"],
                    "ipv4": ip.to_string(), "mac": mac},
                "upstream": format!("http://{ip}:{port}"), "names": names
            }));
        }
    }
    found.into_values().collect()
}

fn dismissals_exist(db: &Connection) -> Result<bool, Failure> {
    db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='notification_dismissals')", [], |row| row.get(0))
        .map_err(|_| unavailable("link-up-state-unavailable"))
}

fn is_dismissed(db: &Connection, id: &str) -> Result<bool, Failure> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM notification_dismissals WHERE id=?1)",
        [id],
        |row| row.get(0),
    )
    .map_err(|_| unavailable("link-up-state-unavailable"))
}

fn pending(candidates: Vec<Value>, portals: &Value) -> Result<Vec<Value>, Failure> {
    let db = Connection::open_with_flags(crate::stats::db_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|_| unavailable("link-up-state-unavailable"))?;
    let has_dismissals = dismissals_exist(&db)?;
    let mut result = Vec::new();
    for candidate in candidates {
        let admitted = portals["portals"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|portal| portal["fqdn"] == candidate["names"][0]);
        if !admitted && !(has_dismissals && is_dismissed(&db, candidate["id"].as_str().unwrap())?) {
            result.push(candidate);
        }
    }
    Ok(result)
}

async fn list() -> Response {
    let Ok(_permit) = READS.try_acquire() else {
        return refusal(unavailable("link-up-busy"));
    };
    if !gateway_profile() {
        // A peer read carries the gateway's complete raw JSON, including additive
        // fields. A missing gateway door is quiet, not a local admission fallback.
        return match house::gateway_notifications().await {
            Some(value) => Json(value).into_response(),
            None => Json(json!({"schema": SCHEMA, "notifications": [], "gateway": "unreachable"}))
                .into_response(),
        };
    }
    let result = async {
        let roster = roster().await?;
        let portals = house::portals().await?;
        tokio::task::spawn_blocking(move || pending(candidates(&roster), &portals))
            .await
            .map_err(|_| unavailable("link-up-state-unavailable"))?
    }
    .await;
    match result {
        Ok(notifications) => {
            Json(json!({"schema": SCHEMA, "notifications": notifications})).into_response()
        }
        Err(failure) => refusal(failure),
    }
}

// Admin Mode is the existing document-attendance admission, not a new key or
// an owner claim in the request. Check it in every mutation handler, even with
// the PIN switch off, and never trust the middleware's internal marker header.
// The generic administrative gate has a different refusal vocabulary; this
// leaf owns its named link-up refusal while using the same attendance verifier.
fn admin(headers: &HeaderMap) -> Result<(), Failure> {
    let document = headers
        .get("x-caduceus-document")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let token = headers
        .get("x-caduceus-attendance")
        .and_then(|v| v.to_str().ok());
    crate::gate::document_attendance_admits(document, token)
        .map_err(|_| (StatusCode::FORBIDDEN, "link-up-admin-required"))
}

fn names(body: &Value, candidate: &Value) -> Result<Vec<String>, Failure> {
    let values = match body.get("names") {
        None | Some(Value::Null) => &candidate["names"],
        Some(value) => value,
    };
    let invalid = (StatusCode::BAD_REQUEST, "link-up-name-invalid");
    let values = values
        .as_array()
        .filter(|names| !names.is_empty() && names.len() <= 32)
        .ok_or(invalid)?;
    let mut unique = BTreeSet::new();
    values
        .iter()
        .map(|name| {
            let name = name
                .as_str()
                .filter(|name| house::valid_name(name))
                .ok_or(invalid)?;
            if !unique.insert(name) {
                return Err(invalid);
            }
            Ok(name.to_owned())
        })
        .collect()
}

fn record(id: &str, verb: &str, outcome: &Value, started: Instant) {
    let id = if id.len() <= 64 { id } else { "oversized-id" };
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ": "notifications", "kind": "deed", "correlation_id": id, "ok": outcome["ok"] == true,
        "message": "house link-up",
        "attributes_redacted": {"who": "owner", "verb": verb, "target": "house-link-up",
            "outcome": if outcome["ok"] == true {"complete"} else {"refused"},
            "duration_ms": started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "signal": outcome["firstMissingSignal"].as_str().unwrap_or("none")}
    }));
}

// The single worker owns a bounded one-slot coalescing trigger. A trigger
// represents a fresh whole-roster observation, not a child-supplied authority.
static CHILD_BIND_SIGNAL: std::sync::OnceLock<tokio::sync::mpsc::Sender<()>> = std::sync::OnceLock::new();

pub(crate) fn signal_child_portals() {
    if !gateway_profile() { return; }
    let sender = CHILD_BIND_SIGNAL.get_or_init(|| {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            while receiver.recv().await.is_some() {
                let Ok(_permit) = MUTATIONS.acquire().await else { break; };
                let Ok(roster) = roster().await else { continue; };
                for child in roster["staves"].as_array().into_iter().flatten() {
                    let started = Instant::now();
                    if let Err((_, signal)) = bind_child_portals(child, &roster, false).await {
                        let id = child["mac"].as_str().unwrap_or("unknown-child");
                        record(id, "auto-bind", &json!({"ok":false,"firstMissingSignal":signal}), started);
                    }
                }
            }
        });
        sender
    });
    // Full means an already-queued whole-roster sweep will include this PUT.
    let _ = sender.try_send(());
}

// Caller holds MUTATIONS: accept already owns it, and the signal worker takes
// it once before its sweep. Authority is the gateway's current status, never
// the announcement, the child's registry, or Hestia membership.
async fn bind_child_portals(child: &Value, roster: &Value, dry_run: bool) -> Result<Vec<Value>, Failure> {
    if !gateway_profile() { return Ok(Vec::new()); }
    let ip = child["ipv4"].as_str().and_then(|v| v.parse::<std::net::Ipv4Addr>().ok())
        .ok_or_else(|| unavailable("link-up-child-address-unavailable"))?;
    if roster["seat"]["ipv4"].as_str() == Some(ip.to_string().as_str()) { return Ok(Vec::new()); }
    let mut status = house::portals().await?;
    let accepted = status["portals"].as_array().into_iter().flatten().any(|portal| {
        portal["lan_ip"].as_str().and_then(|v| v.parse::<std::net::Ipv4Addr>().ok()) == Some(ip)
    });
    if !accepted { return Ok(Vec::new()); }
    let listener = child["caduceus_port"].as_u64().and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n != 0).unwrap_or(8787);
    let entries = house::child_portals(ip, listener).await?;
    let mut results = Vec::new();
    for entry in entries {
        let Some(url) = entry.local_url.as_str().and_then(|s| s.strip_prefix("https://")) else { continue; };
        let name = url.strip_suffix('/').unwrap_or(url);
        if !name.ends_with(".home.arpa") || name.contains('/') { continue; }
        let Some(port) = entry.port.as_u64().and_then(|port| u16::try_from(port).ok()).filter(|port| *port != 0) else { continue; };
        let started = Instant::now();
        let upstream = format!("http://{ip}:{port}");
        if status["portals"].as_array().into_iter().flatten().any(|p| p["fqdn"] == name && p["upstream"] == upstream) {
            continue;
        }
        let candidate = json!({"from":{"ipv4":ip.to_string()}, "upstream":upstream});
        let names = vec![name.to_owned()];
        let validation = if house::valid_name(name) {
            let names = names.clone();
            let roster = roster.clone();
            let status = status.clone();
            tokio::task::spawn_blocking(move || house::validate_names(&names, &candidate, &roster, &status))
                .await.map_err(|_| unavailable("link-up-name-observation-failed"))?
        } else { Err((StatusCode::BAD_REQUEST, "link-up-name-invalid")) };
        if let Err((_, signal)) = validation {
            let result = json!({"portal":name,"ok":false,"firstMissingSignal":signal});
            record(name, "auto-bind", &result, started);
            results.push(result);
            continue;
        }
        let args = vec!["portal-admit".to_owned(), name.to_owned(), ip.to_string(), upstream];
        if dry_run {
            let mut argv = vec!["caduceus".to_owned(), "cert".to_owned()];
            argv.extend(args);
            results.push(json!({"portal":name,"ok":true,"attempted":false,"argv":argv}));
            continue;
        }
        let result = match house::admit(args).await {
            Ok(value) if value["ok"] == true && value["converged"] != false => json!({"portal":name,"ok":true}),
            Ok(value) => json!({"portal":name,"ok":false,"firstMissingSignal":value["firstMissingSignal"].as_str().unwrap_or("link-up-portal-admit-incomplete")}),
            Err((_, signal)) => json!({"portal":name,"ok":false,"firstMissingSignal":signal}),
        };
        record(name, "auto-bind", &result, started);
        let succeeded = result["ok"] == true;
        results.push(result);
        if succeeded {
            match house::portals().await {
                Ok(current) => status = current,
                Err((_, signal)) => {
                    let failure = json!({"portal":name,"ok":false,"firstMissingSignal":signal});
                    record(name, "auto-bind-refresh", &failure, started);
                    results.push(failure);
                    break;
                }
            }
        }
    }
    Ok(results)
}

// Only identities are kept. The live reader is pending(); accepted/dropped
// announcements are deleted on the next mutation, never during a GET.
fn dismissal(id: &str, dismiss: bool) -> Result<(), Failure> {
    let mut db = crate::stats::open_db()
        .map_err(|_| unavailable("link-up-state-unavailable"))?
        .lock()
        .map_err(|_| unavailable("link-up-state-unavailable"))?;
    let tx = db
        .transaction()
        .map_err(|_| unavailable("link-up-state-unavailable"))?;
    tx.execute_batch("CREATE TABLE IF NOT EXISTS notification_dismissals (id TEXT PRIMARY KEY);")
        .map_err(|_| unavailable("link-up-state-unavailable"))?;
    tx.execute("DELETE FROM notification_dismissals WHERE NOT EXISTS (SELECT 1 FROM ruyi, json_each(ruyi.row, '$.services') AS service WHERE json_extract(service.value, '$.kind')='face' AND notification_dismissals.id='link-up:' || lower(ruyi.mac) || ':' || json_extract(service.value, '$.port'))", [])
        .map_err(|_| unavailable("link-up-state-unavailable"))?;
    if dismiss {
        tx.execute(
            "INSERT OR IGNORE INTO notification_dismissals(id) VALUES(?1)",
            [id],
        )
    } else {
        tx.execute("DELETE FROM notification_dismissals WHERE id=?1", [id])
    }
    .map_err(|_| unavailable("link-up-state-unavailable"))?;
    tx.commit()
        .map_err(|_| unavailable("link-up-state-unavailable"))
}

async fn mutate(
    id: String,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
    dismiss: bool,
) -> Response {
    let started = Instant::now();
    let verb = if dismiss { "dismiss" } else { "accept" };
    let deed_id = id.clone();
    let result: Result<Value, Failure> = async {
        if !gateway_profile() {
            // There is no peer-pinned HTTP credential path in this source.
            return Err((StatusCode::FORBIDDEN, "link-up-accept-on-homeserver"));
        }
        admin(&headers)?;
        let _permit = MUTATIONS
            .try_acquire()
            .map_err(|_| unavailable("link-up-busy"))?;
        let Json(body) = body.map_err(|_| (StatusCode::BAD_REQUEST, "link-up-request-invalid"))?;
        if body
            .get("schema")
            .is_some_and(|schema| !schema.is_null() && schema.as_str() != Some(SCHEMA))
        {
            return Err((StatusCode::BAD_REQUEST, "link-up-schema-desync"));
        }
        let roster = roster().await?;
        let candidate = candidates(&roster)
            .into_iter()
            .find(|candidate| candidate["id"] == id)
            .ok_or((StatusCode::NOT_FOUND, "link-up-notification-absent"))?;
        if dismiss {
            let stored_id = id.clone();
            tokio::task::spawn_blocking(move || dismissal(&stored_id, true))
                .await
                .map_err(|_| unavailable("link-up-state-unavailable"))??;
            return Ok(json!({"schema": SCHEMA, "ok": true, "id": id, "state": "dismissed"}));
        }
        let names = names(&body, &candidate)?;
        let portals = house::portals().await?;
        let owned_names = names.clone();
        let owned_candidate = candidate.clone();
        let validation_roster = roster.clone();
        tokio::task::spawn_blocking(move || {
            house::validate_names(&owned_names, &owned_candidate, &validation_roster, &portals)
        })
        .await
        .map_err(|_| unavailable("link-up-name-observation-failed"))??;
        let mut args = vec![
            "portal-admit".to_owned(),
            names[0].clone(),
            candidate["from"]["ipv4"].as_str().unwrap().to_owned(),
            candidate["upstream"].as_str().unwrap().to_owned(),
        ];
        if names.len() > 1 {
            args.extend(["--aliases".to_owned(), names[1..].join(",")]);
        }
        if body["dry_run"] == true {
            let mut argv = vec!["caduceus".to_owned(), "cert".to_owned()];
            argv.extend(args);
            let child = roster["staves"].as_array().into_iter().flatten()
                .find(|row| row["mac"] == candidate["from"]["mac"] && row["ipv4"] == candidate["from"]["ipv4"]);
            let child_portals = match child {
                Some(child) => match bind_child_portals(child, &roster, true).await {
                    Ok(results) => json!(results),
                    Err((_, signal)) => json!([{"ok":false,"firstMissingSignal":signal}]),
                },
                None => json!([]),
            };
            return Ok(
                json!({"schema": SCHEMA, "ok": true, "dry_run": true, "attempted": false,
                "portal": names[0], "names": names, "argv": argv, "child_portals": child_portals}),
            );
        }
        let mut receipt = house::admit(args).await?;
        // Preserve every staff receipt field. A failed composite is never called
        // accepted, and a pending dismissal is cleared only after full success.
        if receipt.get("converged").is_some_and(|v| v == false) && receipt["ok"] == true {
            return Ok(json!({"schema": SCHEMA, "ok": false,
                "firstMissingSignal": "link-up-portal-admit-incomplete", "staff": receipt}));
        }
        if receipt["ok"] != true {
            return Ok(receipt);
        }
        let child = roster["staves"].as_array().into_iter().flatten()
            .find(|row| row["mac"] == candidate["from"]["mac"] && row["ipv4"] == candidate["from"]["ipv4"]);
        receipt["child_portals"] = match child {
            Some(child) => match bind_child_portals(child, &roster, false).await {
                Ok(results) => json!(results),
                Err((_, signal)) => json!([{"ok":false,"firstMissingSignal":signal}]),
            },
            None => json!([]),
        };
        tokio::task::spawn_blocking(move || dismissal(&id, false))
            .await
            .map_err(|_| unavailable("link-up-state-unavailable"))??;
        receipt["portal"] = json!(names[0]);
        receipt["names"] = json!(names);
        Ok(receipt)
    }
    .await;
    match result {
        Ok(value) => {
            record(&deed_id, verb, &value, started);
            let status = if value["ok"] == true {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            (status, Json(value)).into_response()
        }
        Err(failure) => {
            record(
                &deed_id,
                verb,
                &json!({"ok": false, "firstMissingSignal": failure.1}),
                started,
            );
            refusal(failure)
        }
    }
}

async fn accept(
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Result<Json<Value>, JsonRejection>,
) -> Response {
    mutate(id, headers, body, false).await
}

async fn dismiss(
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    mutate(id, headers, Ok(body.unwrap_or(Json(Value::Null))), true).await
}

pub fn register(router: Router) -> Router {
    let _ = crate::routes::leaf_schema::declaration(SCHEMA).expect("link-up-schema-desync");
    router
        .route("/api/v1/notifications", axum::routing::get(list))
        .route(
            "/api/v1/notifications/:id/accept",
            axum::routing::post(accept),
        )
        .route(
            "/api/v1/notifications/:id/dismiss",
            axum::routing::post(dismiss),
        )
}
