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
use std::{collections::BTreeSet, time::{Duration, Instant}};
use tokio::sync::Semaphore;
use tower::ServiceExt;

#[path = "support/house.rs"]
mod house;
#[path = "support/ledger.rs"]
mod ledger;

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

pub(crate) fn record_stave_failure(stave: Option<&Value>, signal: &'static str) {
    let started = Instant::now();
    let rows = stave.map(|row| candidates(&json!({"staves":[row]}))).unwrap_or_default();
    let id = rows.first().and_then(|row| row["id"].as_str()).unwrap_or("unknown");
    record(id, "post", &json!({"ok":false,"firstMissingSignal":signal}), started);
}

pub(crate) async fn post_stave(stave: Value) -> Result<(), Failure> {
    if !gateway_profile() { return Ok(()); }
    let roster = json!({"staves":[stave]});
    let rows = candidates(&roster);
    if rows.is_empty() { return Ok(()); }
    let portals = house::portals(None).await?;
    for mut row in rows {
        let mac = row["from"]["mac"].as_str().unwrap_or("");
        let admitted = !mac.is_empty() && portals["portals"].as_array().is_some_and(|items| items.iter().any(|p| p["fqdn"] == row["names"][0] && p["origin"] == "face" && p["owner_mac"].as_str().is_some_and(|owner| owner.eq_ignore_ascii_case(mac))));
        row["color"] = json!("blue");
        row["ttl"] = json!("until-acted");
        row["actions"] = json!([{"verb":"accept","label":"Accept","fields":{"names":"list"}},{"verb":"dismiss","label":"Dismiss"}]);
        let id = row["id"].as_str().unwrap_or("").to_owned();
        tokio::task::spawn_blocking(move || ledger::post(row,false)).await.map_err(|_| unavailable("notification-state-unavailable"))??;
        if admitted { tokio::task::spawn_blocking(move || ledger::change(&id,"accepted")).await.map_err(|_| unavailable("notification-state-unavailable"))??; }
    }
    Ok(())
}

async fn list(headers: HeaderMap, uri: axum::http::Uri) -> Response {
    let Ok(_permit) = READS.try_acquire() else { return refusal(unavailable("link-up-busy")); };
    let all = uri.query().is_some_and(|q| q.split('&').any(|part| part == "all=1"));
    if !gateway_profile() {
        if all { return Json(json!({"schema":SCHEMA,"notifications":[],"gateway":"history-on-homeserver"})).into_response(); }
        return match house::gateway_notifications().await {
            Some(value) => Json(value).into_response(),
            None => Json(json!({"schema":SCHEMA,"notifications":[],"gateway":"unreachable"})).into_response(),
        };
    }
    if all { if let Err(error) = admin(&headers) { return refusal(error); } }
    match tokio::task::spawn_blocking(move || ledger::list(all)).await {
        Ok(Ok(notifications)) => Json(json!({"schema":SCHEMA,"notifications":notifications})).into_response(),
        Ok(Err(error)) => refusal(error),
        Err(_) => refusal(unavailable("notification-state-unavailable")),
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
        "message": "notification deed",
        "attributes_redacted": {"who": if verb == "post" || verb == "forward" {"lan"} else {"owner"}, "verb": verb, "target": "notification",
            "outcome": if outcome["ok"] == true {"complete"} else {"refused"},
            "duration_ms": started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "signal": outcome["firstMissingSignal"].as_str().unwrap_or("none")}
    }));
}

// The single worker owns a bounded one-slot coalescing trigger. A trigger
// represents a fresh whole-roster observation, not a child-supplied authority.
static CHILD_BIND_SIGNAL: std::sync::OnceLock<tokio::sync::mpsc::Sender<()>> = std::sync::OnceLock::new();
static FAILED_BINDS: std::sync::OnceLock<std::sync::Mutex<std::collections::BTreeMap<String, (String, String)>>> = std::sync::OnceLock::new();

fn failed_binds() -> &'static std::sync::Mutex<std::collections::BTreeMap<String, (String, String)>> {
    FAILED_BINDS.get_or_init(|| std::sync::Mutex::new(std::collections::BTreeMap::new()))
}

pub(crate) fn signal_child_portals() {
    if !gateway_profile() { return; }
    let sender = CHILD_BIND_SIGNAL.get_or_init(|| {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            while receiver.recv().await.is_some() {
                let Ok(_permit) = MUTATIONS.acquire().await else { break; };
                let deadline = Instant::now() + Duration::from_secs(150);
                let roster = match tokio::time::timeout_at(deadline.into(), roster()).await {
                    Ok(Ok(roster)) => roster,
                    Ok(Err(_)) => continue,
                    Err(_) => {
                        record("sweep", "auto-bind", &json!({"ok":false,"firstMissingSignal":"link-up-sweep-budget-exhausted"}), deadline - Duration::from_secs(150));
                        continue;
                    }
                };
                let live: BTreeSet<String> = roster["staves"].as_array().into_iter().flatten()
                    .filter_map(|child| child["mac"].as_str()).map(str::to_ascii_lowercase).collect();
                if let Ok(mut failed) = failed_binds().lock() { failed.retain(|_, (_, mac)| live.contains(mac)); }
                for child in roster["staves"].as_array().into_iter().flatten() {
                    let started = Instant::now();
                    let result = if Instant::now() >= deadline {
                        Err(unavailable("link-up-sweep-budget-exhausted"))
                    } else {
                        bind_child_portals(child, &roster, false, Some(deadline)).await.map(|_| ())
                    };
                    if let Err((_, signal)) = result {
                        let id = child["mac"].as_str().unwrap_or("unknown-child");
                        record(id, "auto-bind", &json!({"ok":false,"firstMissingSignal":signal}), started);
                        if signal == "link-up-sweep-budget-exhausted" { break; }
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
async fn bind_child_portals(child: &Value, roster: &Value, dry_run: bool, deadline: Option<Instant>) -> Result<Vec<Value>, Failure> {
    if deadline.is_some_and(|end| Instant::now() >= end) { return Err(unavailable("link-up-sweep-budget-exhausted")); }
    if !gateway_profile() { return Ok(Vec::new()); }
    let ip = child["ipv4"].as_str().and_then(|v| v.parse::<std::net::Ipv4Addr>().ok())
        .ok_or_else(|| unavailable("link-up-child-address-unavailable"))?;
    let mac = child["mac"].as_str().filter(|s| !s.is_empty())
        .ok_or_else(|| unavailable("link-up-child-mac-unavailable"))?.to_ascii_lowercase();
    if roster["seat"]["ipv4"].as_str() == Some(ip.to_string().as_str()) { return Ok(Vec::new()); }
    let mut status = house::portals(deadline).await?;
    if deadline.is_some_and(|end| Instant::now() >= end) { return Err(unavailable("link-up-sweep-budget-exhausted")); }
    let accepted = status["portals"].as_array().into_iter().flatten().any(|portal| {
        portal["origin"] == "face" && portal["owner_mac"].as_str().is_some_and(|owner| owner.eq_ignore_ascii_case(&mac))
    });
    if !accepted { return Ok(Vec::new()); }
    let listener = child["caduceus_port"].as_u64().and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n != 0).unwrap_or(8787);
    let entries = if let Some(end) = deadline {
        tokio::time::timeout_at(end.into(), house::child_portals(ip, listener)).await
            .map_err(|_| unavailable("link-up-sweep-budget-exhausted"))??
    } else {
        house::child_portals(ip, listener).await?
    };
    let mut results = Vec::new();
    // Snapshot names before rejecting invalid ports or other malformed entries.
    let declared: BTreeSet<String> = entries.iter().filter_map(|entry| entry.local_url.as_str())
        .filter_map(|url| url.split_once("://").map(|(_, host)| host))
        .filter_map(|host| host.split(['/', '?', '#', ':']).next())
        .map(str::to_ascii_lowercase).collect();
    let safe_to_retire = !entries.is_empty() && entries.iter().all(|entry| {
        entry.local_url.as_str().is_some_and(|url| {
            url.starts_with('/') || url.split_once("://")
                .and_then(|(_, host)| host.split(['/', '?', '#', ':']).next())
                .is_some_and(|host| house::valid_name(&host.to_ascii_lowercase()))
        })
    });
    if !dry_run && safe_to_retire {
        let mut failed = failed_binds().lock().map_err(|_| unavailable("link-up-bind-memory-unavailable"))?;
        failed.retain(|name, (_, owner)| owner != &mac || declared.contains(name));
    }
    for entry in entries {
        if deadline.is_some_and(|end| Instant::now() >= end) { return Err(unavailable("link-up-sweep-budget-exhausted")); }
        let Some(url) = entry.local_url.as_str().and_then(|s| s.strip_prefix("https://")) else { continue; };
        let name = url.strip_suffix('/').unwrap_or(url);
        if !name.ends_with(".home.arpa") || name.contains('/') { continue; }
        let Some(port) = entry.port.as_u64().and_then(|port| u16::try_from(port).ok()).filter(|port| *port != 0) else { continue; };
        let started = Instant::now();
        let upstream = format!("http://{ip}:{port}");
        let existing = status["portals"].as_array().into_iter().flatten().find(|p| p["fqdn"] == name);
        if existing.is_some_and(|p| p["origin"] == "face") { continue; }
        if existing.is_some_and(|p| p["upstream"] == upstream && p["lan_ip"] == ip.to_string() && p["owner_mac"].as_str().is_some_and(|owner| owner.eq_ignore_ascii_case(&mac))) {
            continue;
        }
        let aliases: Vec<String> = existing.and_then(|p| p["aliases"].as_array()).into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
        let candidate = json!({"from":{"ipv4":ip.to_string(),"mac":mac}, "upstream":upstream});
        let names = vec![name.to_owned()];
        let validation = if house::valid_name(name) {
            let names = names.clone();
            let roster = roster.clone();
            let status = status.clone();
            let task = tokio::task::spawn_blocking(move || house::validate_names(&names, &candidate, &roster, &status, false));
            if let Some(end) = deadline {
                tokio::time::timeout_at(end.into(), task).await
                    .map_err(|_| unavailable("link-up-sweep-budget-exhausted"))?
                    .map_err(|_| unavailable("link-up-name-observation-failed"))?
            } else {
                task.await.map_err(|_| unavailable("link-up-name-observation-failed"))?
            }
        } else { Err((StatusCode::BAD_REQUEST, "link-up-name-invalid")) };
        if let Err((_, signal)) = validation {
            let result = json!({"portal":name,"ok":false,"firstMissingSignal":signal});
            record(name, "auto-bind", &result, started);
            results.push(result);
            continue;
        }
        let portal = name.to_owned();
        let lan_ip = ip.to_string();
        if dry_run {
            let mut argv = vec!["caduceus".to_owned(), "cert".to_owned()];
            argv.extend(["portal-admit".to_owned(), portal.clone(), lan_ip.clone(), upstream.clone()]);
            if !aliases.is_empty() { argv.extend(["--aliases".to_owned(), aliases.join(",")]); }
            argv.extend(["--owner-mac".to_owned(), mac.clone(), "--origin".to_owned(), "tile".to_owned(), "--dry-run".to_owned()]);
            results.push(json!({"portal":name,"ok":true,"attempted":false,"argv":argv}));
            continue;
        }
        let pair = (upstream.clone(), mac.clone());
        if failed_binds().lock().map_err(|_| unavailable("link-up-bind-memory-unavailable"))?.get(name) == Some(&pair) { continue; }
        let result = match house::admit(portal, lan_ip, upstream, aliases, mac.clone(), "tile", Vec::new(), deadline).await {
            Ok(value) if deadline.is_some() && matches!(value["firstMissingSignal"].as_str(), Some("caduceus-agathodaimon-timeout" | "link-up-sweep-budget-exhausted")) => {
                if value["firstMissingSignal"] == "caduceus-agathodaimon-timeout" {
                    failed_binds().lock().map_err(|_| unavailable("link-up-bind-memory-unavailable"))?.insert(name.to_owned(), pair.clone());
                }
                return Err(unavailable("link-up-sweep-budget-exhausted"));
            }
            Err((_, signal @ ("caduceus-agathodaimon-timeout" | "link-up-sweep-budget-exhausted"))) if deadline.is_some() => {
                if signal == "caduceus-agathodaimon-timeout" {
                    failed_binds().lock().map_err(|_| unavailable("link-up-bind-memory-unavailable"))?.insert(name.to_owned(), pair.clone());
                }
                return Err(unavailable("link-up-sweep-budget-exhausted"));
            }
            Ok(value) if value["ok"] == true && value["converged"] != false => json!({"portal":name,"ok":true}),
            Ok(value) => json!({"portal":name,"ok":false,"firstMissingSignal":value["firstMissingSignal"].as_str().unwrap_or("link-up-portal-admit-incomplete")}),
            Err((_, signal)) => json!({"portal":name,"ok":false,"firstMissingSignal":signal}),
        };
        record(name, "auto-bind", &result, started);
        let succeeded = result["ok"] == true;
        {
            let mut failed = failed_binds().lock().map_err(|_| unavailable("link-up-bind-memory-unavailable"))?;
            if succeeded { failed.remove(name); } else { failed.insert(name.to_owned(), pair); }
        }
        results.push(result);
        if succeeded {
            match house::portals(deadline).await {
                Ok(current) => status = current,
                Err((_, "link-up-sweep-budget-exhausted")) if deadline.is_some() => {
                    return Err(unavailable("link-up-sweep-budget-exhausted"));
                }
                Err((_, signal)) => {
                    let failure = json!({"portal":name,"ok":false,"firstMissingSignal":signal});
                    record(name, "auto-bind-refresh", &failure, started);
                    results.push(failure);
                    break;
                }
            }
        }
    }
    if deadline.is_some_and(|end| Instant::now() >= end) { return Err(unavailable("link-up-sweep-budget-exhausted")); }
    if safe_to_retire {
        for portal in status["portals"].as_array().into_iter().flatten() {
            if deadline.is_some_and(|end| Instant::now() >= end) { return Err(unavailable("link-up-sweep-budget-exhausted")); }
            let Some(name) = portal["fqdn"].as_str() else { continue; };
            if portal["origin"] != "tile" || !portal["owner_mac"].as_str().is_some_and(|owner| owner.eq_ignore_ascii_case(&mac)) || declared.contains(name)
                || portal["lan_ip"].as_str().is_some_and(|address| roster["seat"]["ipv4"].as_str() == Some(address)) { continue; }
            if dry_run { results.push(json!({"portal":name,"ok":true,"attempted":false,"argv":["caduceus","cert","portal-retire","--dry-run",name,&mac]})); continue; }
            let started = Instant::now();
            let result = match house::retire(name.to_owned(), mac.clone(), deadline).await {
                Ok(value) if deadline.is_some() && matches!(value["firstMissingSignal"].as_str(), Some("caduceus-agathodaimon-timeout" | "link-up-sweep-budget-exhausted")) => {
                    return Err(unavailable("link-up-sweep-budget-exhausted"));
                }
                Err((_, "caduceus-agathodaimon-timeout" | "link-up-sweep-budget-exhausted")) if deadline.is_some() => {
                    return Err(unavailable("link-up-sweep-budget-exhausted"));
                }
                Ok(value) => value,
                Err((_, signal)) => json!({"ok":false,"firstMissingSignal":signal}),
            };
            record(name, "auto-retire", &result, started);
            results.push(result);
        }
    }
    Ok(results)
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
        let candidate_id = id.clone();
        let candidate = tokio::task::spawn_blocking(move || ledger::get(&candidate_id)).await
            .map_err(|_| unavailable("notification-state-unavailable"))??;
        if candidate["state"] != "pending" { return Err((StatusCode::CONFLICT, "notification-not-pending")); }
        if candidate["kind"] != "house-link-up" { return Err((StatusCode::BAD_REQUEST, "notification-verb-unknown")); }
        let roster = roster().await?;
        if dismiss {
            let stored_id = id.clone();
            tokio::task::spawn_blocking(move || ledger::change(&stored_id, "dismissed"))
                .await.map_err(|_| unavailable("notification-state-unavailable"))??;
            return Ok(json!({"schema": SCHEMA, "ok": true, "id": id, "state": "dismissed"}));
        }
        let names = names(&body, &candidate)?;
        let portals = house::portals(None).await?;
        let owned_names = names.clone();
        let owned_candidate = candidate.clone();
        let validation_roster = roster.clone();
        tokio::task::spawn_blocking(move || {
            house::validate_names(&owned_names, &owned_candidate, &validation_roster, &portals, true)
        })
        .await
        .map_err(|_| unavailable("link-up-name-observation-failed"))??;
        let portal = names[0].clone();
        let lan_ip = candidate["from"]["ipv4"].as_str().unwrap().to_owned();
        let upstream = candidate["upstream"].as_str().unwrap().to_owned();
        let mac = candidate["from"]["mac"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| unavailable("link-up-child-mac-unavailable"))?.to_ascii_lowercase();
        let aliases = names[1..].to_vec();
        let child = roster["staves"].as_array().into_iter().flatten()
            .find(|row| row["mac"] == candidate["from"]["mac"] && row["ipv4"] == candidate["from"]["ipv4"]);
        let claim_tiles: Vec<String> = if let Some(child) = child {
            let listener = child["caduceus_port"].as_u64().and_then(|n| u16::try_from(n).ok()).filter(|n| *n != 0).unwrap_or(8787);
            let ip = lan_ip.parse::<std::net::Ipv4Addr>().map_err(|_| unavailable("link-up-child-address-unavailable"))?;
            house::child_portals(ip, listener).await.unwrap_or_default().iter().filter_map(|entry| entry.local_url.as_str())
                .filter_map(|url| url.strip_prefix("https://"))
                .map(|url| url.strip_suffix('/').unwrap_or(url))
                .filter(|name| house::valid_name(name)).map(str::to_owned).collect()
        } else { Vec::new() };
        if body["dry_run"] == true {
            let mut argv = vec!["caduceus".to_owned(), "cert".to_owned()];
            argv.extend(["portal-admit".to_owned(), portal.clone(), lan_ip.clone(), upstream.clone()]);
            if !aliases.is_empty() { argv.extend(["--aliases".to_owned(), aliases.join(",")]); }
            argv.extend(["--owner-mac".to_owned(), mac.clone(), "--origin".to_owned(), "face".to_owned(), "--dry-run".to_owned()]);
            if !claim_tiles.is_empty() { argv.extend(["--claim-tiles".to_owned(), claim_tiles.join(",")]); }
            let child_portals = match child {
                Some(child) => match bind_child_portals(child, &roster, true, None).await {
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
        failed_binds().lock().map_err(|_| unavailable("link-up-bind-memory-unavailable"))?.retain(|_, (_, owner)| owner != &mac);
        let mut receipt = house::admit(portal, lan_ip, upstream, aliases, mac, "face", claim_tiles, None).await?;
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
            Some(child) => match bind_child_portals(child, &roster, false, None).await {
                Ok(results) => json!(results),
                Err((_, signal)) => json!([{"ok":false,"firstMissingSignal":signal}]),
            },
            None => json!([]),
        };
        let accepted_id = id.clone();
        tokio::task::spawn_blocking(move || ledger::change(&id, "accepted"))
            .await
            .map_err(|_| unavailable("notification-state-unavailable"))??;
        Ok(json!({"schema":SCHEMA,"ok":true,"id":accepted_id,"state":"accepted","staff":receipt,"portal":names[0],"names":names}))
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
    if !gateway_profile() { return refusal((StatusCode::FORBIDDEN, if id.starts_with("link-up:") { "link-up-accept-on-homeserver" } else { "notification-act-on-homeserver" })); }
    if let Err(error) = admin(&headers) { return refusal(error); }
    let key = id.clone();
    match tokio::task::spawn_blocking(move || ledger::get(&key)).await {
        Ok(Ok(row)) if row["kind"] == "house-link-up" => mutate(id, headers, body, false).await,
        Ok(Ok(_)) => action(axum::extract::Path((id, "accept".to_owned())), headers, body.ok()).await,
        Ok(Err(error)) => refusal(error),
        Err(_) => refusal(unavailable("notification-state-unavailable")),
    }
}

async fn dismiss(
    axum::extract::Path(id): axum::extract::Path<String>,
    headers: HeaderMap,
    body: Option<Json<Value>>,
) -> Response {
    action(axum::extract::Path((id, "dismiss".to_owned())), headers, body).await
}

async fn receive_post(
    forward: bool,
    peer: Option<axum::extract::ConnectInfo<crate::gate::ConnectionInfo>>,
    bytes: axum::body::Bytes,
) -> Response {
    let started = Instant::now();
    let result: Result<Value, Failure> = async {
        if forward && !gateway_profile() { return Err((StatusCode::FORBIDDEN,"notification-forward-on-homeserver")); }
        if bytes.len() >= 1024 { return Err((StatusCode::BAD_REQUEST,"notification-row-invalid")); }
        let mut envelope: Value = serde_json::from_slice(&bytes).map_err(|_| (StatusCode::BAD_REQUEST,"notification-row-invalid"))?;
        let row = envelope.get_mut("notification").and_then(Value::as_object_mut).ok_or((StatusCode::BAD_REQUEST,"notification-row-invalid"))?;
        for key in ["id","kind","title"] { if !row.get(key).and_then(Value::as_str).is_some_and(|s| !s.is_empty()) { return Err((StatusCode::BAD_REQUEST,"notification-row-invalid")); } }
        if row.get("color").is_some_and(|v| !v.is_null() && !v.as_str().is_some_and(|s| ["red","amber","blue","none"].contains(&s))) { return Err((StatusCode::BAD_REQUEST,"notification-row-invalid")); }
        let ip = peer.and_then(|p| match p.0 { crate::gate::ConnectionInfo::Tcp(addr) => match addr.ip() { std::net::IpAddr::V4(ip) => Some(ip.to_string()), _ => None }, _ => None });
        if let Some(ip) = ip {
            row.insert("received_from".into(), json!(ip));
            if !ip.parse::<std::net::Ipv4Addr>().is_ok_and(|address| address.is_loopback()) {
                let from = row.entry("from").or_insert_with(|| json!({}));
                if !from.is_object() { *from = json!({}); }
                if let Some(object) = from.as_object_mut() { if !object.get("ipv4").and_then(Value::as_str).is_some() { object.insert("ipv4".into(),json!(ip)); } }
            }
        }
        if !gateway_profile() {
            let mut receipt = house::gateway_post(&envelope).await.ok_or(unavailable("notification-gateway-unreachable"))?;
            receipt["forwarded"] = json!(true);
            return Ok(receipt);
        }
        let repost = envelope["repost"] == true;
        let mut row = envelope["notification"].clone();
        if let Some(ip) = row["received_from"].as_str().filter(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok_and(|address| !address.is_loopback())) {
            let db = crate::stats::open_db().map_err(|_| unavailable("notification-state-unavailable"))?.lock().map_err(|_| unavailable("notification-state-unavailable"))?;
            use rusqlite::OptionalExtension;
            let mac: Option<String> = db.query_row("SELECT mac FROM ruyi WHERE json_extract(row,'$.ipv4')=?1 LIMIT 1",[ip],|r|r.get(0)).optional().map_err(|_| unavailable("notification-state-unavailable"))?;
            if let Some(mac) = mac { if let Some(from) = row["from"].as_object_mut() { from.insert("mac".into(),json!(mac)); } }
        }
        tokio::task::spawn_blocking(move || ledger::post(row,repost)).await.map_err(|_| unavailable("notification-state-unavailable"))?
    }.await;
    match result {
        Ok(value) => { record(value["id"].as_str().unwrap_or("unknown"), if forward {"forward"} else {"post"}, &value, started); Json(value).into_response() }
        Err(error) => { record("unknown",if forward {"forward"} else {"post"},&json!({"ok":false,"firstMissingSignal":error.1}),started); refusal(error) }
    }
}

async fn post(peer: Option<axum::extract::ConnectInfo<crate::gate::ConnectionInfo>>, bytes: axum::body::Bytes) -> Response { receive_post(false, peer, bytes).await }
async fn forward(peer: Option<axum::extract::ConnectInfo<crate::gate::ConnectionInfo>>, bytes: axum::body::Bytes) -> Response { receive_post(true, peer, bytes).await }

// The check runs on a blocking worker, so enter the same local post path as
// HTTP without calling the live listener or bypassing peer forwarding.
pub(crate) fn post_update_check(envelope: Value) {
    match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => {
            let bytes = axum::body::Bytes::from(envelope.to_string());
            let _ = runtime.block_on(receive_post(false, None, bytes));
        }
        Err(_) => record("update-available", "post", &json!({"ok":false,"firstMissingSignal":"notification-runtime-unavailable"}), Instant::now()),
    }
}

async fn action(axum::extract::Path((id,verb)): axum::extract::Path<(String,String)>, headers: HeaderMap, body: Option<Json<Value>>) -> Response {
    if !gateway_profile() { return refusal((StatusCode::FORBIDDEN, if verb == "accept" && id.starts_with("link-up:") {"link-up-accept-on-homeserver"} else {"notification-act-on-homeserver"})); }
    if let Err(error) = admin(&headers) { return refusal(error); }
    let Ok(_permit) = MUTATIONS.try_acquire() else { return refusal(unavailable("link-up-busy")); };
    let started = Instant::now();
    let result: Result<Value,Failure> = async {
        let row_id = id.clone();
        let row = tokio::task::spawn_blocking(move || ledger::get(&row_id)).await.map_err(|_| unavailable("notification-state-unavailable"))??;
        if row["state"] != "pending" { return Err((StatusCode::CONFLICT, "notification-not-pending")); }
        if verb != "dismiss" && !row["actions"].as_array().is_some_and(|actions| actions.iter().any(|a| a["verb"] == verb)) { return Err((StatusCode::BAD_REQUEST,"notification-verb-unknown")); }
        if verb == "accept" && row["kind"] == "house-link-up" { return Err((StatusCode::BAD_REQUEST,"notification-verb-unknown")); }
        let state = if verb == "dismiss" { "dismissed".to_owned() } else {
            if crate::shared::policy::allows_command("notify act").ok() != Some(true) { return Err((StatusCode::FORBIDDEN,"notification-staff-forbidden")); }
            let input = json!({"id":id,"verb":verb,"fields":body.map(|b|b.0).unwrap_or_else(||json!({})),"row":row});
            let staff = crate::gate::blocking_task("notify act", move || crate::shared::agathodaimon::crossing_value_preserving_receipt("notify","act",&input,false)).await.map_err(|_| unavailable("notification-staff-unavailable"))?.unwrap_or_else(|v|v);
            if staff["ok"] != true { return Ok(json!({"schema":SCHEMA,"ok":false,"id":id,"state":row["state"],"staff":staff})); }
            let state = staff["state_after"].as_str().unwrap_or("pending").to_owned();
            let key = id.clone(); let next = state.clone();
            tokio::task::spawn_blocking(move || ledger::change(&key,&next)).await.map_err(|_| unavailable("notification-state-unavailable"))??;
            return Ok(json!({"schema":SCHEMA,"ok":true,"id":id,"state":state,"staff":staff}));
        };
        let key = id.clone(); let next = state.clone();
        tokio::task::spawn_blocking(move || ledger::change(&key,&next)).await.map_err(|_| unavailable("notification-state-unavailable"))??;
        Ok(json!({"schema":SCHEMA,"ok":true,"id":id,"state":state}))
    }.await;
    match result { Ok(value) => { record(&id,&verb,&value,started); Json(value).into_response() }, Err(error) => { record(&id,&verb,&json!({"ok":false,"firstMissingSignal":error.1}),started); refusal(error) } }
}

pub fn register(router: Router) -> Router {
    let _ = crate::routes::leaf_schema::declaration(SCHEMA).expect("link-up-schema-desync");
    if gateway_profile() { let _ = ledger::initialize(); }
    router
        .route("/api/v1/notifications", axum::routing::get(list).post(post))
        .route("/api/v1/notifications/forward", axum::routing::post(forward))
        .route("/api/v1/notifications/:id/:verb", axum::routing::post(action))
        .route(
            "/api/v1/notifications/:id/accept",
            axum::routing::post(accept),
        )
        .route(
            "/api/v1/notifications/:id/dismiss",
            axum::routing::post(dismiss),
        )
}
