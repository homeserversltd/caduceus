use crate::gate::{blocking_task, snake};
use crate::shared::{hyalos::LogFilters, policy};
use axum::{http::StatusCode, routing::get, Json, Router};
use serde_json::{json, Value};
use std::{sync::LazyLock, time::Duration};

const COMMAND: &str = "storage backup drive card";
const STOP: &str = "storage/backup/drive/card";
static DECLARATION: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("index.json")).expect("backup drive card declaration")
});

fn last_copy() -> Option<Value> {
    let mut before = None;
    for _ in 0..10 {
        let (rows, next) = LogFilters::read_backup_page(before, 200).ok()?;
        for row in rows {
            if row["verb"].as_str() != Some("mirror-pull") || row["target"].as_str() != Some("nas-sync") {
                continue;
            }
            let at = row["at"].as_str()?;
            let timestamp = chrono::DateTime::parse_from_rfc3339(at).ok()?;
            if timestamp.offset().local_minus_utc() != 0 { return None; }
            let outcome = row["outcome"].as_str()?;
            if !matches!(outcome, "ok" | "failed" | "refused") { return None; }
            let signal = row["signal"].as_str()?;
            if !(1..=40).contains(&signal.len()) || !signal.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') { return None; }
            let duration = row["duration_ms"].as_u64()?;
            return Some(json!({"at": at, "outcome": outcome, "signal": signal, "durationMs": duration}));
        }
        before = next.and_then(|n| u64::try_from(n).ok());
        before?;
    }
    None
}

fn unavailable() -> Value {
    json!({"schema": DECLARATION["receipt"], "stop": {"noun": "storage/backup/drive", "verb": "card"},
        "ok": false, "box": null, "present": false, "model": null, "sizeBytes": null,
        "usedBytes": null, "freeBytes": null, "health": "unknown", "readErrors": null,
        "transport": null, "lastCopy": null, "firstMissingSignal": "backup-drive-card-unavailable",
        "observed": null, "could_change_to": null, "attempt": {"attempted": true},
        "final_receipt": {"ok": false, "firstMissingSignal": "backup-drive-card-unavailable"}})
}

fn read_card() -> Value {
    let crossing = match crate::shared::config::resolved_profile().as_deref() {
        Ok("homeconsole" | "hometv" | "homesi" | "specula") =>
            snake::crossing_path_with_timeout(STOP, &json!({}), Duration::from_secs(60)).ok(),
        _ => None,
    };
    let mut card = crossing.and_then(|v| {
        if v["ok"].as_bool() != Some(true) { return None; }
        let mut receipt = v.get("receiptPayload")?.clone();
        if receipt["ok"].as_bool() != Some(true) || !crate::routes::leaf_schema::bound(&receipt, STOP) { return None; }
        if let (Some(object), Some(band)) = (receipt.as_object_mut(), v.get("bandPath")) {
            object.entry("bandPath").or_insert_with(|| band.clone());
        }
        Some(receipt)
    }).unwrap_or_else(unavailable);
    card["lastCopy"] = last_copy().unwrap_or(Value::Null);
    card
}

async fn http() -> (StatusCode, Json<Value>) {
    if crate::gate::admittance::check_declared_admittance(&DECLARATION).is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(unavailable()));
    }
    match policy::allows_command(COMMAND) {
        Ok(true) => {},
        Ok(false) => return (StatusCode::FORBIDDEN, Json(unavailable())),
        Err(_) => return (StatusCode::FORBIDDEN, Json(unavailable())),
    }
    match blocking_task(COMMAND, read_card).await {
        Ok(card) => (StatusCode::OK, Json(card)),
        Err(_) => (StatusCode::OK, Json(unavailable())),
    }
}

pub fn register(router: Router) -> Router {
    router.route(LEAF_STORAGE_BACKUP_DRIVE_CARD_CANONICAL, get(http))
}
