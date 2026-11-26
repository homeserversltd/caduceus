//! The HomeServer's bounded, sequential backup night.
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn remaining(deadline: Instant) -> Duration { deadline.saturating_duration_since(Instant::now()) }

// External diagnostics are projected to a bounded signal, never an error body.
fn signal(value: Option<&str>, fallback: &'static str, secret: Option<&str>) -> String {
    value.filter(|s| (1..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && *s != "none" && !secret.is_some_and(|pin| !pin.is_empty() && s.contains(pin)))
        .unwrap_or(fallback).to_owned()
}

pub(super) fn export(deadline: Instant) -> Option<String> {
    let left = remaining(deadline);
    if left.is_zero() { return Some("no-time-remaining".into()); }
    match crate::gate::snake::schedule_crossing("storage/backup/forgejo/nas-export", &json!({"wait":true}), left) {
        Ok(answer) => {
            let payload = answer.get("receiptPayload").unwrap_or(&Value::Null);
            if answer["ok"] == true && payload["ok"] == true && payload["status"] == "done" { None }
            else { Some(signal(payload.get("firstMissingSignal").and_then(Value::as_str), "forgejo-nas-export-run-failed", None)) }
        }
        Err(_) => Some("forgejo-nas-export-run-failed".into()),
    }
}

#[cfg(all(leaf_storage_backup_pair, leaf_ruyi))]
fn pull(mac: &str, inlet: Option<&str>, deadline: Instant) -> Result<(), String> {
    use crate::routes::leaf_storage_backup_pair as pair;
    let (seen, start, act_started) = pair::queue_pull(mac, inlet, deadline)?;
    match pair::wait_report(mac, seen, start, act_started, deadline).map_err(|_| "backup-pair-unavailable".to_owned())? {
        Some(report) if report.outcome == "ok" => Ok(()),
        Some(report) => Err(report.signal),
        None => Err("no-report".into()),
    }
}

#[cfg(all(leaf_storage_backup_pair, leaf_ruyi))]
pub(super) fn boxes(deadline: Instant) -> Result<Option<String>, String> {
    let pairs = crate::routes::leaf_storage_backup_pair::conductor_pairs().map_err(|_| "backup-pair-unavailable".to_owned())?;
    let mut rows = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let started = Instant::now();
        let result = pull(&pair.mac, pair.inlet_name.as_deref(), deadline);
        rows.push((pair,result,started.elapsed()));
    }
    let mut first_missed = None;
    for (pair,result,duration) in rows {
        let miss = result.as_ref().err().map(String::as_str);
        if miss.is_some() && first_missed.is_none() { first_missed = Some(pair.mac.clone()); }
        let notified = tell(&pair.mac, &pair.hostname, miss);
        let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
            "organ":"backup-conduct", "kind":"deed", "ok":miss.is_none(), "message":"backup box conduct",
            "attributes_redacted":{"who":"caduceus","verb":"conduct-box","target":pair.mac,"mac":pair.mac,"hostname":pair.hostname,
                "outcome":if miss.is_none(){"ok"}else{"failed"},"signal":miss.unwrap_or("none"),"notification":if notified {"ok"} else {"failed"},"duration_ms":duration.as_millis().min(u64::MAX as u128) as u64}
        }));
    }
    Ok(first_missed)
}

#[cfg(not(all(leaf_storage_backup_pair, leaf_ruyi)))]
pub(super) fn boxes(_deadline: Instant) -> Result<Option<String>, String> { Err("backup-pair-unavailable".into()) }

#[cfg(all(leaf_storage_backup_pair, leaf_ruyi, leaf_notifications))]
fn tell(mac: &str, hostname: &str, miss: Option<&str>) -> bool {
    let id = format!("backup-box-missed:{mac}");
    if let Some(reason) = miss {
        // Bound the encoded row even for a pathological externally supplied hostname.
        let name: String = hostname.chars().take(80).filter(|c| !c.is_control()).collect();
        let envelope = json!({"repost":true,"notification":{"id":id,"kind":"backup-box-missed","color":"amber",
            "title":format!("{name}'s backup drive missed last night's copy"),"body":format!("Backup signal: {reason}"),
            "actions":[{"label":"Dismiss","verb":"dismiss"}],
            "act":{"verb":"copy-now","label":"Copy now","target":{"mac":mac,"hostname":name}}}});
        crate::routes::leaf_notifications::post_update_check(envelope)
    } else {
        crate::routes::leaf_notifications::clear_update_check(json!({"clear":true,"notification":{"id":id,"kind":"backup-box-missed"}}))
    }
}
#[cfg(all(leaf_storage_backup_pair, leaf_ruyi, not(leaf_notifications)))]
fn tell(_mac: &str, _hostname: &str, _miss: Option<&str>) -> bool { false }
