//! The HomeServer's bounded, sequential backup night.
use serde_json::{json, Value};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

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
    if remaining(deadline).is_zero() { return Err("no-report".into()); }
    let name = inlet.filter(|s| !s.is_empty()).ok_or("pin-inlet-missing")?;
    let mut crossing = crate::gate::snake::crossing_path_with_timeout("storage/backup/pin-inlet/export", &json!({"name":name}), remaining(deadline).min(Duration::from_secs(30)))
        .map_err(|_| "pin-inlet-missing".to_owned())?;
    if crossing["ok"] != true { return Err("pin-inlet-missing".into()); }
    let mut result = crossing.as_object_mut().and_then(|v|v.remove("receiptPayload")).ok_or("pin-inlet-missing")?;
    drop(crossing);
    if result["ok"] != true || result["username"].as_str() != Some(mac) { return Err("pin-inlet-missing".into()); }
    let pin = result.as_object_mut().and_then(|o| o.remove("password")).and_then(|v| match v { Value::String(s) => Some(s), _ => None })
        .filter(|s| !s.is_empty()).ok_or("pin-inlet-missing")?;
    drop(result);
    // This owned buffer is wiped even if runtime construction or the act fails.
    struct Secret(Vec<u8>);
    impl Drop for Secret { fn drop(&mut self) { for byte in &mut self.0 { unsafe { std::ptr::write_volatile(byte, 0) }; } std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst); } }
    let pin = Secret(pin.into_bytes());
    let text = std::str::from_utf8(&pin.0).map_err(|_| "pin-inlet-missing".to_owned())?;
    let seen = pair::report_counter(mac).map_err(|_| "backup-pair-unavailable".to_owned())?;
    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().min(i64::MAX as u64) as i64;
    let left = remaining(deadline);
    if left.is_zero() { return Err("no-report".into()); }
    let request = json!({"schema":crate::routes::leaf_schema::row_schema(),"target":mac,"thing":"backup-pull","flags":{"exousia":{"pin":text}}});
    let bytes = serde_json::to_vec(&request).map_err(|_| "road-act-failed".to_owned())?;
    drop(request);
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| "road-act-failed".to_owned())?;
    let act_started = Instant::now();
    let answer = runtime.block_on(async { tokio::time::timeout(left, crate::routes::leaf_ruyi::road::post(bytes.into())).await });
    let queued = match answer {
        Ok(Ok((_, axum::Json(value)))) => {
            let entry = &value["answers"][0];
            if entry["signal"].is_null() && entry.pointer("/answer/answers/0/answer/state").and_then(Value::as_str) == Some("Queued") { Ok(()) }
            else { Err(signal(entry.get("signal").and_then(Value::as_str), "road-act-failed", Some(text))) }
        },
        _ => Err("road-act-failed".into()),
    };
    drop(pin);
    queued?;
    match pair::wait_report(mac, seen, start, act_started, deadline).map_err(|_| "backup-pair-unavailable".to_owned())? {
        Some(report) if report.outcome == "ok" => Ok(()),
        Some(report) => Err(signal(Some(&report.signal), "backup-pull-failed", None)),
        None => Err("no-report".into()),
    }
}

#[cfg(all(leaf_storage_backup_pair, leaf_ruyi))]
pub(super) fn boxes(deadline: Instant) -> Result<bool, String> {
    let pairs = crate::routes::leaf_storage_backup_pair::conductor_pairs().map_err(|_| "backup-pair-unavailable".to_owned())?;
    let mut rows = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let started = Instant::now();
        let result = pull(&pair.mac, pair.inlet_name.as_deref(), deadline);
        rows.push((pair,result,started.elapsed()));
    }
    let mut all = true;
    for (pair,result,duration) in rows {
        let miss = result.as_ref().err().map(String::as_str);
        if miss.is_some() { all = false; }
        tell(&pair.mac, &pair.hostname, miss);
        let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
            "organ":"backup-conduct", "kind":"deed", "ok":miss.is_none(), "message":"backup box conduct",
            "attributes_redacted":{"who":"caduceus","verb":"conduct-box","target":pair.mac,"mac":pair.mac,"hostname":pair.hostname,
                "outcome":if miss.is_none(){"ok"}else{"failed"},"signal":miss.unwrap_or("none"),"duration_ms":duration.as_millis().min(u64::MAX as u128) as u64}
        }));
    }
    Ok(all)
}

#[cfg(not(all(leaf_storage_backup_pair, leaf_ruyi)))]
pub(super) fn boxes(_deadline: Instant) -> Result<bool, String> { Err("backup-pair-unavailable".into()) }

#[cfg(all(leaf_storage_backup_pair, leaf_ruyi, leaf_notifications))]
fn tell(mac: &str, hostname: &str, miss: Option<&str>) {
    let id = format!("backup-box-missed:{mac}");
    if let Some(reason) = miss {
        // Bound the encoded row even for a pathological externally supplied hostname.
        let name: String = hostname.chars().take(80).filter(|c| !c.is_control()).collect();
        let envelope = json!({"repost":true,"notification":{"id":id,"kind":"backup-box-missed","color":"amber",
            "title":format!("{name}'s backup drive missed last night's copy"),"body":format!("Backup signal: {reason}"),
            "actions":[{"label":"Dismiss","verb":"dismiss"}]}});
        crate::routes::leaf_notifications::post_update_check(envelope);
    } else {
        crate::routes::leaf_notifications::clear_update_check(json!({"clear":true,"notification":{"id":id,"kind":"backup-box-missed"}}));
    }
}
#[cfg(all(leaf_storage_backup_pair, leaf_ruyi, not(leaf_notifications)))]
fn tell(_mac: &str, _hostname: &str, _miss: Option<&str>) {}
