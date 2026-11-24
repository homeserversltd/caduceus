use super::*;
use axum::extract::Query;

// The returned address is the one that answered both identity requests. It is
// deliberately not replaced with a DNS name between proof and the thing read.
pub(super) async fn prove_stave(row: &RuyiRow, deadline: Instant) -> Result<(String, u16), &'static str> {
    let host = row.ipv4.clone();
    if host.parse::<Ipv4Addr>().is_err() {
        return Err("unreachable");
    }
    let port = row.caduceus_port.unwrap_or_else(peer_probe_port);
    let beam = timeout_at(deadline, fetch_peer(&host, port, PEER_BEAM_PATH))
        .await.map_err(|_| "timeout")?.map_err(|_| "unreachable")?;
    if !valid_peer_beam(&beam) {
        return Err("unreachable");
    }
    let path = "/api/v1/ruyi?seat=1";
    let response = timeout_at(deadline, fetch_peer(&host, port, path))
        .await.map_err(|_| "timeout")?.map_err(|_| "unreachable")?;
    let roster = response_json_200(&response).ok_or("unreachable")?;
    if (roster.get("schema").and_then(Value::as_str) != Some(row_schema())
        && !leaf_schema::bound_http_reply(&roster, path))
        || roster.get("ok").and_then(Value::as_bool) != Some(true)
        || roster.get("service").and_then(Value::as_str) != Some("caduceus")
    {
        return Err("unreachable");
    }
    let mac = roster.pointer("/seat/mac").and_then(Value::as_str)
        .filter(|mac| !mac.trim().eq_ignore_ascii_case("unknown"))
        .ok_or("seat-mac-unknown")?;
    if normalized_mac(mac).as_deref() != Some(row.mac.as_str()) {
        return Err("seat-mac-mismatch");
    }
    Ok((host, port))
}

fn answer(mac: &str, hostname: &str, proven: bool, signal: Option<String>, value: Option<Value>) -> Value {
    json!({"mac": mac, "hostname": hostname, "proven": proven, "signal": signal, "answer": value})
}

pub(super) async fn get(
    Query(query): Query<BTreeMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let raw_target = query.get("target").ok_or_else(|| error(StatusCode::BAD_REQUEST, "target-invalid"))?;
    let target = if raw_target == "every" {
        "every".to_owned()
    } else {
        normalized_mac(raw_target).ok_or_else(|| error(StatusCode::BAD_REQUEST, "target-invalid"))?
    };
    let thing = query.get("thing").cloned().unwrap_or_default();
    let (rows, identity) = crate::gate::blocking_task("ruyi", || {
        let stored = crate::stats::ruyi_snapshot().map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-store-failed"))?;
        let mut rows = Vec::with_capacity(stored.rows.len());
        for (_, bytes, last_seen) in stored.rows {
            let value: Value = serde_json::from_str(&bytes).map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
            if !leaf_schema::accepts_form(row_schema(), "row", &value) {
                return Err(error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"));
            }
            let mut row: RuyiRow = serde_json::from_value(value).map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
            row.last_seen = u64::try_from(last_seen).map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))?;
            rows.push(row);
        }
        Ok::<_, (StatusCode, Json<crate::gate::ApiErrorBody>)>((rows, current_identity()))
    }).await??;
    let known_self_mac = identity.mac;
    let self_mac = known_self_mac.as_deref().unwrap_or("unknown");
    let Json(beam) = crate::routes::leaf_beam::route().await?;
    let hostname = beam.hostname.filter(|name| !name.trim().is_empty()).unwrap_or_else(|| "unknown".to_owned());
    let mut answers = Vec::new();
    let mut tasks = JoinSet::new();
    let mut task_peers = std::collections::HashMap::new();
    if target == "every" || target == self_mac {
        if known_self_mac.is_none() {
            answers.push(answer(self_mac, &hostname, false, Some("seat-mac-unknown".to_owned()), None));
        } else if thing == "stats" {
            let (value, signal) = local_stats();
            answers.push(answer(self_mac, &hostname, true, signal, value));
        } else {
            answers.push(answer(self_mac, &hostname, false, Some("thing-undeclared".to_owned()), None));
        }
    }
    for row in rows.into_iter().filter(|row| known_self_mac.as_deref() != Some(row.mac.as_str()) && (target == "every" || row.mac == target)) {
        if thing != "stats" {
            answers.push(answer(&row.mac, &row.hostname, false, Some("thing-undeclared".to_owned()), None));
            continue;
        }
        let peer = (row.mac.clone(), row.hostname.clone());
        let handle = tasks.spawn(async move {
            match prove_stave(&row, Instant::now() + RUYI_PEER_TIMEOUT).await {
                Ok((host, port)) => {
                    let (value, signal) = fetch_peer_stats(&host, port).await;
                    answer(&row.mac, &row.hostname, true, signal, value)
                }
                Err(signal) => answer(&row.mac, &row.hostname, false, Some(signal.to_owned()), None),
            }
        });
        task_peers.insert(handle.id(), peer);
    }
    while let Some(result) = tasks.join_next_with_id().await {
        match result {
            Ok((id, value)) => {
                task_peers.remove(&id);
                answers.push(value);
            }
            Err(err) => {
                if let Some((mac, hostname)) = task_peers.remove(&err.id()) {
                    answers.push(answer(&mac, &hostname, false, Some("road-task-failed".to_owned()), None));
                }
            }
        }
    }
    if answers.is_empty() {
        let signal = if thing == "stats" { "target-unknown" } else { "thing-undeclared" };
        answers.push(answer(&target, "unknown", false, Some(signal.to_owned()), None));
    }
    Ok(Json(json!({"schema": row_schema(), "ok": true, "service": "caduceus", "seat": {"mac": self_mac, "hostname": hostname}, "thing": thing, "answers": answers})))
}
