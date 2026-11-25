use super::*;
use axum::extract::Query;

// Only this map selects a peer door; query parameters never supply a path.
const GET_THINGS: &[(&str, Option<&str>, Duration)] = &[
    ("stats", None, Duration::from_millis(500)),
    ("backup-drive", Some("/api/v1/storage/backup/drive/card"), Duration::from_secs(70)),
];

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

type Failure = (StatusCode, Json<crate::gate::ApiErrorBody>);

fn enroll_mac(payload: Option<&Value>) -> Option<&str> {
    let payload = payload?;
    if serde_json::to_vec(payload).ok()?.len() > 1024 { return None; }
    let outer = payload.as_object()?;
    if outer.len() != 1 { return None; }
    let home = outer.get("home")?.as_object()?;
    if home.len() != 1 { return None; }
    let mac = home.get("mac")?.as_str()?;
    if mac.len() != 17 || !mac.bytes().enumerate().all(|(i, b)| if i % 3 == 2 { b == b':' } else { b.is_ascii_digit() || (b'a'..=b'f').contains(&b) }) { return None; }
    Some(mac)
}

fn road_body(mac: &str, hostname: &str, thing: &str, entry: Value) -> Value {
    json!({"schema": row_schema(), "ok": true, "service": "caduceus", "seat": {"mac": mac, "hostname": hostname}, "thing": thing, "answers": [entry]})
}

pub(super) async fn post(body: Bytes) -> Result<(StatusCode, Json<Value>), Failure> {
    let started = Instant::now();
    if body.len() > 4096 {
        return Err(error(StatusCode::BAD_REQUEST, "road-act-body-invalid"));
    }
    if body.windows(6).filter(|part| *part == b"\"pin\":").count() > 1 {
        return Err(error(StatusCode::BAD_REQUEST, "road-act-pin-carrier-duplicated"));
    }
    let mut request: Value = serde_json::from_slice(&body)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "road-act-body-invalid"))?;
    if !request.is_object() || request.get("schema").and_then(Value::as_str) != Some(row_schema()) {
        return Err(error(StatusCode::BAD_REQUEST, "road-act-body-invalid"));
    }
    let target = request.get("target").and_then(Value::as_str).and_then(normalized_mac)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "road-act-body-invalid"))?;
    let thing = request.get("thing").and_then(Value::as_str)
        .ok_or_else(|| error(StatusCode::BAD_REQUEST, "road-act-body-invalid"))?.to_owned();
    let identity = current_identity();
    let self_mac = identity.mac.as_deref().unwrap_or("unknown");

    if identity.mac.as_deref() == Some(target.as_str()) {
        let pin = request.pointer_mut("/flags/exousia").and_then(Value::as_object_mut)
            .and_then(|flags| flags.remove("pin")).unwrap_or(Value::Null);
        crate::shared::attendance::verify_administrative_pin(pin.as_str().unwrap_or(""))
            .map_err(|signal| crate::gate::api_error_signal("ruyi", &signal))?;
        drop(pin);
        let home = if thing == "backup-enroll" {
            Some(enroll_mac(request.get("payload")).ok_or_else(|| error(StatusCode::BAD_REQUEST, "payload-invalid"))?.to_owned())
        } else {
            if request.get("payload").is_some() { return Err(error(StatusCode::BAD_REQUEST, "payload-invalid")); }
            None
        };
        drop(request);
        let hostname = crate::shared::seat_identity::local_hostname();
        let (status, value) = match thing.as_str() {
            "pin-check" => (StatusCode::OK, json!({"ok":true,"verified":true})),
            #[cfg(leaf_pid2)]
            "backup-enroll" => {
                let registration = json!({"schema":"caduceus.pid2.schedule.v1", "intent_id":"backup-pull-enroll", "transition":"register", "version":"1.0.0", "timestamp":"1970-01-01T00:00:00Z", "schedule":{"schedule_id":"backup-pull","enabled":true,"calendar":null,"job":{"band":"storage/backup/mirror/pull","action":"pull","max_seconds":86400,"payload":{"home":{"mac":home}}}}});
                crate::gate::blocking_task("ruyi", move || crate::pid2::schedule::register(registration.to_string().as_bytes())).await?
                    .map_err(|signal| crate::gate::api_error_signal("ruyi", &signal))?;
                (StatusCode::OK, json!({"ok":true,"enrolled":true}))
            },
            #[cfg(leaf_pid2)]
            "backup-pull" => {
                let queued = crate::gate::blocking_task("ruyi", || crate::pid2::schedule::queue("backup-pull", "road", None)).await?
                    .map_err(|signal| crate::gate::api_error_signal("ruyi", if signal == "pid2-schedule-not-found" {"backup-pull-not-enrolled"} else {&signal}))?;
                (StatusCode::OK, queued)
            },
            #[cfg(not(leaf_pid2))]
            "backup-enroll" | "backup-pull" => return Err(error(StatusCode::SERVICE_UNAVAILABLE, "pid2-unavailable")),
            "update-now" => { let (status, Json(value)) = crate::routes::update_support::update_now_route(axum::http::HeaderMap::new()).await?; (status, value) },
            _ => return Err(error(StatusCode::BAD_REQUEST, "thing-undeclared")),
        };
        let signal = value.get("firstMissingSignal").and_then(Value::as_str)
            .filter(|s| !s.is_empty() && *s != "none").map(str::to_owned);
        let entry = answer(self_mac, &hostname, true, signal, Some(value));
        return Ok((status, Json(road_body(self_mac, &hostname, &thing, entry))));
    }

    let Json(beam) = crate::routes::leaf_beam::route().await?;
    let hostname = beam.hostname.filter(|name| !name.trim().is_empty()).unwrap_or_else(|| "unknown".to_owned());
    let row_target = target.clone();
    let row = crate::gate::blocking_task("ruyi", move || {
        let bytes = crate::stats::ruyi_row(&row_target)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-store-failed"))?;
        bytes.map(|bytes| serde_json::from_str::<RuyiRow>(&bytes)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "caduceus-ruyi-row-invalid"))).transpose()
    }).await??;
    let (entry, signal) = match row {
        None => (answer(&target, "unknown", false, Some("target-unknown".into()), None), Some("target-unknown".to_owned())),
        Some(row) => match prove_stave(&row, Instant::now() + RUYI_PEER_TIMEOUT).await {
            Err(signal) => (answer(&target, &row.hostname, false, Some(signal.into()), None), Some(signal.to_owned())),
            Ok((host, port)) => {
                let pin = request.pointer("/flags/exousia/pin").cloned().unwrap_or(Value::Null);
                let mut outgoing = json!({"schema": row_schema(), "target": target, "thing": thing, "flags": {"exousia": {"pin": pin}}});
                if let Some(payload) = request.get("payload") { outgoing["payload"] = payload.clone(); }
                let bytes = serde_json::to_vec(&outgoing).map_err(|_| error(StatusCode::BAD_REQUEST, "road-act-body-invalid"))?;
                let response = timeout(Duration::from_secs(5), post_peer(&host, port, &bytes)).await;
                let (signal, value, peer_status) = match response {
                    Err(_) => (Some("timeout".to_owned()), None, None),
                    Ok(Err(_)) => (Some("unreachable".to_owned()), None, None),
                    Ok(Ok(response)) => {
                        let end = response.windows(4).position(|w| w == b"\r\n\r\n");
                        let status = end.and_then(|n| std::str::from_utf8(&response[..n]).ok())
                            .and_then(|headers| headers.lines().next()).and_then(|line| line.split_whitespace().nth(1));
                        let peer_status = status.and_then(|s| s.parse::<u16>().ok());
                        if status == Some("405") {
                            (Some("act-door-absent".to_owned()), None, peer_status)
                        } else if let Some(value) = end.and_then(|n| serde_json::from_slice::<Value>(&response[n+4..]).ok()) {
                            let signal = value.get("firstMissingSignal").and_then(Value::as_str)
                                .or_else(|| value.pointer("/answers/0/signal").and_then(Value::as_str))
                                .filter(|s| !s.is_empty() && *s != "none").map(str::to_owned);
                            (signal, Some(value), peer_status)
                        } else { (Some("unreachable".to_owned()), None, peer_status) }
                    }
                };
                let mut entry = answer(&target, &row.hostname, true, signal.clone(), value);
                entry["peerStatus"] = json!(peer_status);
                (entry, signal)
            }
        }
    };
    let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ": "ruyi", "kind": "deed", "ok": signal.is_none(), "message": "ruyi act",
        "attributes_redacted": {"who": "caduceus", "verb": "ruyi-act", "target": target,
            "thing": thing, "outcome": if signal.is_none() {"success"} else {"refused"},
            "signal": signal.as_deref().unwrap_or("none"), "duration_ms": duration_ms}
    }));
    Ok((StatusCode::OK, Json(road_body(self_mac, &hostname, &thing, entry))))
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
    let declared = GET_THINGS.iter().find(|(name, _, _)| *name == thing).copied();
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
        } else if thing == "backup-drive" {
            let mac = self_mac.to_owned();
            let name = hostname.clone();
            let peer = (mac.clone(), name.clone());
            let handle = tasks.spawn(async move {
                match crate::gate::blocking_task("storage backup drive card", crate::routes::leaf_storage_backup_drive_card::read_card).await {
                    Ok(card) => answer(&mac, &name, true, None, Some(card)),
                    Err(_) => answer(&mac, &name, true, Some("road-task-failed".to_owned()), None),
                }
            });
            task_peers.insert(handle.id(), peer);
        } else {
            answers.push(answer(self_mac, &hostname, false, Some("thing-undeclared".to_owned()), None));
        }
    }
    for row in rows.into_iter().filter(|row| known_self_mac.as_deref() != Some(row.mac.as_str()) && (target == "every" || row.mac == target)) {
        let Some((_, path, deadline)) = declared else {
            answers.push(answer(&row.mac, &row.hostname, false, Some("thing-undeclared".to_owned()), None));
            continue;
        };
        let peer = (row.mac.clone(), row.hostname.clone());
        let handle = tasks.spawn(async move {
            match prove_stave(&row, Instant::now() + RUYI_PEER_TIMEOUT).await {
                Ok((host, port)) => {
                    let (value, signal) = if let Some(path) = path {
                        match timeout(deadline, fetch_peer(&host, port, path)).await {
                            Err(_) => (None, Some("timeout".to_owned())),
                            Ok(Err(err)) if err.kind() == ErrorKind::InvalidData => (None, Some("too-large".to_owned())),
                            Ok(Err(_)) => (None, Some("unreachable".to_owned())),
                            Ok(Ok(bytes)) => match response_json_200(&bytes) {
                                Some(card) => (Some(card), None),
                                None => (None, Some("malformed".to_owned())),
                            },
                        }
                    } else {
                        // The shared stats reader owns the unchanged 500 ms timeout.
                        debug_assert_eq!(deadline, RUYI_PEER_TIMEOUT);
                        fetch_peer_stats(&host, port).await
                    };
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
        let signal = if declared.is_some() { "target-unknown" } else { "thing-undeclared" };
        answers.push(answer(&target, "unknown", false, Some(signal.to_owned()), None));
    }
    Ok(Json(json!({"schema": row_schema(), "ok": true, "service": "caduceus", "seat": {"mac": self_mac, "hostname": hostname}, "thing": thing, "answers": answers})))
}
