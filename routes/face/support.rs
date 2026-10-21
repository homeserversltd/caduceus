pub(crate) async fn face_post(
    declaration_source: &'static str,
    body: serde_json::Value,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    face_post_with_timeout(declaration_source, body, None).await
}

pub(crate) async fn face_post_with_timeout(
    declaration_source: &'static str,
    body: serde_json::Value,
    crossing_timeout: Option<std::time::Duration>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    let declaration =
        serde_json::from_str::<serde_json::Value>(declaration_source).map_err(|_| {
            crate::gate::api_error_signal("staff intent", "caduceus-route-declaration-invalid")
        })?;
    let namespace = declaration
        .get("namespace")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            crate::gate::api_error_signal("staff intent", "caduceus-route-namespace-missing")
        })?
        .to_owned();
    if !crate::gate::roster_allows("POST", &namespace).unwrap_or(false) {
        return Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-route-off-roster",
        ));
    }
    match crate::shared::policy::allows_command("staff intent") {
        Ok(true) => {
            let route_set = declaration
                .get("serve")
                .and_then(serde_json::Value::as_array)
                .cloned()
                .ok_or_else(|| {
                    crate::gate::api_error_signal("staff intent", "gate-route-serve-missing")
                })?;
            crate::gate::admittance::check_declared_admittance(&declaration)
                .map_err(|signal| crate::gate::api_error_signal("staff intent", &signal))?;
            let verb = namespace
                .strip_prefix("face/")
                .unwrap_or(&namespace)
                .to_owned();
            let record_failure = match verb.as_str() {
                "fetch" | "badge" | "meter" => false,
                "launcher-cache" => {
                    body.get("action").and_then(serde_json::Value::as_str) != Some("check")
                }
                _ => true,
            };
            let started = record_failure.then(std::time::Instant::now);
            let envelope = crate::gate::snake::route_envelope(&namespace, &body);
            let benchmark_started = if crate::protocol::benchmark_enabled(&envelope) {
                Some(std::time::Instant::now())
            } else {
                None
            };
            let result: Result<serde_json::Value, String> = async {
                let receive = crate::gate::receive(
                    envelope.clone(),
                    &route_set,
                    &declaration,
                    false,
                )?;
                let aggregate = crate::gate::snake::execute_ordered_serve_with_timeout(
                    &route_set,
                    &envelope,
                    crossing_timeout,
                )
                .await?;
                let mut payload = aggregate
                    .get("receiptPayload")
                    .filter(|value| value.is_object())
                    .cloned()
                    .ok_or_else(|| "caduceus-agathodaimon-cli-response-not-object".to_string())?;
                if let Some(object) = payload.as_object_mut() {
                    for key in ["intent_id", "raw_envelope", "envelope", "staff", "stamps"] {
                        object.remove(key);
                    }
                }
                if let Some(started) = benchmark_started {
                    crate::protocol::append_benchmark_reply(
                        &mut payload,
                        started.elapsed(),
                        &[&receive, &aggregate],
                    );
                }
                let child_failed = aggregate
                    .get("stepReceipts")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|receipts| {
                        receipts.iter().any(|receipt| {
                            receipt.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
                        })
                    });
                if child_failed
                    || payload.get("ok").and_then(serde_json::Value::as_bool) != Some(true)
                {
                    face_reflect_failure_async(
                        &verb,
                        Some(payload.clone()),
                        "caduceus-agathodaimon-cli-refused",
                        started.map(|started| started.elapsed().as_millis()).unwrap_or_default(),
                        record_failure,
                    )
                    .await?;
                } else if verb == "dictate" {
                    face_reflect_dictate_success_async(
                        &payload,
                        started.map(|started| started.elapsed().as_millis()).unwrap_or_default(),
                    )
                    .await?;
                }
                Ok(payload)
            }
            .await;
            if let Err(signal) = &result {
                face_reflect_failure_async(
                    &verb,
                    None,
                    signal,
                    started.map(|started| started.elapsed().as_millis()).unwrap_or_default(),
                    record_failure,
                )
                .await
                .map_err(|signal| crate::gate::api_error_signal("staff intent", &signal))?;
            }
            match result {
                Ok(receipt) => Ok((crate::gate::mutation_status(&receipt), axum::Json(receipt))),
                Err(signal) => Err(crate::gate::api_error_signal("staff intent", &signal)),
            }
        }
        Ok(false) => Err(crate::gate::api_error("staff intent")),
        Err(_) => Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-profile-missing",
        )),
    }
}

async fn face_reflect_dictate_success_async(
    receipt: &serde_json::Value,
    duration_ms: u128,
) -> Result<(), String> {
    // Only bounded deed fields cross into the log, never receipt text or audio.
    let state = match receipt.get("state").and_then(serde_json::Value::as_str) {
        Some("recording") => Some("recording"),
        Some("transcribed") => Some("transcribed"),
        _ => None,
    };
    let chars = receipt.get("chars").and_then(serde_json::Value::as_u64);
    crate::gate::blocking_task("staff intent", move || {
        let _ = crate::shared::hyalos::reflect_json(serde_json::json!({
            "organ": "agathodaimon",
            "kind": "crossing-change",
            "level": "info",
            "ok": true,
            "message": "agathodaimon crossing completed",
            "attributes_redacted": {
                "who": "agathodaimon",
                "verb": "dictate",
                "target": "face",
                "outcome": "success",
                "duration_ms": u64::try_from(duration_ms).unwrap_or(u64::MAX),
                "state": state,
                "chars": chars,
            }
        }));
    })
    .await
    .map_err(|_| "caduceus-blocking-task-join-failed".to_string())
}

fn face_reflect_failure(
    verb: &str,
    receipt: Option<&serde_json::Value>,
    fallback_signal: &str,
    duration_ms: u128,
    record_failure: bool,
) {
    if !record_failure {
        return;
    }
    let signal = receipt
        .and_then(|value| {
            value
                .get("firstMissingSignal")
                .or_else(|| value.get("first_missing_signal"))
                .and_then(serde_json::Value::as_str)
        })
        .unwrap_or(fallback_signal);
    let first_missing_field = receipt.and_then(|value| {
        value
            .get("firstMissingField")
            .or_else(|| value.get("field"))
            .and_then(serde_json::Value::as_str)
    });
    let _ = crate::shared::hyalos::reflect_json(serde_json::json!({
        "organ": "agathodaimon",
        "kind": "crossing-failure",
        "level": "error",
        "ok": false,
        "message": "agathodaimon crossing failed",
        "attributes_redacted": {
            "who": "agathodaimon",
            "verb": verb,
            "target": "face",
            "outcome": "failure",
            "duration_ms": u64::try_from(duration_ms).unwrap_or(u64::MAX),
            "signal": signal,
            "first_missing_field": first_missing_field,
        }
    }));
}

async fn face_reflect_failure_async(
    verb: &str,
    receipt: Option<serde_json::Value>,
    fallback_signal: &str,
    duration_ms: u128,
    record_failure: bool,
) -> Result<(), String> {
    if !record_failure {
        return Ok(());
    }
    let verb = verb.to_owned();
    let fallback_signal = fallback_signal.to_owned();
    crate::gate::blocking_task("staff intent", move || {
        face_reflect_failure(
            &verb,
            receipt.as_ref(),
            &fallback_signal,
            duration_ms,
            true,
        )
    })
    .await
    .map_err(|_| "caduceus-blocking-task-join-failed".to_string())
}
