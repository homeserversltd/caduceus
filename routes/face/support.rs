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
            let namespace_for_run = namespace.clone();
            let crossed = crate::gate::blocking_task("staff intent", move || {
                let started = std::time::Instant::now();
                let envelope = crate::gate::snake::route_envelope(&namespace_for_run, &body);
                let result: Result<serde_json::Value, String> = (|| {
                    crate::gate::receive(envelope.clone(), &route_set, &declaration, false)
                        .map_err(|signal| signal)?;
                    let aggregate =
                        crate::gate::snake::execute_ordered_serve(&route_set, &envelope)?;
                    let payload = aggregate
                        .get("receiptPayload")
                        .filter(|value| value.is_object())
                        .cloned()
                        .ok_or_else(|| {
                            "caduceus-agathodaimon-cli-response-not-object".to_string()
                        })?;
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
                        face_reflect_failure(
                            &verb,
                            Some(&payload),
                            "caduceus-agathodaimon-cli-refused",
                            started.elapsed().as_millis(),
                            record_failure,
                        );
                    }
                    Ok(payload)
                })();
                if let Err(signal) = &result {
                    face_reflect_failure(
                        &verb,
                        None,
                        signal,
                        started.elapsed().as_millis(),
                        record_failure,
                    );
                }
                result
            })
            .await?;
            match crossed {
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
