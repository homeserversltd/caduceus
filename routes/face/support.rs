pub(crate) async fn face_post(
    verb: &'static str,
    body: serde_json::Value,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    let namespace = format!("face/{verb}");
    if !crate::gate::roster_allows("POST", &namespace).unwrap_or(false) {
        return Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-route-off-roster",
        ));
    }
    match crate::shared::policy::allows_command("staff intent") {
        Ok(true) => {
            let record_failure = match verb {
                "fetch" | "badge" | "meter" => false,
                "launcher-cache" => {
                    body.get("action").and_then(serde_json::Value::as_str) != Some("check")
                }
                _ => true,
            };
            let input = serde_json::json!({"payload": body});
            let verb = verb.to_owned();
            let crossed = crate::gate::blocking_task("staff intent", move || {
                crate::shared::agathodaimon::crossing_value_preserving_receipt(
                    "face",
                    &verb,
                    &input,
                    record_failure,
                )
            })
            .await?;
            match crossed {
                Ok(receipt) => Ok((crate::gate::mutation_status(&receipt), axum::Json(receipt))),
                Err(failure) => {
                    let signal = failure
                        .get("firstMissingSignal")
                        .or_else(|| failure.get("first_missing_signal"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or("caduceus-agathodaimon-cli-failed");
                    Err(crate::gate::api_error_signal("staff intent", signal))
                }
            }
        }
        Ok(false) => Err(crate::gate::api_error("staff intent")),
        Err(_) => Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-profile-missing",
        )),
    }
}
