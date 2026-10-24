use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

/// Shared non-actuating receipt path for the cold canopy leaves.
pub(crate) fn staff_route(
    raw: Value,
    declaration_source: &str,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let declaration: Value = serde_json::from_str(declaration_source).map_err(|error| {
        refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus-route-declaration-invalid",
            error.to_string(),
        )
    })?;
    let namespace = declaration
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "caduceus-route-declaration-invalid",
                "namespace".into(),
            )
        })?;
    let route_set = declaration
        .get("serve")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            refusal(
                StatusCode::INTERNAL_SERVER_ERROR,
                "caduceus-route-declaration-invalid",
                "serve".into(),
            )
        })?;
    let mut receipt = crate::gate::receive(raw, route_set, &declaration, false)
        .map_err(|signal| refusal(StatusCode::BAD_REQUEST, "caduceus.staff.v1", signal))?;
    let object = receipt.as_object_mut().ok_or_else(|| {
        refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "caduceus.staff.v1",
            "receipt-not-object".into(),
        )
    })?;
    object.insert("route".into(), Value::String(namespace.into()));
    object.insert("ok".into(), Value::Bool(false));
    object.insert("mutationPerformed".into(), Value::Bool(false));
    object.insert("planned".into(), Value::Bool(true));
    let signal = declaration
        .get("flags")
        .and_then(Value::as_object)
        .and_then(|flags| flags.get("firstMissingSignal"))
        .and_then(Value::as_str)
        .unwrap_or("caduceus-staff-debt");
    object.insert("first_missing_signal".into(), Value::String(signal.into()));
    Ok((StatusCode::SERVICE_UNAVAILABLE, Json(receipt)))
}

fn refusal(status: StatusCode, schema: &str, signal: String) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "schema": schema,
            "ok": false,
            "first_missing_signal": signal
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::staff_route;
    use axum::http::StatusCode;
    use serde_json::json;

    const DECLARATION: &str = r#"{"namespace":"appliance/restart","admittance":"open","flags":{"firstMissingSignal":"agathodaimon-sbin-appliance-restart"},"serve":[{"rust":"caduceus_staff_receipt"}]}"#;

    #[test]
    fn valid_envelope_retains_unknown_fields_and_adds_seat_stamps() {
        let (status, body) = staff_route(
            json!({
                "schema": "caduceus.staff.v1",
                "intent_id": "intent-test",
                "transition": "observe",
                "unknown_field": {"retained": true}
            }),
            DECLARATION,
        )
        .expect("valid envelope must produce bounded refusal receipt");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let receipt = body.0;
        assert_eq!(receipt["unknown_field"]["retained"], true);
        assert_eq!(receipt["admittance"], "open");
        assert_eq!(receipt["attendance"], "absent");
        assert_eq!(receipt["registers_lit"], true);
        assert_eq!(receipt["ok"], false);
        assert_eq!(
            receipt["first_missing_signal"],
            "agathodaimon-sbin-appliance-restart"
        );
        assert_eq!(receipt["route"], "appliance/restart");
        assert_eq!(receipt["mutationPerformed"], false);
    }

    #[test]
    fn gaming_cold_seats_emit_their_exact_debt_signals() {
        for (declaration, signal, route) in [
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/routes/gaming/sync/index.json"
                )),
                "agathodaimon-sbin-gaming-sync",
                "gaming/sync",
            ),
            (
                include_str!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/routes/gaming/provider-keys/index.json"
                )),
                "agathodaimon-sbin-gaming-provider-keys",
                "gaming/provider-keys",
            ),
        ] {
            let (_, body) = staff_route(
                json!({
                    "schema": "caduceus.staff.v1",
                    "intent_id": "gaming-test",
                    "transition": "observe",
                    "unknown_field": "preserve-me"
                }),
                declaration,
            )
            .expect("gaming cold seat must produce a refusal receipt");
            assert_eq!(body.0["route"], route);
            assert_eq!(body.0["unknown_field"], "preserve-me");
            assert_eq!(body.0["first_missing_signal"], signal);
            assert_eq!(body.0["mutationPerformed"], false);
            assert_eq!(body.0["planned"], true);
        }
    }

    #[test]
    fn invalid_envelope_is_a_typed_refusal() {
        let (status, body) = staff_route(json!({"schema": "wrong"}), DECLARATION).unwrap_err();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.0["schema"], "caduceus.staff.v1");
        assert!(body.0["first_missing_signal"].is_string());
    }
}
