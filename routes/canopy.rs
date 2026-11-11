use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

/// Shared non-actuating receipt path for the cold canopy leaves.
pub(crate) fn staff_route(
    raw: Value,
    declaration_source: &str,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let seat = crate::protocol::seat().ok();
    let kernel = seat.as_ref().and_then(|s| s.pointer("/kernel/fields")).and_then(Value::as_array);
    let observed = raw.as_object().map(|object| {
        let fields: Vec<&str> = kernel.into_iter().flatten()
            .filter_map(Value::as_str).filter(|name| object.contains_key(*name)).collect();
        json!({"others": object.len() - fields.len(), "fields": fields})
    }).unwrap_or(Value::Null);
    let required = seat.as_ref().and_then(|s| s.pointer("/kernel/required")).cloned().unwrap_or(Value::Null);
    let hint = declaration_namespace(declaration_source);
    let declaration: Value = serde_json::from_str(declaration_source).map_err(|error| {
        refusal(StatusCode::INTERNAL_SERVER_ERROR, hint, &observed, &required, "declaration", error.to_string())
    })?;
    let namespace = declaration.get("namespace").and_then(Value::as_str).ok_or_else(|| {
        refusal(StatusCode::INTERNAL_SERVER_ERROR, hint, &observed, &required, "declaration", "namespace".into())
    })?;
    let route_set = declaration.get("serve").and_then(Value::as_array).ok_or_else(|| {
        refusal(StatusCode::INTERNAL_SERVER_ERROR, Some(namespace), &observed, &required, "declaration", "serve".into())
    })?;
    let mut receipt = crate::gate::receive(raw, route_set, &declaration, false)
        .map_err(|signal| refusal(StatusCode::BAD_REQUEST, Some(namespace), &observed, &required, "receive", signal))?;
    let object = receipt.as_object_mut().ok_or_else(|| {
        refusal(StatusCode::INTERNAL_SERVER_ERROR, Some(namespace), &observed, &required, "receive", "receipt-not-object".into())
    })?;
    object.insert("route".into(), Value::String(namespace.into()));
    object.insert("mutationPerformed".into(), Value::Bool(false));
    object.insert("planned".into(), Value::Bool(true));
    let signal = declaration.get("flags").and_then(Value::as_object)
        .and_then(|flags| flags.get("firstMissingSignal")).and_then(Value::as_str)
        .unwrap_or("caduceus-staff-debt");
    stamp(object, Some(namespace), &observed, &required, "planned", signal);
    Ok((StatusCode::SERVICE_UNAVAILABLE, Json(receipt)))
}

// The declarations are compiled in at the five call sites. Match their bytes
// before parsing so even a broken declaration can name its own door. If two
// broken declarations have identical bytes, neither can be identified safely.
fn declaration_namespace(source: &str) -> Option<&'static str> {
    let candidates = [
        (include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/routes/appliance/restart/index.json")), "appliance/restart"),
        (include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/routes/appliance/poweroff/index.json")), "appliance/poweroff"),
        (include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/routes/appliance/reboot/index.json")), "appliance/reboot"),
        (include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/routes/settings/ssh/config/index.json")), "settings/ssh/config"),
        (include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/routes/settings/ssh/authorized-keys/index.json")), "settings/ssh/authorized-keys"),
    ];
    let mut matches = candidates.into_iter().filter(|(declaration, _)| *declaration == source);
    let name = matches.next()?.1;
    if matches.next().is_some() { None } else { Some(name) }
}

fn stamp(object: &mut serde_json::Map<String, Value>, namespace: Option<&str>, observed: &Value, required: &Value, step: &str, signal: &str) {
    let stop = namespace.map(|path| path.rsplit_once('/').unwrap_or((path, "")));
    object.remove("changed");
    object.insert("schema".into(), json!("caduceus.staff.receipt.v1"));
    object.insert("ok".into(), json!(false));
    object.insert("first_missing_signal".into(), json!(signal));
    object.insert("firstMissingSignal".into(), json!(signal));
    object.insert("stop".into(), json!({"noun": stop.map(|s| s.0), "verb": stop.map(|s| s.1)}));
    object.insert("observed".into(), observed.clone());
    object.insert("could_change_to".into(), json!({"namespace": namespace, "required_kernel": required, "firstMissingSignal": signal}));
    object.insert("attempt".into(), json!({"attempted": false, "step": step, "outcome": signal}));
    object.insert("final_receipt".into(), json!({"ok": false, "firstMissingSignal": signal}));
}

fn refusal(status: StatusCode, namespace: Option<&str>, observed: &Value, required: &Value, step: &str, signal: String) -> (StatusCode, Json<Value>) {
    let mut object = serde_json::Map::new();
    stamp(&mut object, namespace, observed, required, step, &signal);
    (status, Json(Value::Object(object)))
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
