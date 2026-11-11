use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;
use std::time::Duration;

const COMMAND: &str = "transmission up";
const CROSSING: &str = "transmission/up";
const TIMEOUT: Duration = Duration::from_secs(600);

async fn up_route(
    body: Option<Json<Value>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    if crate::routes::profile_routes::ACTIVE_PROFILE != "homeserver" {
        return Err(crate::gate::api_error(COMMAND));
    }
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(crate::gate::api_error(COMMAND)),
        Err(_) => {
            return Err(crate::gate::api_error_signal(
                COMMAND,
                "caduceus-carapace-desync",
            ));
        }
    }

    let payload = body.map(|Json(value)| value).unwrap_or(Value::Null);
    let crossed = crate::gate::blocking_task(COMMAND, move || {
        crate::gate::snake::crossing_path_with_timeout(CROSSING, &payload, TIMEOUT)
    })
    .await?;
    let crossing = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
    let mut receipt = crossing.get("receiptPayload").cloned().ok_or_else(|| {
        crate::gate::service_unavailable(COMMAND, "caduceus-transmission-up-receipt-missing")
    })?;
    if receipt.get("schema").and_then(Value::as_str) == Some("caduceus.chord.receipt.v1")
        && (!crate::routes::leaf_schema::accepts("caduceus.chord.receipt.v1", &receipt)
            || receipt.get("routine_id").and_then(Value::as_str) != Some(CROSSING))
    {
        if let Some(out) = receipt.as_object_mut() {
            out.insert("doorSignal".into(), Value::String("caduceus-schema-desync".into()));
        }
    } else if receipt.get("schema").and_then(Value::as_str) == Some("caduceus.chord.receipt.v1") {
        // Keep the aggregate whole at the top level; derived legacy fields
        // ride beside it, selected from named stops rather than stage order.
        let chord = receipt.clone();
        let rows = chord.get("stages").and_then(Value::as_array);
        let row = |id: &str| rows.and_then(|rows| rows.iter().find(|row| row.get("stage_id").and_then(Value::as_str) == Some(id)));
        let stage = |id: &str| row(id).and_then(|row| row.get("receipt"));
        if let Some(out) = receipt.as_object_mut() {
            if let Some(resolve) = stage("resolve") {
                for key in ["provider", "rpcPort", "holdUnit", "nativeUnit"] {
                    if let Some(value) = resolve.get(key) { out.insert(key.into(), value.clone()); }
                }
            }
            if let Some(onness) = stage("onness") {
                for key in ["on", "conditions", "forwardPort", "peerPort", "rpcPort"] {
                    if let Some(value) = onness.get(key) { out.insert(key.into(), value.clone()); }
                }
            }
            if let Some(value) = stage("native-start").and_then(|s| s.pointer("/readback/active_state")).filter(|v| !v.is_null()) {
                out.insert("nativeState".into(), value.clone());
            }
            if let Some(value) = stage("hold-readback").and_then(|s| s.pointer("/readback/active_state")).filter(|v| !v.is_null())
                .or_else(|| stage("hold-failure-readback").and_then(|s| s.pointer("/readback/active_state")).filter(|v| !v.is_null())) {
                out.insert("holdState".into(), value.clone());
            }
            let failed = chord.get("failedStage").and_then(Value::as_str);
            let (rung, signal) = match failed {
                Some("resolve") => (Some("provider"), None),
                Some("hold-preflight" | "native-preflight") => (Some("hold"), None),
                Some("native-start") => {
                    let hold_active = row("hold-failure-readback")
                        .filter(|r| r.get("outcome").and_then(Value::as_str) == Some("stage-completed"))
                        .and_then(|r| r.pointer("/receipt/readback/active_state"))
                        .and_then(Value::as_str)
                        .is_some_and(|state| matches!(state, "active" | "reloading"));
                    if hold_active {
                        (Some("daemon"), Some("transmission-native-start-failed"))
                    } else {
                        (Some("hold"), Some("transmission-hold-start-failed"))
                    }
                }
                Some("hold-readback") => (Some("hold"), Some("transmission-hold-start-failed")),
                Some("onness" | "rollback-stop") => (Some("onness"), None),
                _ => (None, None),
            };
            if let Some(rung) = rung { out.insert("failedRung".into(), Value::String(rung.into())); }
            if let Some(signal) = signal { out.insert("failedSignal".into(), Value::String(signal.into())); }
            if failed == Some("rollback-stop") {
                if let Some(rollback) = stage("rollback-stop") { out.insert("rollback".into(), rollback.clone()); }
            }
            if let Some(rows) = rows { out.insert("steps".into(), Value::Array(rows.clone())); }
        }
    } else if !crate::routes::leaf_schema::bound(&receipt, "transmission/up") {
        return Err(crate::gate::service_unavailable(
            COMMAND,
            "caduceus-schema-desync",
        ));
    }

    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/transmission/up", axum::routing::post(up_route))
}
