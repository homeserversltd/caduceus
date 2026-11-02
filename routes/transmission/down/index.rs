use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;
use std::time::Duration;

const COMMAND: &str = "transmission down";
const TIMEOUT: Duration = Duration::from_secs(180);

async fn down_route(
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
        crate::gate::snake::crossing_path_with_timeout("transmission/down", &payload, TIMEOUT)
    })
    .await?;
    let crossing = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
    let mut receipt = crossing.get("receiptPayload").cloned().ok_or_else(|| {
        crate::gate::service_unavailable(COMMAND, "caduceus-transmission-down-receipt-missing")
    })?;
    if crate::routes::leaf_schema::accepts("caduceus.chord.receipt.v1", &receipt) {
        let chord = receipt.clone();
        if let Some(out) = receipt.as_object_mut() {
            out.insert("schema".into(), Value::String("caduceus.transmission.down.v1".into()));
            if let Some(rows) = chord.get("stages").and_then(Value::as_array) {
                out.insert("steps".into(), Value::Array(rows.clone()));
            }
            out.insert("chord".into(), chord);
        }
    } else if !crate::routes::leaf_schema::accepts("caduceus.transmission.down.v1", &receipt) {
        return Err(crate::gate::service_unavailable(
            COMMAND,
            "caduceus-schema-desync",
        ));
    }

    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/transmission/down", axum::routing::post(down_route))
}
