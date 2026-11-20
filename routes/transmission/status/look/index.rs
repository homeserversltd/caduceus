use crate::shared::policy;
use axum::{http::StatusCode, routing::post, Json, Router};
use serde_json::{json, Value};

const COMMAND: &str = "transmission status";
const RECEIPT_SCHEMA: &str = "caduceus.staff.receipt.v1";

fn refusal(status: StatusCode, signal: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({
            "schema": RECEIPT_SCHEMA,
            "ok": false,
            "firstMissingSignal": signal,
            "stop": {"noun": "transmission/status", "verb": "look"},
            "observed": null,
            "could_change_to": null,
            "attempt": {"outcome": signal},
            "final_receipt": {"ok": false, "firstMissingSignal": signal}
        })),
    )
}

async fn look_route() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let forbidden = StatusCode::FORBIDDEN;
    if profile_routes::ACTIVE_PROFILE != "homeserver" {
        return Err(refusal(forbidden, "caduceus-public-action-not-allowed"));
    }
    match policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(refusal(forbidden, "caduceus-public-action-not-allowed")),
        Err(_) => return Err(refusal(forbidden, "caduceus-carapace-desync")),
    }

    let unavailable = StatusCode::SERVICE_UNAVAILABLE;
    let (recorded_at, queued) = tokio::task::spawn_blocking(crate::pid2::solver::queue_vpn_look)
        .await
        .map_err(|_| refusal(unavailable, "pid2-vpn-look-task-failed"))?
        .map_err(|signal| refusal(unavailable, signal))?;
    Ok(Json(json!({
        "schema": RECEIPT_SCHEMA,
        "ok": true,
        "stop": {"noun": "transmission/status", "verb": "look"},
        "observed": {"recorded_at": recorded_at},
        "could_change_to": null,
        "attempt": {"outcome": if queued { "queued" } else { "coalesced" }},
        "final_receipt": {"ok": true}
    })))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/transmission/status/look", post(look_route))
}
