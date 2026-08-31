use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};

const READ_COMMAND: &str = "settings input read";
const SET_COMMAND: &str = "settings input set";
const BAND: &str = "input-policy";
const SCHEMA: &str = "caduceus.staff.v1";

fn admitted(command: &str) -> Result<(), (StatusCode, Json<Value>)> {
    match crate::shared::policy::allows_command(command) {
        Ok(true) => Ok(()),
        Ok(false) => Err((StatusCode::FORBIDDEN, Json(json!({"schema":"caduceus.api.error.v1","ok":false,"command":command,"first_missing_signal":"caduceus-public-action-not-allowed"})))),
        Err(_) => Err((StatusCode::FORBIDDEN, Json(json!({"schema":"caduceus.api.error.v1","ok":false,"command":command,"first_missing_signal":"caduceus-profile-missing"})))),
    }
}

fn actuator_receipt(transition: &str, payload: Option<Value>) -> Result<Value, String> {
    let mut envelope = json!({"schema":SCHEMA,"intent_id":format!("caduceus-settings-input-{transition}"),"transition":transition,"origin_of_intent":"near"});
    if let Some(payload) = payload { envelope["payload"] = payload; }
    let walked = crate::gate::snake::run(BAND, &envelope)?;
    walked.get("envelope").and_then(|value| value.get("caduceusReceipt")).and_then(|value| value.get("stepReceipt")).cloned().ok_or_else(|| "caduceus-snake-staff-receipt-missing".to_string())
}

async fn read_http() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    admitted(READ_COMMAND)?;
    actuator_receipt("read", None).map(|receipt| (crate::gate::mutation_status(&receipt), Json(receipt))).map_err(|signal| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"schema":SCHEMA,"ok":false,"command":READ_COMMAND,"firstMissingSignal":signal}))))
}

async fn set_http(Json(body): Json<Value>) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    admitted(SET_COMMAND)?;
    actuator_receipt("set", Some(body)).map(|receipt| (crate::gate::mutation_status(&receipt), Json(receipt))).map_err(|signal| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"schema":SCHEMA,"ok":false,"command":SET_COMMAND,"firstMissingSignal":signal}))))
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/settings/input", axum::routing::get(read_http).post(set_http))
}
