use axum::{http::StatusCode, routing::post, Json, Router};
use serde_json::{json, Value};
use std::time::Duration;

const COMMAND: &str = "storage nas prefire";
const STOP: &str = "storage/nas/setup/prefire";
static DECLARATION: std::sync::LazyLock<Value> = std::sync::LazyLock::new(|| {
    serde_json::from_str(include_str!("index.json")).expect("nas prefire declaration")
});

pub(crate) fn answer(signal: &str) -> Value {
    json!({"schema": DECLARATION["receipt"], "stop":{"noun":"storage/nas","verb":"prefire"},
        "ok":false,"lockedIn":false,"sizeBytes":0,"mainSizeBytes":null,"fits":null,
        "blank":false,"contents":[],"firstMissingSignal":signal,
        "observed":null,"could_change_to":null,"attempt":{"attempted":true},
        "final_receipt":{"ok":false,"firstMissingSignal":signal}})
}

pub(crate) fn observe(device: &str, role: &str) -> Option<Value> {
    let crossed = crate::gate::snake::crossing_path_with_timeout(STOP, &json!({"device":device,"role":role}), Duration::from_secs(60)).ok()?;
    if crossed["ok"] != true { return None; }
    let receipt = crossed.get("receiptPayload")?;
    if receipt["ok"] != true || !crate::routes::leaf_schema::bound(receipt, STOP)
        || receipt["sizeBytes"].as_i64().filter(|v| *v > 0).is_none()
        || receipt["blank"].as_bool().is_none() || !receipt["contents"].is_array() { return None; }
    Some(receipt.clone())
}

pub(crate) fn judge(device: &str, role: &str) -> Value {
    use crate::routes::leaf_storage_nas_locked_in_list as table;
    let unavailable = || answer("nas-prefire-unavailable");
    if !matches!(role, "primary" | "backup") || table::adopt(role).is_err() { return unavailable(); }
    if role == "backup" && table::adopt("primary").is_err() { return unavailable(); }
    let Some(observation) = observe(device, role) else { return unavailable(); };
    let locked = match observation.get("partUuid").and_then(Value::as_str).filter(|s| !s.is_empty()) {
        Some(uuid) => match table::read_by_uuid(uuid) { Ok(row) => row.is_some(), Err(_) => return unavailable() },
        None => false,
    };
    let main = match table::primary_row() { Ok(row) => row, Err(_) => return unavailable() };
    let main_size = main.as_ref().map(|row| row.size_bytes);
    let size = observation["sizeBytes"].as_i64().unwrap_or(0);
    // Exact 9667/10000 comparison in i128, without rounding or overflow.
    let fits = if role == "backup" { main_size.map(|main| i128::from(size) * 10000 >= i128::from(main) * 9667) } else { None };
    let signal = if role == "backup" && main_size.is_none() { "nas-main-size-unknown" }
        else if fits == Some(false) { "nas-backup-too-small" } else { "none" };
    let ok = signal == "none";
    let mut result = answer(signal);
    result["ok"] = json!(ok); result["lockedIn"] = json!(locked);
    result["sizeBytes"] = json!(size); result["mainSizeBytes"] = json!(main_size);
    result["fits"] = json!(fits); result["blank"] = observation["blank"].clone();
    result["contents"] = observation["contents"].clone();
    result["final_receipt"] = json!({"ok":ok,"firstMissingSignal":signal});
    result
}

async fn http(body: Result<Json<Value>, axum::extract::rejection::JsonRejection>) -> (StatusCode, Json<Value>) {
    if crate::gate::admittance::check_declared_admittance(&DECLARATION).is_err()
        || !matches!(crate::shared::policy::allows_command(COMMAND), Ok(true)) {
        return (StatusCode::OK, Json(answer("nas-prefire-unavailable")));
    }
    let Ok(Json(body)) = body else { return (StatusCode::OK, Json(answer("nas-prefire-unavailable"))); };
    let device = body.get("device").and_then(Value::as_str).unwrap_or("").to_owned();
    let role = body.get("role").and_then(Value::as_str).unwrap_or("").to_owned();
    let result = crate::gate::blocking_task(COMMAND, move || judge(&device, &role)).await;
    (StatusCode::OK, Json(result.unwrap_or_else(|_| answer("nas-prefire-unavailable"))))
}

pub fn register(router: Router) -> Router {
    router.route(LEAF_STORAGE_NAS_PREFIRE_CANONICAL, post(http))
}
