use axum::{body::Bytes, extract::Path, http::StatusCode, routing::{get, post}, Json, Router};
use serde_json::{json, Value};

type Response = Result<Json<Value>, (StatusCode, Json<Value>)>;
const RECEIPT_SCHEMA: &str = "caduceus.staff.receipt.v1";
fn refusal(signal: String, noun: &str, verb: &str, route: &str, attempted: Option<bool>) -> (StatusCode, Json<Value>) {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({
        "schema": RECEIPT_SCHEMA, "ok": false,
        "firstMissingSignal": signal, "first_missing_signal": signal,
        "stop": {"noun": noun, "verb": verb}, "observed": {"route": route},
        "could_change_to": null,
        "attempt": {"attempted": attempted, "step": format!("{noun}/{verb}"), "outcome": signal},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    })))
}
fn respond(result: Result<Value, String>, request: Option<Value>, transition: &str, noun: &str, verb: &str, route: &str, attempted: Option<bool>) -> Response {
    result.map(|receipt| Json(json!({
        "schema": crate::protocol::SCHEMA_ID,
        "intent_id": request.as_ref().and_then(|r| r.get("intent_id")).cloned().unwrap_or_else(||json!(format!("caduceus-pid2-{transition}"))),
        "transition": transition,
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "rawEnvelope": request,
        "receiptPayload": receipt
    }))).map_err(|signal| refusal(signal, noun, verb, route, attempted))
}
static IN_FLIGHT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);
async fn work<F>(run: F) -> Result<Value,String>
where F: FnOnce()->Result<Value,String> + Send + 'static {
    let permit=IN_FLIGHT.try_acquire().map_err(|_|"pid2-door-busy".to_string())?;
    tokio::task::spawn_blocking(move || { let _permit=permit; run() }).await.map_err(|_|"pid2-door-task-failed".to_string())?
}
async fn list() -> Response { respond(work(crate::pid2::list).await,None,"pid2-list","pid2","list","GET /api/v1/pid2/list",None) }
async fn status(Path(id): Path<String>) -> Response { respond(work(move || crate::pid2::status(&id)).await,None,"pid2-status","pid2","status","GET /api/v1/pid2/status/{id}",None) }
async fn command(Path(verb): Path<String>, body: Bytes) -> Response {
    let stop_verb = match verb.as_str() {
        "enable" => "enable", "disable" => "disable", "hold" => "hold", "release" => "release",
        "answer" => "answer", "start" => "start", "stop" => "stop", "restart" => "restart",
        _ => "unplaced-verb",
    };
    let route = "POST /api/v1/pid2/{verb}";
    let value: Value = match serde_json::from_slice(&body) { Ok(v) => v, Err(e) => return respond(Err(format!("pid2-invalid-json: {e}")),None,&verb,"pid2",stop_verb,route,Some(false)) };
    if verb == "enable" { return respond(work(move || crate::pid2::enable(&body)).await,Some(value),"pid2-enable","pid2",stop_verb,route,None); }
    if let Err(signal)=crate::protocol::Envelope::parse(value.clone()) { return respond(Err(signal),Some(value),&verb,"pid2",stop_verb,route,Some(false)); }
    let payload=value.get("payload").filter(|v|v.is_object()).unwrap_or(&value).clone();
    let transition=format!("pid2-{verb}");
    let result=work(move || {
        let target=payload.get("routine_id").or_else(||payload.get("unit")).and_then(Value::as_str).unwrap_or("");
        match verb.as_str() {
            "disable" => crate::pid2::disable(target),
            "hold" => crate::pid2::hold(target),
            "release" => crate::pid2::release(target),
            "answer" => crate::pid2::solver::owner_answer(payload.get("routine_id").and_then(Value::as_str).unwrap_or(""), payload.get("line").and_then(Value::as_str).unwrap_or(""), payload.get("value").and_then(Value::as_str).unwrap_or("")),
            "start" | "stop" | "restart" => crate::pid2::request_unit(&verb, target),
            _ => Err("pid2-action-unknown".into()),
        }
    }).await;
    respond(result,Some(value),&transition,"pid2",stop_verb,route,if stop_verb == "unplaced-verb" {Some(false)} else {None})
}
pub(crate) fn unit_control(payload: &Value) -> Result<Value,String> {
    unit_control_with_timeout(payload,std::time::Duration::from_secs(300))
}
pub(crate) fn unit_control_with_timeout(payload: &Value, timeout: std::time::Duration) -> Result<Value,String> {
    // Existing PID 2 callers supply the legacy action internally; only nouns
    // cross the staff boundary. Restrict the path to the known unit verbs.
    let action=payload.get("action").and_then(Value::as_str).ok_or("pid2-action-missing")?;
    let band=match action {
        "start"=>"unit/start", "stop"=>"unit/stop", "restart"=>"unit/restart",
        "enable"=>"unit/enable", "disable"=>"unit/disable", "status"=>"unit/status",
        _=>return Err("pid2-action-unknown".into()),
    };
    let nouns=json!({"unit":payload.get("unit"),"scope":payload.get("scope")});
    let result = crate::gate::snake::crossing_path_with_timeout(band,&nouns,timeout)?;
    let receipt = result.get("receiptPayload").cloned().unwrap_or(Value::Null);
    if result.get("ok").and_then(Value::as_bool) != Some(true) || receipt.get("ok").and_then(Value::as_bool) != Some(true)
        || result.get("converged").and_then(Value::as_bool) == Some(false) || receipt.get("converged").and_then(Value::as_bool) == Some(false) {
        return Err(receipt.get("first_missing_signal").and_then(Value::as_str)
            .or_else(|| result.get("firstMissingSignal").and_then(Value::as_str))
            .unwrap_or("pid2-unit-control-refused").to_owned());
    }
    Ok(receipt)
}

async fn schedule_list() -> Response { respond(work(crate::pid2::schedule::list).await,None,"schedule-list","pid2/schedule","list","GET /api/v1/pid2/schedule/list",None) }
async fn schedule_status(Path(id): Path<String>) -> Response { respond(work(move || crate::pid2::schedule::status(&id)).await,None,"schedule-status","pid2/schedule","status","GET /api/v1/pid2/schedule/status/{id}",None) }
async fn schedule_actuator(Json(body):Json<Value>) -> Response {
    let route="POST /api/v1/pid2/schedule/actuator";
    if body.get("actuator").and_then(Value::as_str)!=Some("nas-sync") {return respond(Err("pid2-schedule-actuator-unknown".into()),None,"schedule-actuator","pid2/schedule","actuator",route,Some(false));}
    let metadata=body.get("metadata").cloned().unwrap_or(Value::Null);
    let pre_act = !matches!(metadata.get("action").and_then(Value::as_str), Some("sync-now"|"sync-job-status"|"sync-schedule"|"sync-schedule-update"));
    work(move || crate::pid2::schedule::face(&metadata)).await.map(Json).map_err(|signal|refusal(signal,"pid2/schedule","actuator",route,if pre_act {Some(false)} else {None}))
}
async fn schedule_command(Path(verb): Path<String>, body: Bytes) -> Response {
    let stop_verb=match verb.as_str() {"register"=>"register", "enable"=>"enable", "disable"=>"disable", "update"=>"update", "run"=>"run", _=>"unplaced-verb"};
    let route="POST /api/v1/pid2/schedule/{verb}";
    let value:Value=match serde_json::from_slice(&body) {Ok(v)=>v,Err(e)=>return respond(Err(format!("pid2-invalid-json: {e}")),None,&verb,"pid2/schedule",stop_verb,route,Some(false))};
    if verb=="register" {return respond(work(move || crate::pid2::schedule::register(&body)).await,Some(value),"schedule-register","pid2/schedule",stop_verb,route,None);}
    if let Err(signal)=crate::protocol::Envelope::parse(value.clone()) {return respond(Err(signal),Some(value),&verb,"pid2/schedule",stop_verb,route,Some(false));}
    let payload=value.get("payload").filter(|v|v.is_object()).unwrap_or(&value).clone();
    let transition=format!("schedule-{verb}");
    let result=work(move || {
        let id=payload.get("schedule_id").and_then(Value::as_str).unwrap_or("");
        match verb.as_str() {
            "enable"=>crate::pid2::schedule::set_enabled(id,true,false),
            "disable"=>crate::pid2::schedule::set_enabled(id,false,false),
            "update"=>crate::pid2::schedule::update(id,&payload),
            "run"=>crate::pid2::schedule::queue(id,"owner",None),
            _=>Err("pid2-schedule-action-unknown".into()),
        }
    }).await;
    respond(result,Some(value),&transition,"pid2/schedule",stop_verb,route,if stop_verb == "unplaced-verb" {Some(false)} else {None})
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/pid2/schedule/list", get(schedule_list))
        .route("/api/v1/pid2/schedule/status/:id", get(schedule_status))
        .route("/api/v1/pid2/schedule/actuator", post(schedule_actuator))
        .route("/api/v1/pid2/schedule/:verb", post(schedule_command))
        .route("/api/v1/pid2/list", get(list))
        .route("/api/v1/pid2/status/:id", get(status))
        .route("/api/v1/pid2/:verb", post(command))
}
