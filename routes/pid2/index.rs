use axum::{body::Bytes, extract::Path, http::StatusCode, routing::{get, post}, Json, Router};
use serde_json::{json, Value};

type Response = Result<Json<Value>, (StatusCode, Json<Value>)>;
fn respond(result: Result<Value, String>, request: Option<Value>, transition: &str) -> Response {
    result.map(|receipt| Json(json!({
        "schema": crate::protocol::SCHEMA_ID,
        "intent_id": request.as_ref().and_then(|r| r.get("intent_id")).cloned().unwrap_or_else(||json!(format!("caduceus-pid2-{transition}"))),
        "transition": transition,
        "version": env!("CARGO_PKG_VERSION"),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "rawEnvelope": request,
        "receiptPayload": receipt
    }))).map_err(|signal| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"first_missing_signal":signal}))))
}
static IN_FLIGHT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(16);
async fn work<F>(run: F) -> Result<Value,String>
where F: FnOnce()->Result<Value,String> + Send + 'static {
    let permit=IN_FLIGHT.try_acquire().map_err(|_|"pid2-door-busy".to_string())?;
    tokio::task::spawn_blocking(move || { let _permit=permit; run() }).await.map_err(|_|"pid2-door-task-failed".to_string())?
}
async fn list() -> Response { respond(work(crate::pid2::list).await,None,"pid2-list") }
async fn status(Path(id): Path<String>) -> Response { respond(work(move || crate::pid2::status(&id)).await,None,"pid2-status") }
async fn command(Path(verb): Path<String>, body: Bytes) -> Response {
    let value: Value = match serde_json::from_slice(&body) { Ok(v) => v, Err(e) => return respond(Err(format!("pid2-invalid-json: {e}")),None,&verb) };
    if verb == "enable" { return respond(work(move || crate::pid2::enable(&body)).await,Some(value),"pid2-enable"); }
    if let Err(signal)=crate::protocol::Envelope::parse(value.clone()) { return respond(Err(signal),Some(value),&verb); }
    let payload=value.get("payload").filter(|v|v.is_object()).unwrap_or(&value).clone();
    let transition=format!("pid2-{verb}");
    let result=work(move || {
        let target=payload.get("routine_id").or_else(||payload.get("unit")).and_then(Value::as_str).unwrap_or("");
        match verb.as_str() {
            "disable" => crate::pid2::disable(target),
            "answer" => crate::pid2::solver::owner_answer(payload.get("routine_id").and_then(Value::as_str).unwrap_or(""), payload.get("line").and_then(Value::as_str).unwrap_or(""), payload.get("value").and_then(Value::as_str).unwrap_or("")),
            "start" | "stop" | "restart" => crate::pid2::request_unit(&verb, target),
            _ => Err("pid2-action-unknown".into()),
        }
    }).await;
    respond(result,Some(value),&transition)
}
pub(crate) fn unit_control(payload: &Value) -> Result<Value,String> {
    let result = crate::gate::snake::crossing_path_with_timeout("unit/control",payload,std::time::Duration::from_secs(300))?;
    let receipt = result.get("receiptPayload").cloned().unwrap_or(Value::Null);
    if result.get("ok").and_then(Value::as_bool) != Some(true) || receipt.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(receipt.get("first_missing_signal").and_then(Value::as_str)
            .or_else(|| result.get("firstMissingSignal").and_then(Value::as_str))
            .unwrap_or("pid2-unit-control-refused").to_owned());
    }
    Ok(receipt)
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/pid2/list", get(list))
        .route("/api/v1/pid2/status/:id", get(status))
        .route("/api/v1/pid2/:verb", post(command))
}
