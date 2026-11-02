use axum::{http::StatusCode, Json, Router};
use serde_json::{json, Value};
use std::time::Duration;

const ROUTE: &str = "local-ai/nap";

async fn nap(
    Json(body): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    if !crate::gate::roster_allows("POST", ROUTE).unwrap_or(false) {
        return Err(crate::gate::api_error(ROUTE));
    }
    let crossing = crate::gate::blocking_task(ROUTE, move || {
        crate::gate::snake::crossing_path_with_timeout(ROUTE, &body, Duration::from_secs(180))
    }).await?
      .map_err(|signal| crate::gate::service_unavailable(ROUTE, &signal))?;
    let receipt = crossing.get("receiptPayload").filter(|value| value.is_object())
        .ok_or_else(|| crate::gate::service_unavailable(ROUTE, "local-ai-nap-receipt-missing"))?;
    if crossing.get("ok").and_then(Value::as_bool) != Some(true)
        || crossing.get("converged").and_then(Value::as_bool) == Some(false)
        || receipt.get("ok").and_then(Value::as_bool) != Some(true)
        || receipt.get("converged").and_then(Value::as_bool) == Some(false)
    {
        let signal = receipt.get("firstMissingSignal").or_else(|| receipt.get("signal"))
            .and_then(Value::as_str).unwrap_or("local-ai-nap-refused");
        return Err(crate::gate::service_unavailable(ROUTE, signal));
    }
    let mut answer = serde_json::Map::new();
    answer.insert("route".into(), json!(ROUTE));
    answer.insert("ok".into(), json!(true));
    for name in ["judged", "folded", "stale", "gist"] {
        let count = receipt.get(name).and_then(Value::as_u64)
            .ok_or_else(|| crate::gate::service_unavailable(ROUTE, "local-ai-nap-count-missing"))?;
        answer.insert(name.into(), json!(count));
    }
    Ok((StatusCode::OK, Json(Value::Object(answer))))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/local-ai/nap", axum::routing::post(nap))
}
