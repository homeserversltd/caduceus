use axum::{extract::Json, http::StatusCode, response::{IntoResponse, Response}, Router};
use serde_json::{json, Value};
use std::time::Duration;
#[path = "../support.rs"]
mod support;
const DECLARATION: &str = include_str!("index.json");
const BAND: &str = "network/wifi/radio/get";
const ROUTE: &str = "network/device/wifi/radio";

async fn route(
    Json(body): Json<Value>,
) -> Result<(axum::http::StatusCode, Json<Value>), (axum::http::StatusCode, Json<Value>)> {
    support::execute("network device wifi radio", "radio", body, DECLARATION).await
}

fn failure(signal: &str, raw: Value, crossed: Option<bool>, actual_stop: Value) -> Value {
    json!({
        "schema": "caduceus.staff.receipt.v1",
        "stop": {"noun": ROUTE, "verb": "get"},
        "ok": false,
        "observed": {
            "route": ROUTE,
            "band": BAND,
            "band_crossed": crossed,
            "membrane_error": raw,
            "expected_stop": {"noun": "network/wifi/radio", "verb": "get"},
            "actual_stop": actual_stop
        },
        "could_change_to": null,
        "attempt": {"attempted": crossed},
        "final_receipt": {"ok": false, "firstMissingSignal": signal},
        "firstMissingSignal": signal
    })
}

fn read_radio() -> Result<Value, &'static str> {
    let crossing = match crate::gate::snake::crossing_path_with_timeout(
        BAND, &json!({}), Duration::from_secs(60),
    ) {
        Ok(value) => value,
        Err(error) => {
            let signal = if error == "caduceus-agathodaimon-timeout" {
                "wifi-radio-staff-timeout"
            } else if error.starts_with("caduceus-agathodaimon-output-too-large")
                || error == "caduceus-staff-socket-reply-too-large"
                || error == "caduceus-staff-socket-output-too-large"
            {
                "wifi-radio-staff-output-too-large"
            } else {
                "wifi-radio-staff-unavailable"
            };
            // A completed oversized output or socket reply follows dispatch;
            // other errors may happen before or after crossing.
            let crossed = if signal == "wifi-radio-staff-output-too-large" {
                Some(true)
            } else if error == "caduceus-agathodaimon-cli-missing" {
                Some(false)
            } else {
                None
            };
            return Ok(failure(signal, json!(error), crossed, Value::Null));
        }
    };
    let payload = crossing.get("receiptPayload").cloned().unwrap_or(Value::Null);
    if !payload.is_object() {
        return Ok(failure("wifi-radio-staff-receipt-invalid", payload, Some(true), Value::Null));
    }
    if let Some(stop) = payload.get("stop") {
        if stop.get("noun").and_then(Value::as_str) != Some("network/wifi/radio")
            || stop.get("verb").and_then(Value::as_str) != Some("get")
        {
            return Ok(failure("caduceus-schema-desync", Value::Null, Some(true), stop.clone()));
        }
    }
    Ok(payload)
}

async fn posture() -> Response {
    if !crate::gate::roster_allows("GET", "network/device/wifi/radio").unwrap_or(false) {
        return crate::gate::api_error("network/device/wifi/radio").into_response();
    }
    let value = match tokio::task::spawn_blocking(read_radio).await {
        Ok(Ok(value)) => value,
        Ok(Err(signal)) => failure(signal, Value::Null, None, Value::Null),
        Err(error) => failure("wifi-radio-staff-task-failed", json!(error.to_string()), None, Value::Null),
    };
    let success = value.get("ok").and_then(Value::as_bool) == Some(true)
        && value.get("present").and_then(Value::as_bool).is_some()
        && value.get("enabled").and_then(Value::as_bool).is_some();
    let status = if success { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(value)).into_response()
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/network/device/wifi/radio",
        axum::routing::post(route).get(posture),
    )
}
