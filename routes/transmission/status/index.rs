use axum::http::StatusCode;
use axum::{body::{to_bytes, Body}, http::{header::CONTENT_TYPE, Request}, Json, Router};
use serde_json::{json, Value};
use std::time::Duration;

const COMMAND: &str = "transmission status";
const TIMEOUT: Duration = Duration::from_secs(180);

async fn status_route(
    request: Request<Body>,
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

    let (parts, body) = request.into_parts();
    let failure = |status, signal: &str| {
        let (_, body) = crate::gate::api_error_signal(COMMAND, signal);
        (status, body)
    };
    let bytes = to_bytes(body, 2 * 1024 * 1024).await
        .map_err(|_| failure(StatusCode::PAYLOAD_TOO_LARGE, "caduceus-request-body-too-large"))?;
    let payload = if bytes.is_empty() {
        Value::Null
    } else {
        let json_type = parts.headers.get(CONTENT_TYPE).and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(';').next()).map(str::trim)
            .is_some_and(|v| v.eq_ignore_ascii_case("application/json") || v.to_ascii_lowercase().ends_with("+json"));
        if !json_type {
            return Err(failure(StatusCode::UNSUPPORTED_MEDIA_TYPE, "caduceus-request-content-type-invalid"));
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| failure(StatusCode::BAD_REQUEST, "caduceus-request-body-invalid"))?;
        if !value.is_object() {
            return Err(failure(StatusCode::BAD_REQUEST, "caduceus-request-body-object-required"));
        }
        value
    };
    let envelope = crate::gate::snake::route_envelope("transmission/status", &payload);
    let crossed = crate::gate::snake::execute_ordered_serve_with_timeout(
        &[json!({"snake":"transmission/status"})], &envelope, Some(TIMEOUT),
    ).await;
    let crossing = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
    let receipt = crossing.get("receiptPayload").cloned().ok_or_else(|| {
        crate::gate::service_unavailable(COMMAND, "caduceus-transmission-status-receipt-missing")
    })?;
    if !crate::routes::leaf_schema::bound(&receipt, "transmission/status") {
        return Err(crate::gate::service_unavailable(
            COMMAND,
            "caduceus-schema-desync",
        ));
    }

    Ok((crate::gate::mutation_status(&receipt), Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/transmission/status",
        axum::routing::get(status_route),
    )
}
