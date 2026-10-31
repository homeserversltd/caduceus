use axum::{
    extract::Query,
    http::{HeaderMap, StatusCode},
    routing::get,
    Json as ResponseJson, Router,
};
use serde_json::Value;
use std::collections::HashMap;
use std::time::Duration;

pub const NAMESPACE: &str = "linker/hardlink-scan";
const COMMAND: &str = "linker hardlink-scan";
const BAND: &str = "linker/hardlink-scan";

type DoorReply = Result<
    (StatusCode, ResponseJson<Value>),
    (StatusCode, ResponseJson<crate::gate::ApiErrorBody>),
>;

fn admit_document(
    headers: &HeaderMap,
) -> Result<(), (StatusCode, ResponseJson<crate::gate::ApiErrorBody>)> {
    let document = headers
        .get("x-caduceus-document")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    let attendance = headers
        .get("x-caduceus-attendance")
        .and_then(|value| value.to_str().ok());
    crate::gate::document_attendance_admits(document, attendance).map_err(|signal| {
        (
            StatusCode::UNAUTHORIZED,
            ResponseJson(crate::gate::ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: COMMAND.into(),
                first_missing_signal: signal,
            }),
        )
    })
}

async fn cross(headers: HeaderMap, payload: Value) -> DoorReply {
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {},
        Ok(false) => return Err(crate::gate::api_error(COMMAND)),
        Err(_) => {
            return Err(crate::gate::api_error_signal(
                COMMAND,
                "caduceus-carapace-desync",
            ));
        }
    }
    admit_document(&headers)?;

    let result = crate::gate::blocking_task(COMMAND, move || {
        crate::gate::snake::crossing_path_with_timeout(
            BAND,
            &payload,
            Duration::from_secs(30),
        )
    })
    .await?;

    match result {
        Ok(executor) => {
            let Some(receipt_payload) = executor.get("receiptPayload").cloned() else {
                return Err(crate::gate::service_unavailable(
                    COMMAND,
                    "caduceus-snake-receipt-payload-missing",
                ));
            };
            let status = if executor.get("ok").and_then(Value::as_bool) == Some(true)
                && receipt_payload.get("ok").and_then(Value::as_bool) == Some(true)
                && receipt_payload.get("converged").and_then(Value::as_bool) != Some(false)
            {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            Ok((status, ResponseJson(receipt_payload)))
        }
        Err(signal) => Err(crate::gate::service_unavailable(COMMAND, &signal)),
    }
}

async fn route(
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> DoorReply {
    let payload = Value::Object(
        query
            .into_iter()
            .map(|(key, value)| (key, Value::String(value)))
            .collect(),
    );
    cross(headers, payload).await
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/linker/hardlink-scan", get(route))
}
