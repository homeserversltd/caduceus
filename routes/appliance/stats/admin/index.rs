/// C2 route leaf for attended administrative telemetry.
pub const NAMESPACE: &str = "appliance/stats/admin";

use crate::gate::{gated_body, ApiErrorBody};

const STATS_COMMAND: &str = "appliance stats admin";

fn json_response(body: String) -> axum::response::Response {
    axum::response::IntoResponse::into_response((
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        axum::body::Body::from(body),
    ))
}

async fn current_admin_http(
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, (axum::http::StatusCode, axum::Json<ApiErrorBody>)> {
    crate::gate::document_attendance_admits(
        headers
            .get("x-caduceus-document")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default(),
        headers
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| crate::gate::api_error_signal(STATS_COMMAND, &signal))?;
    gated_body(STATS_COMMAND, crate::stats::current_admin)
        .await
        .map(json_response)
}

/// Register the protected administrative current-sample endpoint.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/appliance/stats/admin",
        axum::routing::get(current_admin_http),
    )
}
