pub const NAMESPACE: &str = "display/projector/scan";
pub use crate::routes::control_projector::*;
async fn scan_http(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    let command = "pjlink scan";
    match crate::shared::policy::allows_command(command) {
        Ok(true) => {
            let id = body.get("deviceId").and_then(|v| v.as_str()).unwrap_or("");
            let dry = body
                .get("dryRun")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            crate::routes::control_projector::scan_product_json(id, dry)
                .map(|v| (crate::gate::mutation_status(&v), axum::Json(v)))
                .map_err(|e| crate::gate::api_error_signal(command, &e))
        }
        Ok(false) => Err(crate::gate::api_error(command)),
        Err(_) => Err(crate::gate::api_error_signal(
            command,
            "caduceus-profile-missing",
        )),
    }
}
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/display/projector/scan",
            axum::routing::post(scan_http),
        )
        .route(
            "/api/v1/pjlink/product/scan",
            axum::routing::post(scan_http),
        )
}
