pub const NAMESPACE: &str = "display/projector/products";
pub use crate::routes::control_projector::*;

async fn devices_http() -> Result<
    axum::Json<serde_json::Value>,
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    crate::gate::gated_json(
        "pjlink devices",
        crate::routes::control_projector::devices_json,
    )
    .await
}
async fn known_add(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    let c = "pjlink known add";
    match crate::shared::policy::allows_command(c) {
        Ok(true) => crate::routes::control_projector::add_known_product_json(
            body.get("deviceId").and_then(|v| v.as_str()).unwrap_or(""),
            body.get("dryRun")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            body.get("fromProfile")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        )
        .map(|v| (crate::gate::mutation_status(&v), axum::Json(v)))
        .map_err(|e| crate::gate::api_error_signal(c, &e)),
        Ok(false) => Err(crate::gate::api_error(c)),
        Err(_) => Err(crate::gate::api_error_signal(c, "caduceus-profile-missing")),
    }
}
async fn known_http() -> Result<
    axum::Json<serde_json::Value>,
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    crate::gate::gated_json(
        "pjlink known-products",
        crate::routes::control_projector::known_products_json,
    )
    .await
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/display/projector/products",
            axum::routing::get(devices_http),
        )
        .route("/api/v1/pjlink/devices", axum::routing::get(devices_http))
        .route(
            "/api/v1/pjlink/known-products",
            axum::routing::get(known_http).post(known_add),
        )
}
