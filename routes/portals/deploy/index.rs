/// Canonical C2 leaf; real handler is owned by the legacy-compatible support band.
pub const NAMESPACE: &str = "portals/deploy";
pub use crate::routes::report_links::*;

async fn staff_route(
    actuator: &str,
    body: serde_json::Value,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    match crate::shared::policy::allows_command("staff intent") {
        Ok(true) => crate::routes::staff::named_actuator_json(actuator, body)
            .map(|v| (crate::gate::mutation_status(&v), axum::Json(v)))
            .map_err(|e| crate::gate::api_error_signal("staff intent", &e)),
        Ok(false) => Err(crate::gate::api_error("staff intent")),
        Err(_) => Err(crate::gate::api_error_signal(
            "staff intent",
            "caduceus-profile-missing",
        )),
    }
}

async fn file_ingress(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    staff_route("file-ingress", body).await
}

async fn force_permissions(
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    staff_route("upload-force-permissions", body).await
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/file/ingress", axum::routing::post(file_ingress))
        .route(
            "/api/v1/upload/force-permissions",
            axum::routing::post(force_permissions),
        )
}
