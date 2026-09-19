/// Homeserver-only service status leaf.
pub const NAMESPACE: &str = "appliance/service/:service/status";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/appliance/service/:service/status",
            axum::routing::post(crate::routes::appliance_support::registered_service_status_route),
        )
        .route(
            "/api/v1/service/:service/status",
            axum::routing::post(crate::routes::appliance_support::registered_service_status_route),
        )
}
