/// Homeserver-only service enable leaf.
pub const NAMESPACE: &str = "appliance/service/:service/enable";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/appliance/service/:service/enable",
            axum::routing::post(crate::routes::appliance_support::registered_service_enable_route),
        )
        .route(
            "/api/v1/service/:service/enable",
            axum::routing::post(crate::routes::appliance_support::registered_service_enable_route),
        )
}
