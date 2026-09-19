/// Homeserver-only service disable leaf.
pub const NAMESPACE: &str = "appliance/service/:service/disable";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/appliance/service/:service/disable",
            axum::routing::post(crate::routes::appliance_support::registered_service_disable_route),
        )
        .route(
            "/api/v1/service/:service/disable",
            axum::routing::post(crate::routes::appliance_support::registered_service_disable_route),
        )
}
