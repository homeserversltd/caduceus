/// Homeserver-only service start leaf.
pub const NAMESPACE: &str = "appliance/service/:service/start";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/appliance/service/:service/start",
            axum::routing::post(crate::routes::appliance_support::registered_service_start_route),
        )
        .route(
            "/api/v1/service/:service/start",
            axum::routing::post(crate::routes::appliance_support::registered_service_start_route),
        )
}
