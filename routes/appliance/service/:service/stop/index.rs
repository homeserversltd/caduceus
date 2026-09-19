/// Homeserver-only service stop leaf.
pub const NAMESPACE: &str = "appliance/service/:service/stop";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/appliance/service/:service/stop",
            axum::routing::post(crate::routes::appliance_support::registered_service_stop_route),
        )
        .route(
            "/api/v1/service/:service/stop",
            axum::routing::post(crate::routes::appliance_support::registered_service_stop_route),
        )
}
