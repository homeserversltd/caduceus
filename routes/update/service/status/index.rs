/// C2 route leaf.
pub const NAMESPACE: &str = "update/service/status";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/update/service/status",
            axum::routing::get(crate::routes::update_support::update_service_status_route),
        )
}
