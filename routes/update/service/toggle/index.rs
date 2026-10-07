/// C2 route leaf.
pub const NAMESPACE: &str = "update/service/toggle";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/update/service/toggle",
            axum::routing::post(crate::routes::update_support::update_service_toggle_route),
        )
}
