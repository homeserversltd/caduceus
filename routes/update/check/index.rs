/// C2 route leaf.
pub const NAMESPACE: &str = "update/check";

/// Canonical registration seam for this leaf.
// HOIST: obliterate after counterparty realignment
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/update/check",
            axum::routing::post(crate::routes::update_support::update_check_route),
        )
        .route(
            "/api/v1/update/service/status",
            axum::routing::get(crate::routes::update_support::update_service_status_route),
        )
        .route(
            "/api/v1/update/service/toggle",
            axum::routing::post(crate::routes::update_support::update_service_toggle_route),
        )
}
