/// C2 route leaf.
pub const NAMESPACE: &str = "update/check";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/update/check",
            axum::routing::post(crate::routes::update_support::update_check_route),
        )
}
