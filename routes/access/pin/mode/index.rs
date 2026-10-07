/// C2 route leaf.
pub const NAMESPACE: &str = "access/pin/mode";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/access/pin/mode",
            axum::routing::get(crate::routes::exousia_support::pin_mode_read_route)
                .post(crate::routes::exousia_support::pin_mode_route),
        )
}
