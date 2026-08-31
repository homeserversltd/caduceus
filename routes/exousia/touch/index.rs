/// C2 route leaf.
pub const NAMESPACE: &str = "exousia/touch";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/exousia/touch",
            axum::routing::post(crate::routes::exousia_support::attendance_route),
        )
        .route(
            "/api/v1/attendance/touch",
            axum::routing::post(crate::routes::exousia_support::attendance_route),
        )
}
