/// C2 route leaf.
pub const NAMESPACE: &str = "exousia/validate";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/exousia/validate",
            axum::routing::post(crate::routes::exousia_support::attendance_route),
        )
        .route(
            "/api/v1/attendance/validate",
            axum::routing::post(crate::routes::exousia_support::attendance_route),
        )
}
