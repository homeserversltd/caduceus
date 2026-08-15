/// C2 route leaf.
pub const NAMESPACE: &str = "admin-admittance/invalidate";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/admin-admittance/invalidate",
            axum::routing::post(crate::routes::admin_admittance_support::attendance_route),
        )
}
