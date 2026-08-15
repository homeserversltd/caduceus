/// C2 route leaf.
pub const NAMESPACE: &str = "admin-admittance/open";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/admin-admittance/open",
            axum::routing::post(crate::routes::admin_admittance_support::attendance_route),
        )
}
