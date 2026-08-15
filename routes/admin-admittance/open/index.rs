/// C2 route leaf.
pub const NAMESPACE: &str = "admin-admittance/open";

/// Canonical registration seam for this leaf.
// HOIST: obliterate after counterparty realignment
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/admin-admittance/open",
            axum::routing::post(crate::routes::admin_admittance_support::attendance_route),
        )
        .route(
            "/api/v1/attendance/open",
            axum::routing::post(crate::routes::admin_admittance_support::attendance_route),
        )
}
