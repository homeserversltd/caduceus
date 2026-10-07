/// C2 route leaf.
pub const NAMESPACE: &str = "appliance/stats/history";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/appliance/stats/history",
            axum::routing::get(crate::routes::leaf_appliance_stats::history_http),
        )
}
