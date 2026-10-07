/// C2 route leaf.
pub const NAMESPACE: &str = "appliance/model-lanes/pulse";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/appliance/model-lanes/pulse",
            axum::routing::post(crate::routes::leaf_appliance_stats::pulse_http),
        )
}
