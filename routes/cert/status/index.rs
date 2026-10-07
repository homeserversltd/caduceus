/// C2 route leaf.
pub const NAMESPACE: &str = "cert/status";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/cert/status",
            axum::routing::get(crate::routes::leaf_network_cert_status::legacy_status),
        )
}
