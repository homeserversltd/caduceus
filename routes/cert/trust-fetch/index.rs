/// C2 route leaf.
pub const NAMESPACE: &str = "cert/trust-fetch";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/cert/trust-fetch",
            axum::routing::post(crate::routes::leaf_network_cert_trust::trust_fetch),
        )
}
