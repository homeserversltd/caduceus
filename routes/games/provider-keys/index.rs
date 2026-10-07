/// C2 route leaf.
pub const NAMESPACE: &str = "games/provider-keys";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/games/provider-keys",
            axum::routing::get(crate::routes::leaf_gaming_provider_keys::status),
        )
        .route(
            "/api/v1/games/provider-keys",
            axum::routing::post(crate::routes::leaf_gaming_provider_keys::save),
        )
}
