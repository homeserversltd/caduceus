/// C2 route leaf.
pub const NAMESPACE: &str = "games/sync";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/games/sync",
            axum::routing::post(crate::routes::leaf_gaming_sync::sync),
        )
}
