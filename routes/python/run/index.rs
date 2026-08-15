/// C2 route leaf.
pub const NAMESPACE: &str = "python/run";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
