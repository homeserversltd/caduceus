/// C2 route leaf.
pub const NAMESPACE: &str = "storage/vault/auto-decrypt";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
