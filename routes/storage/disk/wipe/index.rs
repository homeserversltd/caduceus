/// C2 route leaf.
pub const NAMESPACE: &str = "storage/disk/wipe";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
