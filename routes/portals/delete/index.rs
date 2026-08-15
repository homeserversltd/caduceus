/// C2 route leaf.
pub const NAMESPACE: &str = "portals/delete";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
