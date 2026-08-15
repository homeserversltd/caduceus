/// C2 route leaf.
pub const NAMESPACE: &str = "appliance/claim";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
