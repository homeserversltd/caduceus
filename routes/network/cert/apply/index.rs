/// C2 route leaf.
pub const NAMESPACE: &str = "network/cert/apply";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
