/// C2 route leaf.
pub const NAMESPACE: &str = "settings/pin";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
