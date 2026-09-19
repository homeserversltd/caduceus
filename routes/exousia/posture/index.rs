/// Profile-gated read-only exousia signer posture.
pub const NAMESPACE: &str = "exousia/posture";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/exousia/posture",
        axum::routing::get(crate::routes::exousia_support::posture_route),
    )
}
