pub use crate::routes::cartridges_shared::{passage_bytes, CartridgeError};

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/cartridges",
        axum::routing::get(crate::routes::cartridges_route_support::cartridges_route),
    )
}
