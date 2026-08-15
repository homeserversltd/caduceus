pub use crate::routes::cartridges_shared::{admit, Cartridge, CartridgeError};

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/cartridges/admit",
        axum::routing::post(crate::routes::cartridges_route_support::cartridges_admit_route),
    )
}
