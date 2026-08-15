pub use crate::routes::issue_certificate::{trust_fetch_json, trust_install_json};

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
