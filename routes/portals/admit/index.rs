pub use crate::routes::issue_certificate::{apply_json, constituent_lock_json, portal_admit_json};

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
