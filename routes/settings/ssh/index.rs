use crate::routes::control_service;
use serde_json::Value;
pub fn service(metadata: Value) -> Result<Value, String> {
    control_service::execute_service(metadata)
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
