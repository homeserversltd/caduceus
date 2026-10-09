/// C2 route leaf.
pub const NAMESPACE: &str = "storage/vault/status";

use axum::Json;
use serde_json::Value;

async fn vault_status_route() -> Result<Json<Value>, (axum::http::StatusCode, Json<crate::gate::ApiErrorBody>)> {
    crate::gate::blocking_task("vault status", crate::routes::open_vault::status_json)
        .await
        .map(Json)
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/storage/vault/status",
        axum::routing::get(vault_status_route),
    )
}
