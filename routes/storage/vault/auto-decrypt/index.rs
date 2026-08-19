/// C2 route leaf.
pub const NAMESPACE: &str = "storage/vault/auto-decrypt";

use axum::extract::Json as ExtractJson;
use axum::http::StatusCode;

async fn vault_auto_decrypt_route(
    ExtractJson(body): ExtractJson<crate::gate::VaultAutoBody>,
) -> (StatusCode, axum::Json<serde_json::Value>) {
    (
        StatusCode::OK,
        axum::Json(crate::routes::open_vault::auto_decrypt_json(body.enabled)),
    )
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/storage/vault/auto-decrypt",
        axum::routing::post(vault_auto_decrypt_route),
    )
}
