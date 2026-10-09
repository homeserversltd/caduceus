/// C2 route leaf.
pub const NAMESPACE: &str = "storage/vault/auto-decrypt";

use axum::extract::Json as ExtractJson;
use axum::http::StatusCode;

async fn vault_auto_decrypt_route(
    ExtractJson(body): ExtractJson<crate::gate::VaultAutoBody>,
) -> Result<(StatusCode, axum::Json<serde_json::Value>), (StatusCode, axum::Json<crate::gate::ApiErrorBody>)> {
    let value = crate::gate::blocking_task("vault auto-decrypt", move || {
        crate::routes::open_vault::auto_decrypt_json(body.enabled)
    })
    .await?;
    Ok((
        StatusCode::OK,
        axum::Json(value),
    ))
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/storage/vault/auto-decrypt",
        axum::routing::post(vault_auto_decrypt_route),
    )
}
