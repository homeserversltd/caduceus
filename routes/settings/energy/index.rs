pub const PANE: &str = "energy";
pub fn read_json() -> Result<serde_json::Value, String> {
    crate::shared::settings::read_json(PANE)
}
pub fn mutate_json(body: serde_json::Value) -> Result<serde_json::Value, String> {
    crate::shared::settings::mutate_json(PANE, body)
}

async fn read_http() -> crate::shared::settings::HttpReply {
    crate::shared::settings::read_http(PANE).await
}
async fn mutate_http(axum::Json(body): axum::Json<serde_json::Value>) -> crate::shared::settings::HttpReply {
    crate::shared::settings::mutate_http(PANE, body).await
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/settings/energy", axum::routing::get(read_http).put(mutate_http).patch(mutate_http))
}
