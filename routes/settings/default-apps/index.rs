pub const PANE: &str = "default-apps";
pub fn read_json() -> Result<serde_json::Value, String> {
    crate::shared::settings::read_json(PANE)
}
pub fn mutate_json(body: serde_json::Value) -> Result<serde_json::Value, String> {
    crate::shared::settings::mutate_json(PANE, body)
}

async fn read_http() -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> { crate::gate::gated_json("settings read", read_json).await }
async fn mutate_http(axum::Json(body): axum::Json<serde_json::Value>) -> Result<(axum::http::StatusCode, axum::Json<serde_json::Value>), (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> { match crate::shared::policy::allows_command("settings mutate") { Ok(true) => mutate_json(body).map(|v|(crate::gate::mutation_status(&v), axum::Json(v))).map_err(|e| crate::gate::api_error_signal("settings mutate", &e)), Ok(false) => Err(crate::gate::api_error("settings mutate")), Err(_) => Err(crate::gate::api_error_signal("settings mutate", "caduceus-profile-missing")) } }

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
