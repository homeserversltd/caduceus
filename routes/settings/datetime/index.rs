pub const PANE: &str = "datetime";
pub fn read_json() -> Result<serde_json::Value, String> {
    crate::shared::settings::read_json(PANE)
}
pub fn mutate_json(body: serde_json::Value) -> Result<serde_json::Value, String> {
    crate::shared::settings::mutate_json(PANE, body)
}

async fn read_http() -> Result<axum::Json<serde_json::Value>, (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> {
    let command = crate::shared::settings::read_command(PANE)
        .expect("registered settings family has a read command");
    crate::gate::gated_json(&command, read_json).await
}
async fn mutate_http(axum::Json(body): axum::Json<serde_json::Value>) -> Result<(axum::http::StatusCode, axum::Json<serde_json::Value>), (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> {
    let command = crate::shared::settings::mutate_command(PANE)
        .expect("registered settings family has a mutate command");
    match crate::shared::policy::allows_command(&command) {
        Ok(true) => mutate_json(body)
            .map(|v| (crate::gate::mutation_status(&v), axum::Json(v)))
            .map_err(|e| crate::gate::api_error_signal(&command, &e)),
        Ok(false) => Err(crate::gate::api_error(&command)),
        Err(_) => Err(crate::gate::api_error_signal(
            &command,
            "caduceus-profile-missing",
        )),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/settings/datetime", axum::routing::get(read_http).put(mutate_http).patch(mutate_http))
}
