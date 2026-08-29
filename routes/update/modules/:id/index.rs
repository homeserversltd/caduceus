use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use axum::{extract::Path, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::{json, Value};

pub const NAMESPACE: &str = "update/modules/:id";
const COMMAND: &str = "update modules toggle";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToggleBody {
    enabled: bool,
}

pub(crate) async fn route(
    Path(id): Path<String>,
    Json(body): Json<ToggleBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => match crate::routes::toggle_harmonia_module::toggle_json(&id, body.enabled) {
            Ok(_) => Ok((
                StatusCode::OK,
                Json(json!({
                    "schema": "caduceus.update.modules.mutate.v1",
                    "ok": true,
                    "id": id,
                    "enabled": body.enabled,
                    "firstMissingSignal": "none"
                })),
            )),
            Err(e) => Err(api_error_signal(COMMAND, &e)),
        },
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/update/modules/:id", axum::routing::post(route))
}
