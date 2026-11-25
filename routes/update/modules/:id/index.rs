use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use axum::{extract::Path, http::StatusCode, Json};
use serde::Deserialize;
use serde_json::Value;

pub const NAMESPACE: &str = "update/modules/:id";
const COMMAND: &str = "update modules toggle";

#[derive(Deserialize)]
pub(crate) struct TogglePayload {
    enabled: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum ToggleBody {
    Envelope { payload: TogglePayload },
    Direct(TogglePayload),
}

pub(crate) async fn route(
    Path(id): Path<String>,
    Json(body): Json<ToggleBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {
            let operation_id = id.clone();
            let enabled = match body { ToggleBody::Envelope { payload } | ToggleBody::Direct(payload) => payload.enabled };
            let result = crate::gate::blocking_task(COMMAND, move || {
                crate::routes::toggle_harmonia_module::toggle_staff(&operation_id, enabled)
            })
            .await?;
            match result {
                Ok(receipt) => Ok((crate::gate::mutation_status(&receipt), Json(receipt))),
                Err(e) => Err(api_error_signal(COMMAND, &e)),
            }
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/update/modules/:id", axum::routing::post(route))
}
