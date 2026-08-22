use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{harmonia, policy};
use axum::{extract::Path, http::StatusCode, Json};
use serde_json::Value;

pub const NAMESPACE: &str = "interactables/:id/run";

pub(crate) async fn route(
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("interactable run") {
        Ok(true) => {
            let (code, body) = harmonia::invoke("interactable_run", &[id], false);
            let value = harmonia::invoke_body_to_json("interactable_run", code, &body);
            Ok((
                if value.get("ok").and_then(Value::as_bool) == Some(true) {
                    StatusCode::OK
                } else {
                    StatusCode::SERVICE_UNAVAILABLE
                },
                Json(value),
            ))
        }
        Ok(false) => Err(api_error("interactable run")),
        Err(_) => Err(api_error_signal(
            "interactable run",
            "caduceus-profile-missing",
        )),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/interactables/:id/run", axum::routing::post(route))
}
