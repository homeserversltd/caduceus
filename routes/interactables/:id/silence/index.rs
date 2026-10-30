use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{harmonia, policy};
use axum::{extract::Path, http::StatusCode, Json};
use serde_json::Value;

pub const NAMESPACE: &str = "interactables/:id/silence";

pub(crate) async fn route(
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("interactable silence") {
        Ok(true) => {
            let (code, body) = crate::gate::blocking_task("interactable silence", move || {
                harmonia::invoke("interactable_silence", &[id], false)
            })
            .await?;
            if code != 0 {
                return Err(api_error_signal("interactable silence", "caduceus-harmonia-command-failed"));
            }
            let value = serde_json::from_str(&body)
                .map_err(|_| api_error_signal("interactable silence", "caduceus-harmonia-command-failed"))?;
            Ok((StatusCode::OK, Json(value)))
        }
        Ok(false) => Err(api_error("interactable silence")),
        Err(_) => Err(api_error_signal(
            "interactable silence",
            "caduceus-profile-missing",
        )),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/interactables/:id/silence", axum::routing::post(route))
}
