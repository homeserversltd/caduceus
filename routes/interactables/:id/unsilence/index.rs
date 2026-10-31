use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{harmonia, policy};
use axum::{extract::Path, http::StatusCode, Json};
use serde_json::Value;

pub const NAMESPACE: &str = "interactables/:id/unsilence";

pub(crate) async fn route(
    Path(id): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("interactable unsilence") {
        Ok(true) => {
            let (code, body) = crate::gate::blocking_task("interactable unsilence", move || {
                harmonia::invoke("interactable_unsilence", &[id], false)
            })
            .await?;
            if code != 0 {
                return Err(api_error_signal("interactable unsilence", "caduceus-harmonia-command-failed"));
            }
            let value = serde_json::from_str(&body)
                .map_err(|_| api_error_signal("interactable unsilence", "caduceus-harmonia-command-failed"))?;
            Ok((StatusCode::OK, Json(value)))
        }
        Ok(false) => Err(api_error("interactable unsilence")),
        Err(_) => Err(api_error_signal(
            "interactable unsilence",
            "caduceus-carapace-desync",
        )),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/interactables/:id/unsilence", axum::routing::post(route))
}
