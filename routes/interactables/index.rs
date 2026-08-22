use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{harmonia, policy};
use axum::{body::Body, http::StatusCode, response::Response};

pub const NAMESPACE: &str = "interactables";

pub(crate) async fn route() -> Result<Response, (StatusCode, axum::Json<ApiErrorBody>)> {
    match policy::allows_command("interactable list") {
        Ok(true) => {
            let (code, body) = harmonia::invoke("interactable_list", &[], false);
            if code != 0 {
                return Err(api_error_signal(
                    "interactable list",
                    "caduceus-harmonia-command-failed",
                ));
            }
            Ok(Response::builder()
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("interactable list response is valid"))
        }
        Ok(false) => Err(api_error("interactable list")),
        Err(_) => Err(api_error_signal(
            "interactable list",
            "caduceus-profile-missing",
        )),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/interactables", axum::routing::get(route))
}
