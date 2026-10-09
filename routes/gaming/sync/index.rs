/// C2 route leaf.
pub const NAMESPACE: &str = "gaming/sync";

use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};

fn staff_refusal(command: &str, signal: String) -> (StatusCode, Json<crate::gate::ApiErrorBody>) {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(crate::gate::ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.to_string(),
            first_missing_signal: signal,
        }),
    )
}

pub(super) async fn sync() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)>
{
    let body = json!({});
    match crate::shared::policy::allows_command("gaming sync") {
        Ok(true) => {
            let result = crate::gate::blocking_task("gaming sync", move || {
                crate::gate::snake::crossing_path("games/sync", &body)
            })
            .await?;
            result
                .map(|value| (crate::gate::mutation_status(&value), Json(value)))
                .map_err(|signal| staff_refusal("gaming sync", signal))
        }
        Ok(false) => Err(crate::gate::api_error("gaming sync")),
        Err(_) => Err(crate::gate::api_error_signal(
            "gaming sync",
            "caduceus-profile-missing",
        )),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router
        .route("/api/v1/gaming/sync", axum::routing::post(sync))
}
