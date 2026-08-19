/// C2 route leaf.
pub const NAMESPACE: &str = "console/restart";

use axum::{extract::Json, http::StatusCode, Router};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Degree {
    Steam,
    Stream,
    Seat,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartBody {
    degree: Degree,
}

fn bad_request(command: &str, signal: impl Into<String>) -> (StatusCode, Json<crate::gate::ApiErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(crate::gate::ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.to_string(),
            first_missing_signal: signal.into(),
        }),
    )
}

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

async fn restart(
    Json(raw): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let body: RestartBody = serde_json::from_value(raw).map_err(|error| {
        let signal = if error.to_string().contains("unknown variant") {
            "caduceus-console-restart-degree-invalid: expected steam|stream|seat"
        } else {
            "caduceus-console-restart-request-invalid"
        };
        bad_request("console restart", signal)
    })?;
    let degree = match body.degree {
        Degree::Steam => "steam",
        Degree::Stream => "stream",
        Degree::Seat => "seat",
    };
    let payload = json!({"degree": degree});
    match crate::shared::policy::allows_command("console restart") {
        Ok(true) => crate::gate::snake::crossing_path("console/restart", &payload)
            .map(|value| (crate::gate::mutation_status(&value), Json(value)))
            .map_err(|signal| staff_refusal("console restart", signal)),
        Ok(false) => Err(crate::gate::api_error("console restart")),
        Err(_) => Err(crate::gate::api_error_signal(
            "console restart",
            "caduceus-profile-missing",
        )),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/console/restart", axum::routing::post(restart))
}
