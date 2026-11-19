use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{hyalos::TailFilters, policy};
use axum::{extract::Query, http::StatusCode, routing::get, Json, Router};
use serde_json::Value;
use std::collections::HashMap;

pub const NAMESPACE: &str = "log/tail";
const COMMAND: &str = "hyalos tail";

async fn http(
    Query(query): Query<HashMap<String, String>>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let filters = TailFilters {
        count: query.get("count").and_then(|x| x.parse().ok()).unwrap_or(20),
        kind: query.get("kind").cloned(),
        organ: query.get("organ").cloned(),
        world: query.get("world").cloned(),
        correlation_id: query.get("correlation_id").or_else(|| query.get("correlationId")).cloned(),
        level: query.get("level").cloned(),
        ok: query.get("ok").and_then(|x| x.parse().ok()),
    };
    match policy::allows_command(COMMAND) {
        Ok(true) => {
            let result = crate::gate::blocking_task(COMMAND, move || crate::routes::hyalos::tail_json(filters)).await?;
            result.map(|value| (StatusCode::OK, Json(value))).map_err(|error| {
                let (status, body) = api_error_signal(COMMAND, &error);
                let status = match error.as_str() {
                    "hyalos-tail-level-invalid" | "hyalos-tail-world-unavailable" => StatusCode::BAD_REQUEST,
                    _ => status,
                };
                (status, body)
            })
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
}

/// Register the same handler on every path the gate classifies as this leaf.
pub fn register(mut router: Router) -> Router {
    let declaration: Value = serde_json::from_str(include_str!("index.json")).expect("log/tail declaration");
    router = router.route(declaration["http_path"].as_str().expect("log/tail path"), get(http));
    for alias in declaration["http_aliases"].as_array().expect("log/tail aliases") {
        router = router.route(alias.as_str().expect("log/tail alias path"), get(http));
    }
    router
}
