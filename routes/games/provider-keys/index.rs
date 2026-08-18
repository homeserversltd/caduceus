/// C2 route leaf.
pub const NAMESPACE: &str = "games/provider-keys";

use axum::{extract::Json, http::StatusCode, Router};
use serde::Deserialize;
use serde_json::{json, Map, Value};

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

const PROVIDERS: &[(&str, &str)] = &[
    ("steamgriddb", "STEAMGRIDDB_API_KEY"),
    ("thegamesdb", "THEGAMESDB_API_KEY"),
    ("screenscraper", "SCREENSCRAPER_API_KEY"),
];

fn bad_request() -> (StatusCode, Json<crate::gate::ApiErrorBody>) {
    (
        StatusCode::BAD_REQUEST,
        Json(crate::gate::ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: "games provider-keys save".to_string(),
            first_missing_signal: "caduceus-games-provider-keys-empty".to_string(),
        }),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderKeysBody {
    steamgriddb_api_key: Option<String>,
    thegamesdb_api_key: Option<String>,
    screenscraper_api_key: Option<String>,
}

fn configured(value: Option<&Value>) -> bool {
    match value {
        Some(Value::String(value)) => !value.trim().is_empty(),
        Some(Value::Object(object)) => object
            .get("configured")
            .and_then(Value::as_bool)
            .or_else(|| object.get("present").and_then(Value::as_bool))
            .unwrap_or(false),
        Some(Value::Bool(value)) => *value,
        _ => false,
    }
}

fn public_keys(value: &Value) -> Value {
    let source = value
        .get("configured")
        .or_else(|| value.get("keys"))
        .and_then(Value::as_object);
    let mut keys = Map::new();
    for (provider, env_key) in PROVIDERS {
        keys.insert(
            (*provider).into(),
            json!({"configured": configured(source.and_then(|object| object.get(*env_key))), "envKey": env_key}),
        );
    }
    json!({"schema":"caduceus.games.provider-keys.v1","ok":true,"keys":keys})
}

async fn status() -> Result<Json<Value>, (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    match crate::shared::policy::allows_command("games provider-keys read") {
        Ok(true) => crate::gate::snake::crossing_path(
            "games/provider-keys",
            &json!({"verb":"status","args":["status"]}),
        )
        .map(|value| Json(public_keys(&value)))
        .map_err(|signal| staff_refusal("games provider-keys read", signal)),
        Ok(false) => Err(crate::gate::api_error("games provider-keys read")),
        Err(_) => Err(crate::gate::api_error_signal(
            "games provider-keys read",
            "caduceus-profile-missing",
        )),
    }
}

async fn save(
    Json(body): Json<ProviderKeysBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let keys = [
        ("STEAMGRIDDB_API_KEY", body.steamgriddb_api_key),
        ("THEGAMESDB_API_KEY", body.thegamesdb_api_key),
        ("SCREENSCRAPER_API_KEY", body.screenscraper_api_key),
    ]
    .into_iter()
    .filter_map(|(name, value)| {
        value.and_then(|value| {
            (!value.trim().is_empty()).then_some((name.to_string(), Value::String(value)))
        })
    })
    .collect::<Map<_, _>>();
    if keys.is_empty() {
        return Err(bad_request());
    }
    let payload = json!({"verb":"save","args":["save"],"keys":keys});
    match crate::shared::policy::allows_command("games provider-keys save") {
        Ok(true) => crate::gate::snake::crossing_path("games/provider-keys", &payload)
            .map(|value| (crate::gate::mutation_status(&value), Json(value)))
            .map_err(|signal| staff_refusal("games provider-keys save", signal)),
        Ok(false) => Err(crate::gate::api_error("games provider-keys save")),
        Err(_) => Err(crate::gate::api_error_signal(
            "games provider-keys save",
            "caduceus-profile-missing",
        )),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router
        .route("/api/v1/games/provider-keys", axum::routing::get(status))
        .route("/api/v1/games/provider-keys", axum::routing::post(save))
}
