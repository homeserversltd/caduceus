use axum::{extract::Json, http::StatusCode, Router};
use serde_json::Value;

pub const NAMESPACE: &str = "python/run";

pub async fn route(Json(body): Json<Value>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let object = body.as_object().ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-snake-request-invalid"}))))?;
    let band = object.get("bandPath").or_else(|| object.get("band")).and_then(Value::as_str).ok_or_else(|| (StatusCode::BAD_REQUEST, Json(serde_json::json!({"ok":false,"firstMissingSignal":"caduceus-snake-band-missing"}))))?;
    let envelope = object
        .get("envelope")
        .cloned()
        .unwrap_or_else(|| body.clone());
    crate::gate::snake::run(band, &envelope)
        .map(Json)
        .map_err(|signal| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({"ok":false,"firstMissingSignal":signal})),
            )
        })
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/python/run", axum::routing::post(route))
}
