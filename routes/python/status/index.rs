use axum::{
    extract::{Json, Query},
    Router,
};
use serde::Deserialize;

pub const NAMESPACE: &str = "python/status";
#[derive(Deserialize, Default)]
pub struct StatusQuery {
    #[serde(rename = "bandPath")]
    band_path: Option<String>,
}

pub async fn route(Query(query): Query<StatusQuery>) -> Json<serde_json::Value> {
    Json(crate::gate::snake::status(
        query.band_path.as_deref(),
    ))
}
pub fn register(router: Router) -> Router {
    router.route("/api/v1/python/status", axum::routing::get(route))
}
