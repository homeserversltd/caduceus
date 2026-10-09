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

pub async fn route(
    Query(query): Query<StatusQuery>,
) -> Result<
    Json<serde_json::Value>,
    (
        axum::http::StatusCode,
        Json<crate::gate::ApiErrorBody>,
    ),
> {
    let band_path = query.band_path;
    crate::gate::blocking_task("python status", move || {
        crate::gate::snake::status(band_path.as_deref())
    })
    .await
    .map(Json)
}
pub fn register(router: Router) -> Router {
    router.route("/api/v1/python/status", axum::routing::get(route))
}
