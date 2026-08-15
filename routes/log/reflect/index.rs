/// C2 route leaf.
pub const NAMESPACE: &str = "log/reflect";

async fn http(axum::Json(body): axum::Json<serde_json::Value>) -> Result<(axum::http::StatusCode, axum::Json<serde_json::Value>), (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> { match crate::shared::policy::allows_command("hyalos reflect") { Ok(true)=>crate::routes::hyalos::reflect_json(body).map(|v|(axum::http::StatusCode::OK,axum::Json(v))).map_err(|e|crate::gate::api_error_signal("hyalos reflect",&e)), Ok(false)=>Err(crate::gate::api_error("hyalos reflect")), Err(_)=>Err(crate::gate::api_error_signal("hyalos reflect","caduceus-profile-missing")) } }

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    let router = router.route("/api/v1/log/reflect", axum::routing::post(http))
        .route("/api/v1/hyalos/reflect", axum::routing::post(http));
    router
}
