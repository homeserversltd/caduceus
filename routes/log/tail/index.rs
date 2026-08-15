/// C2 route leaf.
pub const NAMESPACE: &str = "log/tail";

async fn http(axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String,String>>) -> Result<(axum::http::StatusCode, axum::Json<serde_json::Value>), (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> { let f=crate::shared::hyalos::TailFilters{count:q.get("count").and_then(|x|x.parse().ok()).unwrap_or(20),kind:q.get("kind").cloned(),organ:q.get("organ").cloned(),world:q.get("world").cloned(),correlation_id:q.get("correlation_id").or_else(||q.get("correlationId")).cloned(),level:q.get("level").cloned(),ok:q.get("ok").and_then(|x|match x.as_str(){"true"=>Some(true),"false"=>Some(false),_=>None})}; match crate::shared::policy::allows_command("hyalos tail") { Ok(true)=>crate::routes::hyalos::tail_json(f).map(|v|(axum::http::StatusCode::OK,axum::Json(v))).map_err(|e|crate::gate::api_error_signal("hyalos tail",&e)), Ok(false)=>Err(crate::gate::api_error("hyalos tail")), Err(_)=>Err(crate::gate::api_error_signal("hyalos tail","caduceus-profile-missing")) } }

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/hyalos/tail", axum::routing::get(http))
}
