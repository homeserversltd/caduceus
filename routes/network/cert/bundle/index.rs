/// C2 route leaf.
pub const NAMESPACE: &str = "network/cert/bundle";

async fn download(axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String,String>>) -> Result<axum::response::Response, (axum::http::StatusCode, axum::Json<serde_json::Value>)> { let cmd="cert bundle read"; if !crate::shared::policy::allows_command(cmd).unwrap_or(false) { return Err((axum::http::StatusCode::SERVICE_UNAVAILABLE,axum::Json(serde_json::json!({"firstMissingSignal":"caduceus-house-ca-refused"})))); } let b=crate::routes::issue_certificate::bundle_download_json(q.get("platform").map(String::as_str).unwrap_or("linux")).map_err(|e|((if e=="caduceus-cert-platform-invalid" { axum::http::StatusCode::BAD_REQUEST } else { axum::http::StatusCode::SERVICE_UNAVAILABLE }),axum::Json(serde_json::json!({"firstMissingSignal":e}))))?; Ok(axum::response::Response::builder().status(200).header("content-type",b.mime_type).header("content-disposition",format!("attachment; filename=\"{}\"",b.filename)).body(axum::body::Body::from(b.bytes)).unwrap()) }

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/cert/bundle/download", axum::routing::get(download))
}
