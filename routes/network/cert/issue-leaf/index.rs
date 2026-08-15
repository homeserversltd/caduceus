/// Canonical C2 leaf; real handler is owned by the legacy-compatible support band.
pub const NAMESPACE: &str = "network/cert/issue-leaf";
pub use crate::routes::issue_certificate::*;

#[derive(serde::Deserialize)] #[serde(rename_all="camelCase", deny_unknown_fields)] struct CsrBody { csr_pem: String }
async fn csr(_headers: axum::http::HeaderMap, axum::Json(_body): axum::Json<CsrBody>) -> Result<(axum::http::StatusCode, axum::Json<serde_json::Value>), (axum::http::StatusCode, axum::Json<serde_json::Value>)> { Err((axum::http::StatusCode::FORBIDDEN, axum::Json(serde_json::json!({"firstMissingSignal":"caduceus-attendance-not-current"})))) }

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/cert/csr/sign", axum::routing::post(csr).layer(axum::extract::DefaultBodyLimit::max(8192)))
}
