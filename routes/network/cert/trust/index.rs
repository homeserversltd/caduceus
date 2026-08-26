pub use crate::routes::issue_certificate::{trust_fetch_json, trust_install_json};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustFetchBody {
    server: String,
    #[serde(default = "default_platform")]
    platform: String,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustInstallBody {
    bundle: String,
    #[serde(default = "default_platform")]
    platform: String,
    #[serde(default)]
    dry_run: bool,
}

fn default_platform() -> String {
    "linux".to_string()
}

async fn trust_fetch(
    axum::Json(body): axum::Json<TrustFetchBody>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    if !crate::shared::policy::allows_command("cert trust-install").unwrap_or(false) {
        return Err(crate::gate::api_error("cert trust-install"));
    }
    trust_fetch_json(&body.server, &body.platform)
        .map(|value| (crate::gate::mutation_status(&value), axum::Json(value)))
        .map_err(|signal| crate::gate::api_error_signal("cert trust-fetch", &signal))
}

async fn trust_install(
    axum::Json(body): axum::Json<TrustInstallBody>,
) -> Result<
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    if !crate::shared::policy::allows_command("cert trust-install").unwrap_or(false) {
        return Err(crate::gate::api_error("cert trust-install"));
    }
    trust_install_json(&body.bundle, &body.platform, body.dry_run)
        .map(|value| (crate::gate::mutation_status(&value), axum::Json(value)))
        .map_err(|signal| crate::gate::api_error_signal("cert trust-install", &signal))
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/cert/trust-fetch", axum::routing::post(trust_fetch))
        .route(
            "/api/v1/cert/trust-install",
            axum::routing::post(trust_install),
        )
}
