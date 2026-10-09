pub use crate::routes::issue_certificate::{trust_fetch_json, trust_install_json};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct TrustFetchBody {
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

pub(super) async fn trust_fetch(
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
    let server = body.server;
    let platform = body.platform;
    let result = crate::gate::blocking_task("cert trust-fetch", move || {
        trust_fetch_json(&server, &platform)
    })
    .await?;
    result
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
    let bundle = body.bundle;
    let platform = body.platform;
    let dry_run = body.dry_run;
    let result = crate::gate::blocking_task("cert trust-install", move || {
        trust_install_json(&bundle, &platform, dry_run)
    })
    .await?;
    result
        .map(|value| (crate::gate::mutation_status(&value), axum::Json(value)))
        .map_err(|signal| crate::gate::api_error_signal("cert trust-install", &signal))
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/cert/trust-install",
            axum::routing::post(trust_install),
        )
}
