/// C2 route leaf.
pub const NAMESPACE: &str = "network/cert/bundle";

async fn download(
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<
    axum::response::Response,
    (axum::http::StatusCode, axum::Json<serde_json::Value>),
> {
    let cmd = "cert bundle read";
    let refusal = match crate::shared::policy::allows_command(cmd) {
        Ok(true) => None,
        Ok(false) => Some((
            axum::http::StatusCode::NOT_FOUND,
            crate::routes::network_read::NOT_THE_GATEWAY,
        )),
        Err(_) => Some((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-house-ca-refused",
        )),
    };
    if let Some((status, signal)) = refusal {
        return Err((
            status,
            axum::Json(serde_json::json!({"firstMissingSignal": signal})),
        ));
    }
    let platform = q
        .get("platform")
        .cloned()
        .unwrap_or_else(|| "linux".to_string());
    let result = crate::gate::blocking_task(cmd, move || {
        crate::routes::issue_certificate::bundle_download_json(&platform)
    })
    .await
    .map_err(|(status, axum::Json(body))| {
        (status, axum::Json(serde_json::json!(body)))
    })?;
    let b = result.map_err(|e| {
        (
            if e == "caduceus-cert-platform-invalid" {
                axum::http::StatusCode::BAD_REQUEST
            } else {
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            },
            axum::Json(serde_json::json!({"firstMissingSignal":e})),
        )
    })?;
    Ok(axum::response::Response::builder()
        .status(200)
        .header("content-type", b.mime_type)
        .header(
            "content-disposition",
            format!("attachment; filename=\"{}\"", b.filename),
        )
        .header("x-caduceus-ca-fingerprint", b.fingerprint)
        .body(axum::body::Body::from(b.bytes))
        .unwrap())
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/cert/bundle/download", axum::routing::get(download))
}
