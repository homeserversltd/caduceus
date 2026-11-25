/// C2 route leaf.
pub const NAMESPACE: &str = "log/reflect";

async fn http(axum::Json(body): axum::Json<serde_json::Value>) -> Result<(axum::http::StatusCode, axum::Json<serde_json::Value>), (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> {
    match crate::shared::policy::allows_command("hyalos reflect") {
        Ok(true) => {
            let result = crate::gate::blocking_task("hyalos reflect", move || crate::routes::hyalos::reflect_json(body)).await?;
            result.map(|v| (axum::http::StatusCode::OK, axum::Json(v))).map_err(|e| {
                let mut error = crate::gate::api_error_signal("hyalos reflect", &e);
                if matches!(e.as_str(), "hyalos-reflection-invalid" | "hyalos-level-invalid" | "hyalos-reflection-required-field-missing") {
                    error.0 = axum::http::StatusCode::BAD_REQUEST;
                }
                error
            })
        }
        Ok(false) => Err(crate::gate::api_error("hyalos reflect")),
        Err(_) => Err(crate::gate::api_error_signal("hyalos reflect", "caduceus-carapace-desync")),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    let reflect = axum::routing::post(http)
        .route_layer(axum::middleware::from_fn(crate::gate::hyalos_local_write_gate));
    router
        .route("/api/v1/log/reflect", reflect.clone())
        .route("/api/v1/hyalos/reflect", reflect)
}
