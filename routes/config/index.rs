/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/config/path", axum::routing::get(crate::routes::config_support::path))
        .route("/api/v1/config/show", axum::routing::get(crate::routes::config_support::show))
        .route("/api/v1/config/get", axum::routing::get(crate::routes::config_support::get))
        .route("/api/v1/config/set", axum::routing::post(crate::routes::config_support::set))
        .route("/api/v1/config/patch", axum::routing::post(crate::routes::config_support::patch))
}
