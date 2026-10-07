/// C2 route leaf.
pub const NAMESPACE: &str = "local-ai/runtime/status";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/local-ai/runtime/status",
            axum::routing::get(crate::routes::leaf_local_ai_query::http_status),
        )
}
