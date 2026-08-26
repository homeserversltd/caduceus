/// Canonical storage categories cache readback.
pub const NAMESPACE: &str = "storage/categories";
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/storage/categories",
        axum::routing::get(crate::routes::storage_support::storage_categories_route),
    )
}
