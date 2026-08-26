/// Synchronous storage categories scan.
pub const NAMESPACE: &str = "storage/categories/scan";
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/storage/categories/scan",
        axum::routing::post(crate::routes::storage_support::storage_categories_scan_route),
    )
}
