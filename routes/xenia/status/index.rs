pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/xenia/status",
        axum::routing::get(crate::routes::leaf_xenia_validate::support::doors::status),
    )
}
