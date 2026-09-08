pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/xenia/remove",
        axum::routing::post(crate::routes::leaf_xenia_validate::support::doors::remove),
    )
}
