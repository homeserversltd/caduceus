pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/xenia/admit",
        axum::routing::post(crate::routes::leaf_xenia_validate::support::doors::admit),
    )
}
