pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/xenia/admit",
        axum::routing::post(crate::routes::xenia_support::doors::admit),
    )
}
