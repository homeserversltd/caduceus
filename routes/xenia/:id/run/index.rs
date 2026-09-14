pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/xenia/:id/run",
        axum::routing::post(crate::routes::xenia_support::doors::run),
    )
}
