pub fn register(router: axum::Router) -> axum::Router {
    crate::routes::xenia_support::startup();
    router.route(
        "/api/v1/xenia/validate",
        axum::routing::post(crate::routes::xenia_support::doors::validate),
    )
}
