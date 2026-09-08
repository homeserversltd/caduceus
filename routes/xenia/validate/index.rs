pub mod support {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/routes/xenia/support/index.rs"
    ));
}
pub fn register(router: axum::Router) -> axum::Router {
    support::startup();
    router.route(
        "/api/v1/xenia/validate",
        axum::routing::post(support::doors::validate),
    )
}
