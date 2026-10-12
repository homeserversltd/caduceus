#[path = "../support.rs"]
mod tailscale_support;

pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/network/tailscale/up",
        axum::routing::post(tailscale_support::up_route),
    )
}
