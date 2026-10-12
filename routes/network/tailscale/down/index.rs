#[path = "../support.rs"]
mod tailscale_support;

pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/network/tailscale/down",
        axum::routing::post(tailscale_support::down_route),
    )
}
