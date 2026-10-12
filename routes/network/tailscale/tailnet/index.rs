#[path = "../support.rs"]
mod tailscale_support;

pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/network/tailscale/tailnet",
        axum::routing::post(tailscale_support::tailnet_route),
    )
}
