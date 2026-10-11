#[path = "../support.rs"]
mod tailscale_support;

pub fn register(router: axum::Router) -> axum::Router {
    tailscale_support::register(router, "down")
}
