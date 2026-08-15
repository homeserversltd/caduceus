/// Homeserver-only service restart leaf.
pub const NAMESPACE: &str = "appliance/service/:service/restart";

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router { router.route("/api/v1/appliance/service/:service/restart", axum::routing::post(crate::routes::appliance_support::registered_service_restart_route)) }
