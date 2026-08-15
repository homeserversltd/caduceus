/// C2 route leaf.
pub const NAMESPACE: &str = "network/dhcp/leases";


use axum::{response::Json, Router};
use serde_json::Value;
use crate::gate::ApiErrorBody;

async fn dhcp_leases_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dhcp leases").await
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/dhcp/leases", axum::routing::get(dhcp_leases_route))
}
