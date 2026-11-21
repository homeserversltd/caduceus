/// C2 route leaf.
pub const NAMESPACE: &str = "network/dhcp/leases";

use crate::gate::ApiErrorBody;
use axum::{response::Json, Router};
use serde_json::Value;

async fn dhcp_leases_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    crate::routes::leaf_network_dhcp_status::native_dhcp_list_route(
        crate::routes::native_kea_read::LEASE_COMMAND,
    )
    .await
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/network/dhcp/leases",
        axum::routing::get(dhcp_leases_route),
    )
}
