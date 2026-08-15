/// C2 route leaf.
pub const NAMESPACE: &str = "network/dns/read";


use axum::{response::Json, Router};
use serde_json::Value;
use crate::gate::ApiErrorBody;

async fn dns_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dns read").await
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/dns/read", axum::routing::get(dns_read_route))
}
