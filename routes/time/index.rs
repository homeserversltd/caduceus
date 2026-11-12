use axum::extract::ConnectInfo;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::net::IpAddr;

fn peer_allowed(peer: Option<&ConnectInfo<crate::gate::ConnectionInfo>>) -> bool {
    let Some(ConnectInfo(crate::gate::ConnectionInfo::Tcp(address))) = peer else {
        return false;
    };
    match address.ip() {
        IpAddr::V4(address) => address.is_loopback() || address.is_private() || address.is_link_local(),
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return mapped.is_loopback() || mapped.is_private() || mapped.is_link_local();
            }
            let octets = address.octets();
            address.is_loopback() || octets[0] & 0xfe == 0xfc
                || octets[0] == 0xfe && octets[1] & 0xc0 == 0x80
        }
    }
}

async fn state(peer: Option<ConnectInfo<crate::gate::ConnectionInfo>>) -> Response {
    if !peer_allowed(peer.as_ref()) {
        return crate::gate::api_error_signal("time state", "caduceus-time-peer-not-allowed").into_response();
    }
    match tokio::task::spawn_blocking(crate::routes::set_time::state_json).await {
        Ok(Ok(value)) => (crate::gate::mutation_status(&value), Json(value)).into_response(),
        Ok(Err(signal)) => crate::gate::service_unavailable("time state", &signal).into_response(),
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "caduceus-time-state-unavailable").into_response(),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    if matches!(crate::routes::profile_routes::ACTIVE_PROFILE, "homeserver" | "specula") {
        router.route("/api/v1/time/state", axum::routing::get(state))
    } else {
        router
    }
}
