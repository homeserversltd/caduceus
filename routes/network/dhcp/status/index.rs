/// C2 route leaf.
pub const NAMESPACE: &str = "network/dhcp/status";


use axum::{extract::Json, http::{HeaderMap, StatusCode}, Router};
use serde_json::Value;
use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::policy;

pub(crate) async fn network_read_route(
    command: &'static str,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let Some(read) = network_read::named(command) else {
        return Err(api_error(command));
    };
    match policy::allows_command(command) {
        Ok(true) => network_read::invoke(read).map(Json).map_err(|error| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: command.to_string(),
                    first_missing_signal: error,
                }),
            )
        }),
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
    }
}

async fn dhcp_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dhcp status").await
}

async fn dhcp_staff_actuator_route(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let (method, route) = match uri.path() {
        "/api/v1/network/dhcp/reservations" => {
            ("POST", "/api/dhcp/reservations")
        }
        "/api/v1/network/dhcp/pool-boundary" => ("POST", "/api/dhcp/pool-boundary"),
        _ => {
            return Err(api_error_signal(
                "staff intent",
                "caduceus-dhcp-route-invalid",
            ))
        }
    };
    match policy::allows_command("staff intent") {
        Ok(true) => crate::routes::dhcp::intent_json(method, route, metadata)
            .map(|value| (mutation_status(&value), Json(value)))
            .map_err(|reason| api_error_signal("staff intent", &reason)),
        Ok(false) => Err(api_error("staff intent")),
        Err(_) => Err(api_error_signal("staff intent", "caduceus-profile-missing")),
    }
}

async fn dhcp_reservation_staff_actuator_route(
    method: axum::http::Method,
    Path(reservation_id): Path<String>,
    Json(mut metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let object = metadata
        .as_object_mut()
        .ok_or_else(|| api_error_signal("staff intent", "caduceus-dhcp-request-invalid"))?;
    if object.contains_key("reservationId") {
        return Err(api_error_signal(
            "staff intent",
            "caduceus-dhcp-reservation-client-supplied",
        ));
    }
    object.insert(
        "reservationId".to_string(),
        Value::String(reservation_id.clone()),
    );
    let route = format!("/api/dhcp/reservations/{reservation_id}");
    match policy::allows_command("staff intent") {
        Ok(true) => crate::routes::dhcp::intent_json(method.as_str(), &route, metadata)
            .map(|value| (mutation_status(&value), Json(value)))
            .map_err(|reason| api_error_signal("staff intent", &reason)),
        Ok(false) => Err(api_error("staff intent")),
        Err(_) => Err(api_error_signal("staff intent", "caduceus-profile-missing")),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/dhcp/status", axum::routing::get(dhcp_status_route)).route("/api/v1/network/dhcp/reservations", axum::routing::post(dhcp_staff_actuator_route)).route("/api/v1/network/dhcp/reservations/:reservation_id", axum::routing::put(dhcp_reservation_staff_actuator_route).delete(dhcp_reservation_staff_actuator_route)).route("/api/v1/network/dhcp/pool-boundary", axum::routing::post(dhcp_staff_actuator_route))
}
