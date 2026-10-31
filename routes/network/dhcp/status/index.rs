/// C2 route leaf.
pub const NAMESPACE: &str = "network/dhcp/status";

use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::policy;
use axum::{extract::Json, http::StatusCode, Router};
#[cfg(carapace_feature_kea)]
use axum::extract::OriginalUri;
#[cfg(carapace_feature_kea)]
use axum::extract::Path;
#[cfg(carapace_feature_kea)]
use axum::http::{HeaderMap, Method};
use serde_json::Value;

pub(crate) async fn network_read_route(
    command: &'static str,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let Some(read) = network_read::named(command) else {
        return Err(api_error(command));
    };
    match policy::allows_command(command) {
        Ok(true) => {
            let context = crate::shared::load_trace::current();
            let configured_native = std::env::var_os("CADUCEUS_NETWORK_READ_CMD").is_some();
            let invocation = context
                .as_ref()
                .filter(|_| configured_native)
                .map(crate::shared::load_trace::begin_invocation);
            let result = crate::gate::blocking_task(command, move || network_read::invoke(read)).await?;
            if let (Some(context), Some(invocation)) = (context, invocation) {
                crate::shared::load_trace::record_native_completion(
                    &context,
                    command,
                    invocation,
                    result.is_ok(),
                );
            }
            match result {
                Ok(mut value) => {
                    crate::shared::load_trace::enrich_json(&mut value);
                    Ok(Json(value))
                }
                Err(error) => Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: command.to_string(),
                        first_missing_signal: error,
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-carapace-desync")),
    }
}

async fn dhcp_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dhcp status").await
}

async fn dhcp_reservations_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let command = "network dhcp reservations list";
    match policy::allows_command(command) {
        Ok(true) => {
            let context = crate::shared::load_trace::current();
            let invocation = context
                .as_ref()
                .map(crate::shared::load_trace::begin_invocation);
            let value = crate::gate::blocking_task(command, move || {
                crate::routes::native_kea_read::response(command)
            })
            .await?;
            if let (Some(context), Some(invocation)) = (context, invocation) {
                crate::shared::load_trace::record_native_completion(
                    &context,
                    command,
                    invocation,
                    value["ok"] == true,
                );
            }

            if value["ok"] == true {
                let mut value = value;
                crate::shared::load_trace::enrich_json(&mut value);
                Ok(Json(value))
            } else {
                Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: command.to_string(),
                        first_missing_signal: value["firstMissingSignal"]
                            .as_str()
                            .unwrap_or("caduceus-network-dhcp-read-failed")
                            .to_string(),
                    }),
                ))
            }
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-carapace-desync")),
    }
}

#[cfg(carapace_feature_kea)]
async fn dhcp_staff_actuator_route(
    headers: HeaderMap,
    OriginalUri(uri): OriginalUri,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let (method, route) = match uri.path() {
        "/api/v1/network/dhcp" => ("POST", "/api/dhcp"),
        "/api/v1/network/dhcp/reservations" => ("POST", "/api/dhcp/reservations"),
        "/api/v1/network/dhcp/pool-boundary" => ("POST", "/api/dhcp/pool-boundary"),
        _ => {
            return Err(api_error_signal(
                "staff intent",
                "caduceus-dhcp-route-invalid",
            ))
        }
    };
    match policy::allows_command("staff intent") {
        Ok(true) => {
            let result = crate::gate::blocking_task("staff intent", move || {
                crate::routes::dhcp::intent_json(method, route, metadata)
            })
            .await?;
            result
                .map(|value| (mutation_status(&value), Json(value)))
                .map_err(|reason| api_error_signal("staff intent", &reason))
        }
        Ok(false) => Err(api_error("staff intent")),
        Err(_) => Err(api_error_signal("staff intent", "caduceus-carapace-desync")),
    }
}

#[cfg(carapace_feature_kea)]
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
        Ok(true) => {
            let result = crate::gate::blocking_task("staff intent", move || {
                crate::routes::dhcp::intent_json(method.as_str(), &route, metadata)
            })
            .await?;
            result
                .map(|value| (mutation_status(&value), Json(value)))
                .map_err(|reason| api_error_signal("staff intent", &reason))
        }
        Ok(false) => Err(api_error("staff intent")),
        Err(_) => Err(api_error_signal("staff intent", "caduceus-carapace-desync")),
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    let reservations_route = axum::routing::get(dhcp_reservations_read_route);
    #[cfg(carapace_feature_kea)]
    let reservations_route = reservations_route.post(dhcp_staff_actuator_route);
    let router = router
        .route(
            "/api/v1/network/dhcp/status",
            axum::routing::get(dhcp_status_route),
        )
        .route("/api/v1/network/dhcp/reservations", reservations_route);
    #[cfg(carapace_feature_kea)]
    let router = router
        .route(
            "/api/v1/network/dhcp",
            axum::routing::post(dhcp_staff_actuator_route),
        )
        .route(
            "/api/v1/network/dhcp/reservations/:reservation_id",
            axum::routing::put(dhcp_reservation_staff_actuator_route)
                .delete(dhcp_reservation_staff_actuator_route),
        )
        .route(
            "/api/v1/network/dhcp/pool-boundary",
            axum::routing::post(dhcp_staff_actuator_route),
        );
    router
}
