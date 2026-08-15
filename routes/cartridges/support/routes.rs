use crate::gate::{api_error, ApiErrorBody};
use crate::routes::cartridges_shared;
use crate::shared::policy;
use axum::{
    body::Body,
    extract::Json,
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::Value;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CartridgeRemoveBody {
    id: String,
}

fn cartridge_error(
    command: &str,
    error: crate::routes::cartridges_shared::CartridgeError,
) -> (StatusCode, Json<ApiErrorBody>) {
    (
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE),
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.to_string(),
            first_missing_signal: error.signal.to_string(),
        }),
    )
}

pub(crate) async fn cartridges_route() -> Result<Response, (StatusCode, Json<ApiErrorBody>)> {
    let bytes = crate::routes::cartridges_shared::passage_bytes()
        .map_err(|error| cartridge_error("cartridges read", error))?;
    Ok(([(CONTENT_TYPE, "application/json")], Body::from(bytes)).into_response())
}

fn cartridges_mutation_admitted() -> Result<(), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("cartridges mutate") {
        Ok(true) => Ok(()),
        Ok(false) => Err(api_error("cartridges mutate")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "cartridges mutate".to_string(),
                first_missing_signal: "caduceus-profile-missing".to_string(),
            }),
        )),
    }
}

pub(crate) async fn cartridges_admit_route(
    Json(body): Json<crate::routes::cartridges_shared::Cartridge>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    cartridges_mutation_admitted()?;
    crate::routes::cartridges_shared::admit(body)
        .map(|receipt| (StatusCode::OK, Json(receipt)))
        .map_err(|error| cartridge_error("cartridges admit", error))
}

pub(crate) async fn cartridges_remove_route(
    Json(body): Json<CartridgeRemoveBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    cartridges_mutation_admitted()?;
    crate::routes::cartridges_shared::remove(&body.id)
        .map(|receipt| (StatusCode::OK, Json(receipt)))
        .map_err(|error| cartridge_error("cartridges remove", error))
}
