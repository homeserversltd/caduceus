use axum::{http::StatusCode, Json};
use serde::Serialize;

const CADUCEUS_BUILD_SHA: Option<&str> = option_env!("CADUCEUS_BUILD_SHA");

#[derive(Serialize)]
pub(crate) struct BeamBody {
    schema: &'static str,
    ok: bool,
    service: &'static str,
    profile: String,
    caduceus_sha: &'static str,
    env_sha: &'static str,
    rustc_version: &'static str,
    gui_face: Option<&'static str>,
    syzygy_sha: Option<String>,
}

pub(crate) async fn route() -> Result<Json<BeamBody>, (StatusCode, Json<crate::gate::ApiErrorBody>)>
{
    let failure = |signal: &str| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(crate::gate::ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "beam".to_owned(),
                first_missing_signal: signal.to_owned(),
            }),
        )
    };
    let syzygy_sha = crate::routes::leaf_ruyi::local_syzygy()
        .map_err(|_| failure("caduceus-ruyi-store-failed"))?;
    let profile = crate::routes::profile_routes::ACTIVE_PROFILE.to_owned();
    let gui_face = match profile.as_str() {
        "homeserver" => Some("Coronatio"),
        "homeconsole" => Some("Arcadia"),
        "tv" => Some("Hyprland"),
        _ => None,
    };
    let body = BeamBody {
        schema: crate::routes::leaf_schema::beam_schema(),
        ok: true,
        service: "caduceus",
        profile,
        caduceus_sha: CADUCEUS_BUILD_SHA.unwrap_or("unset"),
        env_sha: env!("CADUCEUS_BUILD_ENV_SHA"),
        rustc_version: option_env!("CADUCEUS_BUILD_RUSTC_VERSION").unwrap_or("unset"),
        gui_face,
        syzygy_sha,
    };
    let value = serde_json::to_value(&body).map_err(|_| failure("caduceus-schema-desync"))?;
    if !crate::routes::leaf_schema::accepts(body.schema, &value) {
        return Err(failure("caduceus-schema-desync"));
    }
    Ok(Json(body))
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/beam", axum::routing::get(route))
}
