use axum::Json;
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
    gui_face: Option<&'static str>,
    syzygy_sha: Option<&'static str>,
}

pub(crate) async fn route() -> Json<BeamBody> {
    let profile = std::env::var("CADUCEUS_PROFILE").unwrap_or_else(|_| "unknown".to_owned());
    let gui_face = match profile.as_str() {
        "homeserver" => Some("Coronatio"),
        "homeconsole" | "console" => Some("Arcadia"),
        "tv" => Some("Hyprland"),
        _ => None,
    };
    Json(BeamBody {
        schema: "caduceus.beam.v1",
        ok: true,
        service: "caduceus",
        profile,
        caduceus_sha: CADUCEUS_BUILD_SHA.unwrap_or("unset"),
        env_sha: env!("CADUCEUS_BUILD_ENV_SHA"),
        gui_face,
        syzygy_sha: None,
    })
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/beam", axum::routing::get(route))
}
