use axum::{extract::Json, http::StatusCode, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const COMMAND: &str = "storage nas detach";
const NAS_DETACH_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum NasRole {
    Primary,
    Backup,
}

impl NasRole {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Backup => "backup",
        }
    }
}

#[derive(Deserialize)]
struct NasDetachBody {
    role: NasRole,
}

async fn detach_route(
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let body = serde_json::from_value::<NasDetachBody>(value).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(crate::gate::ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: COMMAND.to_string(),
                first_missing_signal: "caduceus-nas-detach-request-invalid".to_string(),
            }),
        )
    })?;
    if crate::routes::profile_routes::ACTIVE_PROFILE != "homeserver" {
        return Err(crate::gate::api_error(COMMAND));
    }
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(crate::gate::api_error(COMMAND)),
        Err(_) => {
            return Err(crate::gate::api_error_signal(
                COMMAND,
                "caduceus-profile-missing",
            ));
        }
    }

    let payload = json!({"role": body.role.as_str()});
    let crossed = crate::gate::blocking_task(COMMAND, move || {
        crate::gate::snake::crossing_path_with_timeout(
            "storage/nas/detach",
            &payload,
            NAS_DETACH_TIMEOUT,
        )
    })
    .await?;
    let crossing = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
    let receipt = crossing.get("receiptPayload").cloned().ok_or_else(|| {
        crate::gate::service_unavailable(COMMAND, "caduceus-nas-detach-receipt-missing")
    })?;
    if !crate::routes::leaf_schema::accepts("caduceus.nas.detach.v1", &receipt) {
        return Err(crate::gate::service_unavailable(
            COMMAND,
            "caduceus-schema-desync",
        ));
    }

    let status = crate::gate::mutation_status(&receipt);
    if status == StatusCode::OK {
        crate::stats::disk_census::request_refresh();
    }
    Ok((status, Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/storage/nas/detach",
        axum::routing::post(detach_route),
    )
}
