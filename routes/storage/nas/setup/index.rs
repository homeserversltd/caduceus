use axum::{extract::Json, http::StatusCode, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;

const COMMAND: &str = "storage nas setup";
const NAS_SETUP_TIMEOUT: Duration = Duration::from_secs(600);
const NAS_SETUP_RESCUE_GRACE: Duration = Duration::from_secs(180);

fn project_chord(aggregate: &Value, request: &Value) -> Value {
    let stages = aggregate.get("stages").and_then(Value::as_array);
    let stage = |id: &str| stages.and_then(|rows| rows.iter().find(|row| {
        row.get("stage_id").and_then(Value::as_str) == Some(id)
            && row.get("outcome").and_then(Value::as_str) != Some("stage-skipped")
    }));
    let seat = stage("seat").and_then(|row| row.get("receipt"));
    let failed = aggregate.get("failedStage").and_then(Value::as_str);
    let refused = failed.and_then(stage).and_then(|row| row.get("receipt"));
    let source = seat.or(refused);
    let field = |name: &str, default: Value| source.and_then(|v| v.get(name)).cloned().unwrap_or(default);
    // The parent initializes the four paths to null and the lists empty
    // before preflight; never guess device paths on a pre-seat refusal.
    let mut result = json!({
        "schema": "caduceus.nas.setup.v1",
        "ok": aggregate.get("ok").cloned().unwrap_or(json!(false)),
        "firstMissingSignal": refused.and_then(|r| r.get("firstMissingSignal"))
            .or_else(|| aggregate.get("firstMissingSignal")).cloned().unwrap_or(json!("caduceus-chord-refused")),
        "role": request["role"], "device": request["device"],
        "partition": field("partition", Value::Null),
        "partlabel": field("partlabel", Value::Null),
        "mapper": field("mapper", Value::Null),
        "mountpoint": field("mountpoint", Value::Null),
        "steps": field("steps", json!([])),
        "servicesStarted": field("servicesStarted", json!([])),
        "rolledBack": field("rolledBack", json!(false))
    });
    if let Some(failed) = failed {
        result["failedStep"] = refused.and_then(|receipt| receipt.get("failedStep"))
            .cloned().unwrap_or_else(|| json!(failed));
    }
    if let Some(rollback) = stage("rollback").and_then(|row| row.get("receipt")) {
        result["rollback"] = rollback.clone();
    }
    result
}

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
struct NasSetupBody {
    device: String,
    role: NasRole,
}

async fn setup_route(
    Json(value): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    let body = serde_json::from_value::<NasSetupBody>(value).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(crate::gate::ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: COMMAND.to_string(),
                first_missing_signal: "caduceus-nas-setup-request-invalid".to_string(),
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
                "caduceus-carapace-desync",
            ));
        }
    }

    let payload = json!({"device": body.device, "role": body.role.as_str()});
    let projection_request = payload.clone();
    let context = crate::shared::load_trace::current();
    let task = tokio::spawn(async move {
        let response = async {
            let crossed = crate::gate::blocking_task(COMMAND, move || {
                crate::shared::load_trace::with_blocking_context(context, || {
                    crate::gate::snake::crossing_path_with_chord_grace(
                        "storage/nas/setup",
                        &payload,
                        NAS_SETUP_TIMEOUT,
                        NAS_SETUP_RESCUE_GRACE,
                    )
                })
            })
            .await?;
            let crossing = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
            let mut receipt = crossing
                .get("receiptPayload")
                .cloned()
                .ok_or_else(|| crate::gate::service_unavailable(COMMAND, "caduceus-nas-setup-receipt-missing"))?;
            if crate::routes::leaf_schema::accepts("caduceus.chord.receipt.v1", &receipt) {
                receipt = project_chord(&receipt, &projection_request);
            }
            if !crate::routes::leaf_schema::accepts_bound("caduceus.nas.setup.v1", "storage/nas/setup", &receipt) {
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
        }.await;
        response
    });
    match task.await {
        Ok(response) => response,
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    }
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/storage/nas/setup",
        axum::routing::post(setup_route),
    )
}
