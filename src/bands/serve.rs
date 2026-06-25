use crate::bands::{
    gui, health, identity, legacy_sbin, local_ai, profile, profile_module, receipts, sync, update,
};
use crate::tools::policy;
use axum::{
    extract::Query,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiErrorBody {
    schema: &'static str,
    ok: bool,
    command: String,
    first_missing_signal: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LivenessBody {
    schema: &'static str,
    ok: bool,
    service: &'static str,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ServiceToggleBody {
    state: String,
}

#[derive(Deserialize)]
struct ProfileModuleToggleBody {
    #[serde(alias = "moduleId")]
    module_id: String,
    enabled: bool,
}

fn api_error(command: &str) -> (StatusCode, Json<ApiErrorBody>) {
    (
        StatusCode::FORBIDDEN,
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: command.to_string(),
            first_missing_signal: "caduceus-public-action-not-allowed",
        }),
    )
}

fn missing_signal(err: &str) -> &'static str {
    if err.contains("identity") {
        "caduceus-identity-missing"
    } else if err.contains("profile") {
        "caduceus-profile-missing"
    } else {
        "caduceus-profile-missing"
    }
}

async fn gated_json(
    command: &str,
    read: fn() -> Result<Value, String>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => match read() {
            Ok(value) => Ok(Json(value)),
            Err(err) => Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: command.to_string(),
                    first_missing_signal: missing_signal(&err),
                }),
            )),
        },
        Ok(false) => Err(api_error(command)),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: command.to_string(),
                first_missing_signal: "caduceus-profile-missing",
            }),
        )),
    }
}

fn mutation_status(value: &Value) -> StatusCode {
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn gated_mutation(
    command: &str,
    run: fn() -> Value,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {
            let value = run();
            Ok((mutation_status(&value), Json(value)))
        }
        Ok(false) => Err(api_error(command)),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: command.to_string(),
                first_missing_signal: "caduceus-profile-missing",
            }),
        )),
    }
}

async fn health_route() -> Json<LivenessBody> {
    Json(LivenessBody {
        schema: "caduceus.liveness.v1",
        ok: true,
        service: "caduceus",
    })
}

async fn identity_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("identity show", identity::read_json).await
}

async fn profile_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("profile show", profile::read_json).await
}

async fn health_api_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("health", health::read_json).await
}

async fn legacy_sbin_list_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("legacy-sbin list", legacy_sbin::list_json).await
}

async fn legacy_sbin_show_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command("legacy-sbin show") {
        Ok(true) => {
            let Some(script_id) = query.get("id") else {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "legacy-sbin show".to_string(),
                        first_missing_signal: "caduceus-legacy-sbin-script-id-missing",
                    }),
                ));
            };
            match legacy_sbin::show_json(script_id) {
                Ok(value) => Ok(Json(value)),
                Err(_) => Err((
                    StatusCode::NOT_FOUND,
                    Json(ApiErrorBody {
                        schema: "caduceus.api.error.v1",
                        ok: false,
                        command: "legacy-sbin show".to_string(),
                        first_missing_signal: "caduceus-legacy-sbin-script-missing",
                    }),
                )),
            }
        }
        Ok(false) => Err(api_error("legacy-sbin show")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "legacy-sbin show".to_string(),
                first_missing_signal: "caduceus-profile-missing",
            }),
        )),
    }
}

async fn update_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("update status", update::read_json).await
}

async fn update_now_route() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("update now", || update::invoke_now_json(&[])).await
}

async fn update_check_route() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)>
{
    gated_mutation("update check", || update::invoke_check_json(&[])).await
}

async fn sync_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("sync status", sync::read_json).await
}

async fn sync_now_route() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("sync now", || sync::invoke_now_json(&[])).await
}

async fn receipts_latest_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("receipts latest", receipts::read_latest_json).await
}

async fn receipts_ledger_route(
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    let page = query
        .get("page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1);
    let per_page = query
        .get("per_page")
        .or_else(|| query.get("perPage"))
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(10);
    match policy::allows_command("receipts ledger") {
        Ok(true) => match receipts::read_ledger_json(page, per_page) {
            Ok(value) => Ok(Json(value)),
            Err(err) => Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: "receipts ledger".to_string(),
                    first_missing_signal: missing_signal(&err),
                }),
            )),
        },
        Ok(false) => Err(api_error("receipts ledger")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "receipts ledger".to_string(),
                first_missing_signal: "caduceus-profile-missing",
            }),
        )),
    }
}

async fn update_service_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("update service status", update::service_status_json).await
}

async fn gui_update_now_route(
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("gui update now", || gui::invoke_update_now_json(&[])).await
}

async fn local_ai_runtime_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("local-ai runtime status", local_ai::runtime_status_json).await
}

async fn local_ai_runtime_check_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("local-ai runtime check", local_ai::runtime_status_json).await
}

async fn local_ai_runtime_update_route(
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    gated_mutation("local-ai runtime update", || {
        local_ai::invoke_runtime_update_json(&[])
    })
    .await
}

async fn profile_module_toggle_route(
    Json(body): Json<ProfileModuleToggleBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let module_id = body.module_id;
    match policy::allows_command("profile module toggle") {
        Ok(true) => match profile_module::toggle_json(&module_id, body.enabled) {
            Ok(value) => Ok((StatusCode::OK, Json(value))),
            Err(_) => Err((
                StatusCode::BAD_REQUEST,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: "profile module toggle".to_string(),
                    first_missing_signal: "caduceus-profile-module-toggle-failed",
                }),
            )),
        },
        Ok(false) => Err(api_error("profile module toggle")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "profile module toggle".to_string(),
                first_missing_signal: "caduceus-profile-missing",
            }),
        )),
    }
}

async fn update_service_toggle_route(
    Json(body): Json<ServiceToggleBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let state = body.state;
    match policy::allows_command("update service toggle") {
        Ok(true) => match update::service_toggle_json(&state, &[]) {
            Ok(value) => Ok((StatusCode::OK, Json(value))),
            Err(_) => Err(api_error("update service toggle")),
        },
        Ok(false) => Err(api_error("update service toggle")),
        Err(_) => Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "update service toggle".to_string(),
                first_missing_signal: "caduceus-profile-missing",
            }),
        )),
    }
}

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health_route))
        .route("/api/v1/identity", get(identity_route))
        .route("/api/v1/profile", get(profile_route))
        .route("/api/v1/health", get(health_api_route))
        .route("/api/v1/legacy-sbin", get(legacy_sbin_list_route))
        .route("/api/v1/legacy-sbin/show", get(legacy_sbin_show_route))
        .route("/api/v1/update/status", get(update_status_route))
        .route("/api/v1/update/now", post(update_now_route))
        .route("/api/v1/update/check", post(update_check_route))
        .route("/api/v1/sync/status", get(sync_status_route))
        .route("/api/v1/sync/now", post(sync_now_route))
        .route("/api/v1/receipts/latest", get(receipts_latest_route))
        .route("/api/v1/receipts/ledger", get(receipts_ledger_route))
        .route(
            "/api/v1/update/service/status",
            get(update_service_status_route),
        )
        .route(
            "/api/v1/update/service/toggle",
            post(update_service_toggle_route),
        )
        .route("/api/v1/gui/update/now", post(gui_update_now_route))
        .route(
            "/api/v1/local-ai/runtime/status",
            get(local_ai_runtime_status_route),
        )
        .route(
            "/api/v1/local-ai/runtime/check",
            post(local_ai_runtime_check_route),
        )
        .route(
            "/api/v1/local-ai/runtime/update",
            post(local_ai_runtime_update_route),
        )
        .route(
            "/api/v1/profile/module/toggle",
            post(profile_module_toggle_route),
        )
}

pub async fn run_async() -> i32 {
    let bind = env::var("CADUCEUS_BIND").unwrap_or_else(|_| "0.0.0.0:8787".to_string());
    let addr: SocketAddr = match bind.parse() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("caduceus-bind-invalid: {err}");
            return 1;
        }
    };

    let app = router();

    let listener = match TcpListener::bind(addr).await {
        Ok(value) => value,
        Err(err) => {
            eprintln!("caduceus-bind-failed: {err}");
            return 1;
        }
    };

    eprintln!("caduceus serve listening on {addr}");
    match axum::serve(listener, app).await {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("caduceus-serve-failed: {err}");
            1
        }
    }
}

pub fn run() -> i32 {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(value) => value,
        Err(err) => {
            eprintln!("caduceus-serve-runtime-failed: {err}");
            return 1;
        }
    };
    runtime.block_on(run_async())
}
