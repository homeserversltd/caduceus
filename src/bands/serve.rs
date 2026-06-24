use crate::bands::{health, identity, profile};
use crate::tools::policy;
use axum::{http::StatusCode, routing::get, Json, Router};
use serde::Serialize;
use serde_json::Value;
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

pub fn router() -> Router {
    Router::new()
        .route("/health", get(health_route))
        .route("/api/v1/identity", get(identity_route))
        .route("/api/v1/profile", get(profile_route))
        .route("/api/v1/health", get(health_api_route))
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
