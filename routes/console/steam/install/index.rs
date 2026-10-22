pub const NAMESPACE: &str = "console/steam/install";

use crate::routes::leaf_console_steam::envelope;
use axum::{
    extract::{rejection::JsonRejection, Json},
    http::StatusCode,
    Router,
};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

fn finish(status: StatusCode, body: Value, started: Instant) -> (StatusCode, Json<Value>) {
    // Only deed metadata crosses the ledger boundary, never either body,
    // stdout, stderr, license text, or a PIN. No second crossing-failure log.
    let logged = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ": "console-steam",
        "kind": "install",
        "level": if status.is_success() { "info" } else { "error" },
        "ok": status.is_success(),
        "message": "owner Steam install",
        "attributes_redacted": {
            "who": "owner",
            "verb": "install",
            "target": "steam",
            "outcome": body["outcome"],
            "duration_ms": started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "exit": body["exit"],
            "signal": body["firstMissingSignal"],
        }
    }));
    let mut body = body;
    body["ledger_written"] = json!(matches!(logged, Ok(true)));
    (status, Json(body))
}

async fn install(raw: Result<Json<Value>, JsonRejection>) -> (StatusCode, Json<Value>) {
    let started = Instant::now();
    if crate::shared::policy::allows_command("console steam install") != Ok(true) {
        return finish(
            StatusCode::FORBIDDEN,
            envelope(
                false,
                "install",
                None,
                "refused",
                "caduceus-public-action-not-allowed",
                Value::Null,
            ),
            started,
        );
    }
    let Ok(Json(body)) = raw else {
        return finish(
            StatusCode::BAD_REQUEST,
            envelope(
                false,
                "install",
                None,
                "request-invalid",
                "caduceus-steam-request-invalid",
                Value::Null,
            ),
            started,
        );
    };
    // Exactly boolean true is the owner's acceptance. Missing, false, null,
    // strings and numbers never start the deed, even with otherwise valid PIN.
    if body.get("accept_license").and_then(Value::as_bool) != Some(true) {
        return finish(
            StatusCode::UNPROCESSABLE_ENTITY,
            envelope(
                false,
                "install",
                Some(8),
                "license-not-accepted",
                "license-not-accepted",
                Value::Null,
            ),
            started,
        );
    }
    drop(body);
    let result = crate::gate::blocking_task("console steam install", move || {
        // The blocking deed owns completion logging even if its HTTP caller
        // disconnects while the staff is still installing.
        let result = crate::shared::agathodaimon::crossing_argv(
            "console",
            "steam-install",
            &["--accept-license", "--json"],
            Duration::from_secs(30 * 60),
        );
        let (status, body) = match result {
            Ok(output) => {
                let (status, outcome) = match output.exit {
                    0 if output.value.as_ref().is_some_and(Value::is_object) => {
                        (StatusCode::OK, "installed")
                    }
                    7 => (StatusCode::CONFLICT, "already-installed"),
                    8 => (StatusCode::UNPROCESSABLE_ENTITY, "license-not-accepted"),
                    6 => (StatusCode::NOT_IMPLEMENTED, "package-manager-unsupported"),
                    9 => (StatusCode::BAD_GATEWAY, "apt-failed"),
                    _ => (StatusCode::BAD_GATEWAY, "staff-response-invalid"),
                };
                let signal = if status.is_success() {
                    "none"
                } else if output.exit == 9 {
                    output.signal.as_deref().unwrap_or("apt-failed")
                } else {
                    outcome
                };
                let staff = if status.is_success() {
                    output.value.unwrap()
                } else {
                    Value::Null
                };
                (
                    status,
                    envelope(
                        status.is_success(),
                        "install",
                        Some(output.exit),
                        outcome,
                        signal,
                        staff,
                    ),
                )
            }
            Err(signal) => (
                StatusCode::BAD_GATEWAY,
                envelope(
                    false,
                    "install",
                    None,
                    "staff-unavailable",
                    signal,
                    Value::Null,
                ),
            ),
        };
        finish(status, body, started)
    })
    .await;
    match result {
        Ok(reply) => reply,
        Err(_) => finish(
            StatusCode::BAD_GATEWAY,
            envelope(
                false,
                "install",
                None,
                "staff-unavailable",
                "caduceus-blocking-task-join-failed",
                Value::Null,
            ),
            started,
        ),
    }
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/console/steam/install",
        axum::routing::post(install),
    )
}
