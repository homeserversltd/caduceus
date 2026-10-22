pub const NAMESPACE: &str = "console/steam";

use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};
use std::time::Duration;

pub(crate) const SCHEMA: &str = "caduceus.console.steam.v1";

pub(crate) fn envelope(
    ok: bool,
    operation: &str,
    exit: Option<i32>,
    outcome: &str,
    signal: &str,
    staff: Value,
) -> Value {
    json!({
        "schema": SCHEMA,
        "ok": ok,
        "operation": operation,
        "exit": exit,
        "outcome": outcome,
        "firstMissingSignal": signal,
        "staff": staff,
    })
}

async fn check() -> (StatusCode, Json<Value>) {
    if crate::shared::policy::allows_command("console steam read") != Ok(true) {
        return (
            StatusCode::FORBIDDEN,
            Json(envelope(
                false,
                "check",
                None,
                "refused",
                "caduceus-public-action-not-allowed",
                Value::Null,
            )),
        );
    }
    let result = crate::gate::blocking_task("console steam read", || {
        crate::shared::agathodaimon::crossing_argv(
            "console",
            "steam-install",
            &["--check", "--json"],
            Duration::from_secs(30),
        )
    })
    .await;
    let body = match result {
        Ok(Ok(output))
            if output.exit == 0 && output.value.as_ref().is_some_and(Value::is_object) =>
        {
            envelope(
                true,
                "check",
                Some(0),
                "checked",
                "none",
                output.value.unwrap(),
            )
        }
        Ok(Ok(output)) => envelope(
            false,
            "check",
            Some(output.exit),
            "unavailable",
            "caduceus-steam-check-unavailable",
            Value::Null,
        ),
        Ok(Err(signal)) => envelope(false, "check", None, "unavailable", signal, Value::Null),
        Err(_) => envelope(
            false,
            "check",
            None,
            "unavailable",
            "caduceus-blocking-task-join-failed",
            Value::Null,
        ),
    };
    // An observation (including an unavailable observation) has no ledger,
    // cached body, or receipt file. The declaration also opts out of counters.
    (StatusCode::OK, Json(body))
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/console/steam", axum::routing::get(check))
}
