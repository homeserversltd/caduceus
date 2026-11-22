use crate::gate::{api_error, api_error_signal, blocking_task, mutation_status, ApiErrorBody};
use crate::shared::{hyalos, policy};
use axum::{body::Bytes, http::StatusCode, routing::get, Json, Router};
use serde::Serialize;
use serde_json::{
    json,
    value::{to_raw_value, RawValue},
    Value,
};
use std::time::Duration;

const COMMAND: &str = "hyalos level";
type Reply = Result<(StatusCode, Json<LevelAnswer>), (StatusCode, Json<ApiErrorBody>)>;

#[derive(Serialize)]
struct LevelAnswer {
    #[serde(flatten)]
    body: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    dial: Option<Box<RawValue>>,
}

async fn run(action: impl FnOnce() -> Result<LevelAnswer, &'static str> + Send + 'static) -> Reply {
    match policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(COMMAND)),
        Err(_) => return Err(api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
    Ok(match blocking_task(COMMAND, action).await? {
        Ok(answer) => (mutation_status(&answer.body), Json(answer)),
        Err(signal) => (
            StatusCode::BAD_REQUEST,
            Json(LevelAnswer {
                body: hyalos::door_error(signal),
                dial: None,
            }),
        ),
    })
}

fn dial_error(signal: &str) -> Box<RawValue> {
    to_raw_value(&hyalos::door_error(signal)).expect("level error is valid JSON")
}

fn apply_dial(level: i64) -> Box<RawValue> {
    let signal = match crate::gate::snake::crossing_path_with_timeout(
        "appliance/log-level",
        &json!({"level": level}),
        Duration::from_secs(300),
    ) {
        Ok(crossing) => {
            // The executor parsed this object; keep its original JSON bytes,
            // not a reserialization of receiptPayload or the executor wrapper.
            if crossing["receiptPayload"].is_object() {
                if let Some(raw) = crossing["rawChildStdout"]
                    .as_str()
                    .and_then(|stdout| serde_json::from_str(stdout).ok())
                {
                    return raw;
                }
            }
            crossing["firstMissingSignal"]
                .as_str()
                .filter(|signal| !signal.is_empty() && *signal != "none")
                .unwrap_or("caduceus-staff-invalid-receipt")
                .to_owned()
        }
        Err(signal) => signal,
    };
    // A failed transport has no staff object to pass through.
    dial_error(&signal)
}

async fn read() -> Reply {
    run(|| {
        Ok(LevelAnswer {
            body: hyalos::level_json(),
            dial: None,
        })
    })
    .await
}

async fn set(body: Bytes) -> Reply {
    run(move || {
        let value = serde_json::from_slice(&body).map_err(|_| hyalos::LEVEL_INVALID)?;
        let (answer, recorded_level) = hyalos::set_level_json(&value)?;
        let dial = match recorded_level {
            Some(level) => Some(apply_dial(level)),
            // The level was saved, but the deed did not commit. No staff
            // call was made, so this is a local signal, not a staff receipt.
            None if answer["changed"] == true => Some(dial_error("hyalos-deed-unwritten")),
            None => None,
        };
        Ok(LevelAnswer { body: answer, dial })
    })
    .await
}

pub fn register(router: Router) -> Router {
    router.route(LEAF_LOG_LEVEL_CANONICAL, get(read).post(set))
}
