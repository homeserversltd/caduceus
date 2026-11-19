use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{hyalos, policy};
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

pub const NAMESPACE: &str = "update/history";
const COMMAND: &str = "update history";
const SCHEMA: &str = "caduceus.update.history.v1";

fn project_run(row: &Value) -> Value {
    let family = &row["families"]["harmonia"];
    json!({
        "run_id": row["routine"],
        "profile": family["profile"],
        "finished_at": family["finished_at"].as_str().or_else(|| row["at"].as_str()),
        "outcome": if row["trouble"] == true { "failed" } else { "ok" },
        "duration_ms": row["duration_ms"],
        "module_count": family["module_count"],
        "updated_count": family["updated_count"],
        "failures": family["failures"].as_array().map(Vec::as_slice).unwrap_or_default(),
    })
}

fn history_json() -> Value {
    let level = hyalos::body_level().ok();
    match hyalos::read_harmonia_runs() {
        Ok(rows) => {
            let runs: Vec<Value> = rows.iter().map(project_run).collect();
            json!({"ok": true, "schema": SCHEMA, "runs": runs, "level": level})
        }
        Err(_) => json!({
            "ok": false,
            "schema": SCHEMA,
            "runs": [],
            "level": level,
            "firstMissingSignal": "caduceus-update-history-log-unreadable",
        }),
    }
}

pub(crate) async fn route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(COMMAND) {
        Ok(true) => Ok(Json(crate::gate::blocking_task(COMMAND, history_json).await?)),
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-carapace-desync")),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/update/history", axum::routing::get(route))
}
