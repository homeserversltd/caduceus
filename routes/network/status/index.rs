// Caduceus household-time band — bounded Rust face over `agathodaimon.household_time`.
//
// The public read endpoint is only admitted from a LAN peer and only when a
// future profile explicitly admits `time state`; time mutation commands are
// likewise profile-gated, but this slice adds no appliance admission entries.

use serde_json::{json, Value};

fn invoke(args: &[String]) -> Result<Value, String> {
    if args.is_empty() {
        return Err("caduceus-household-time-command-missing".to_string());
    }
    crate::gate::snake::crossing_path("settings/datetime", &json!({"args": args}))
}

pub fn state_json() -> Result<Value, String> {
    invoke(&["state".into()])
}

pub fn command(args: &[String]) -> i32 {
    match invoke(args) {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            0
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn delegates_to_named_launcher_without_time_mutation_in_rust() {
        let _guard = crate::gate::snake::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let root =
            std::env::temp_dir().join(format!("caduceus-time-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let log = root.join("args");
        let stdin_log = root.join("stdin");
        let launcher = root.join("launcher");
        std::fs::write(&launcher, format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\ncat > {}\nprintf '{{\"schema\":\"caduceus.household-time.receipt.v1\",\"ok\":true,\"primitive\":\"state\"}}\\n'\n",
            log.display(),
            stdin_log.display()
        )).unwrap();
        let mut permissions = std::fs::metadata(&launcher).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&launcher, permissions).unwrap();
        std::env::set_var("CADUCEUS_AGATHODAIMON_CLI", launcher.to_str().unwrap());
        let state = state_json().unwrap();
        assert_eq!(state["primitive"], "state");
        assert_eq!(std::fs::read_to_string(&log).unwrap().trim(), "settings datetime");
        let envelope: Value = serde_json::from_str(&std::fs::read_to_string(&stdin_log).unwrap()).unwrap();
        assert_eq!(envelope["transition"], "settings/datetime");
        assert_eq!(envelope["payload"]["args"], json!(["state"]));
        assert_eq!(envelope["schema"], crate::protocol::SCHEMA_ID);
        assert!(envelope["intent_id"].as_str().is_some_and(|v| !v.is_empty()));
        std::env::remove_var("CADUCEUS_AGATHODAIMON_CLI");
        let _ = std::fs::remove_dir_all(root);
    }
}


use axum::{response::Json, Router};
use crate::gate::{gated_json, ApiErrorBody};

async fn network_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("network status", network::status_json).await
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/status", axum::routing::get(network_status_route))
}
