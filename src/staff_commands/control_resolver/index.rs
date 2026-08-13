//! Staff-backed DNS resolver controls and status.

use serde_json::{json, Value};

const DNS_INTENT_METHOD: &str = "POST";
const DNS_INTENT_ROUTE: &str = "/api/dns/unbound/drop-in";

fn public_receipt(value: Value) -> Value {
    json!({
        "schema": "caduceus.network.dns.public_receipt.v1",
        "ok": value.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "primitive": value.get("actuator").or_else(|| value.get("action")).cloned().unwrap_or_else(|| json!("network.dns")),
        "changed": value.get("mutationPerformed").or_else(|| value.get("changed")).and_then(Value::as_bool).unwrap_or(false),
        "reloadOutcome": value.get("reload").or_else(|| value.get("reload_outcome")).cloned().unwrap_or_else(|| json!("not-run")),
        "proof": json!({"stagedValidation": value.get("stagedValidation").cloned().unwrap_or(Value::Null), "liveValidation": value.get("liveValidation").cloned().unwrap_or(Value::Null), "rollback": value.get("rollback").cloned().unwrap_or(Value::Null), "restorationVerified": value.get("restoration_verified").cloned().unwrap_or(Value::Null), "state": value.get("state").cloned().unwrap_or(Value::Null)}),
        "firstMissingSignal": value.get("firstMissingSignal").or_else(|| value.get("error")).cloned().unwrap_or_else(|| json!("none")),
    })
}

fn invoke(args: &[String]) -> Result<Value, String> {
    crate::shared::agathodaimon::crossing("network", "dns", &json!({"args": args})).map(public_receipt)
}

pub fn status_json() -> Result<Value, String> {
    invoke(&["status".into()])
}

pub fn read_json() -> Result<Value, String> {
    invoke(&["read".into()])
}

pub fn resolver_json(action: &str, metadata: Option<Value>) -> Result<Value, String> {
    if !["adblock", "blocklist-update", "upstream"].contains(&action) {
        return Err("caduceus-network-dns-resolver-action-invalid".into());
    }
    let mut args = vec!["resolver".into(), action.into()];
    if let Some(metadata) = metadata {
        args.push("--metadata-json".into());
        args.push(
            serde_json::to_string(&metadata)
                .map_err(|_| "caduceus-network-dns-metadata-invalid")?,
        );
    }
    invoke(&args)
}

pub fn intent_json(method: &str, route: &str, metadata: Value) -> Result<Value, String> {
    if method != DNS_INTENT_METHOD || route != DNS_INTENT_ROUTE {
        return Err("caduceus-network-dns-intent-route-refused".into());
    }
    let metadata = serde_json::to_string(&metadata)
        .map_err(|err| format!("caduceus-network-dns-metadata-invalid: {err}"))?;
    invoke(&[
        "intent".into(),
        method.into(),
        route.into(),
        "--metadata-json".into(),
        metadata,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    #[test]
    fn delegates_status_and_intent_without_touching_dns() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("dns-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let args_log = root.join("args");
        let stdin_log = root.join("stdin");
        let script = root.join("staff-dns");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s' \"$*\" > {}\ncat > {}\nprintf '{{\"schema\":\"caduceus.network.dns.intent.v1\",\"ok\":true,\"mutationPerformed\":false}}\\n'\n",
                args_log.display(),
                stdin_log.display()
            ),
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();
        std::env::set_var("CADUCEUS_AGATHODAIMON_CLI", script.to_str().unwrap());
        let result =
            intent_json("POST", "/api/dns/unbound/drop-in", json!({"dryRun":true})).unwrap();
        assert_eq!(result["schema"], "caduceus.network.dns.public_receipt.v1");
        assert_eq!(std::fs::read_to_string(args_log).unwrap(), "network dns");
        assert!(std::fs::read_to_string(stdin_log).unwrap().contains("args"));
        std::env::remove_var("CADUCEUS_AGATHODAIMON_CLI");
        let _ = std::fs::remove_dir_all(root);
    }
}
