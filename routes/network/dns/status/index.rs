// Staff-backed DNS resolver controls and status.

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
    crate::gate::snake::crossing_path("network/dns", &json!({"args": args}))
        .map(public_receipt)
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


use axum::{extract::Json, http::{HeaderMap, StatusCode}, Router};
use serde::Deserialize;
use crate::gate::{api_error, api_error_signal, document_attendance_admits, mutation_status, ApiErrorBody};
use crate::shared::policy;
use crate::routes::{dns_control, dns};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsDeviceNameBody {
    hostname: String,
    ip: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsAliasBody {
    label: String,
    hostname: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DnsAdblockBody {
    pub(crate) enabled: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DnsUpstreamBody {
    preset: Option<String>,
    custom: Option<Vec<String>>,
    dot: bool,
}

fn dns_mutation_admits(
    command: &'static str,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(command)),
        Err(_) => return Err(api_error_signal(command, "caduceus-profile-missing")),
    }
    let document = headers
        .get("x-caduceus-document")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty());
    if let Some(document) = document {
        document_attendance_admits(
            document,
            headers
                .get("x-caduceus-attendance")
                .and_then(|value| value.to_str().ok()),
        )
        .map_err(|signal| api_error_signal(command, &signal))
    } else {
        Ok(())
    }
}

fn dns_mutation_response(
    command: &'static str,
    result: Result<Value, String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    result
        .map(|value| (mutation_status(&value), Json(value)))
        .map_err(|err| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    schema: "caduceus.api.error.v1",
                    ok: false,
                    command: command.to_string(),
                    first_missing_signal: err,
                }),
            )
        })
}

async fn dns_status_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dns status").await
}

async fn dns_resolver_status_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dns resolver status").await
}

async fn dns_resolver_adblock_route(
    headers: HeaderMap,
    Json(body): Json<DnsAdblockBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns resolver adblock";
    dns_mutation_admits(COMMAND, &headers)?;
    dns_mutation_response(
        COMMAND,
        dns_control::resolver_json("adblock", Some(json!({"enabled": body.enabled}))),
    )
}

async fn dns_resolver_blocklist_update_route(
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns resolver blocklist-update";
    dns_mutation_admits(COMMAND, &headers)?;
    dns_mutation_response(
        COMMAND,
        dns_control::resolver_json("blocklist-update", None),
    )
}

async fn dns_resolver_upstream_route(
    headers: HeaderMap,
    Json(body): Json<DnsUpstreamBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns resolver upstream";
    dns_mutation_admits(COMMAND, &headers)?;
    dns_mutation_response(
        COMMAND,
        dns_control::resolver_json(
            "upstream",
            Some(json!({"preset": body.preset, "custom": body.custom, "dot": body.dot})),
        ),
    )
}

async fn network_dns_route(
    headers: HeaderMap,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns intent";
    const TARGET: &str = "/api/dns/unbound/drop-in";
    dns_mutation_admits(COMMAND, &headers)?;
    dns_mutation_response(COMMAND, dns_control::intent_json("POST", TARGET, metadata))
}

async fn dns_device_name_create_route(
    headers: HeaderMap,
    Json(body): Json<DnsDeviceNameBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns device-name create";
    dns_mutation_admits(COMMAND, &headers)?;
    dns_mutation_response(
        COMMAND,
        dns::device_name_json("create", &body.hostname, &body.ip),
    )
}

async fn dns_device_name_remove_route(
    headers: HeaderMap,
    Json(body): Json<DnsDeviceNameBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns device-name remove";
    dns_mutation_admits(COMMAND, &headers)?;
    dns_mutation_response(
        COMMAND,
        dns::device_name_json("remove", &body.hostname, &body.ip),
    )
}

async fn dns_alias_create_route(
    headers: HeaderMap,
    Json(body): Json<DnsAliasBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns alias create";
    dns_mutation_admits(COMMAND, &headers)?;
    dns_mutation_response(
        COMMAND,
        dns::alias_json("create", &body.label, &body.hostname),
    )
}

async fn dns_alias_remove_route(
    headers: HeaderMap,
    Json(body): Json<DnsAliasBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns alias remove";
    dns_mutation_admits(COMMAND, &headers)?;
    dns_mutation_response(
        COMMAND,
        dns::alias_json("remove", &body.label, &body.hostname),
    )
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
// HOIST: obliterate after counterparty realignment
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/dns/status", axum::routing::get(dns_status_read_route)).route("/api/v1/network/dns/resolver/status", axum::routing::get(dns_resolver_status_route)).route("/api/v1/network/dns", axum::routing::post(network_dns_route)).route("/api/v1/network/dns/adblock", axum::routing::post(dns_resolver_adblock_route)).route("/api/v1/network/dns/blocklist/update", axum::routing::post(dns_resolver_blocklist_update_route)).route("/api/v1/network/dns/upstream", axum::routing::post(dns_resolver_upstream_route)).route("/api/v1/network/dns/device-name/create", axum::routing::post(dns_device_name_create_route)).route("/api/v1/network/dns/device-name/remove", axum::routing::post(dns_device_name_remove_route)).route("/api/v1/network/dns/alias/create", axum::routing::post(dns_alias_create_route)).route("/api/v1/network/dns/alias/remove", axum::routing::post(dns_alias_remove_route))
}
