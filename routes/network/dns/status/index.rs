// Staff-backed DNS resolver controls and status.

use serde_json::{json, Value};

#[cfg(carapace_feature_unbound)]
const BLOCKLIST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

#[cfg(carapace_feature_unbound)]
const DNS_INTENT_METHOD: &str = "POST";
#[cfg(carapace_feature_unbound)]
const DNS_INTENT_ROUTE: &str = "/api/dns/unbound/drop-in";

fn public_receipt(value: &Value) -> Value {
    json!({
        "schema": "caduceus.network.dns.public_receipt.v1",
        "ok": crate::gate::receipt_succeeded(value),
        "primitive": value.get("actuator").or_else(|| value.get("action")).cloned().unwrap_or_else(|| json!("network.dns")),
        "changed": value.get("mutationPerformed").or_else(|| value.get("changed")).and_then(Value::as_bool).unwrap_or(false),
        "reloadOutcome": value.get("reload").or_else(|| value.get("reload_outcome")).cloned().unwrap_or_else(|| json!("not-run")),
        "proof": json!({"stagedValidation": value.get("stagedValidation").cloned().unwrap_or(Value::Null), "liveValidation": value.get("liveValidation").cloned().unwrap_or(Value::Null), "rollback": value.get("rollback").cloned().unwrap_or(Value::Null), "restorationVerified": value.get("restoration_verified").cloned().unwrap_or(Value::Null), "state": value.get("state").cloned().unwrap_or(Value::Null)}),
        "firstMissingSignal": value.get("doorSignal").or_else(|| value.get("firstMissingSignal")).or_else(|| value.get("error")).cloned().unwrap_or_else(|| json!("none")),
    })
}

fn with_public_receipt(mut receipt: Value, extra_keys: &[&str]) -> Value {
    let mut projection = public_receipt(&receipt);
    for &key in extra_keys {
        projection[key] = receipt.get(key).cloned().unwrap_or(Value::Null);
    }
    if let Some(fields) = receipt.as_object_mut() {
        fields.entry("publicReceipt").or_insert(projection);
    }
    receipt
}

fn invoke(band: &str, payload: Value) -> Result<Value, String> {
    crate::gate::snake::crossing_path_receipt(band, &payload)
        .map(|receipt| with_public_receipt(receipt, &[]))
}

#[cfg(carapace_feature_unbound)]
fn invoke_blocklist(band: &str, payload: Value) -> Result<Value, String> {
    // The blocklist's fetch deadline is longer than crossing_path_receipt's.
    let mut crossed = crate::gate::snake::crossing_path_with_timeout(band, &payload, BLOCKLIST_TIMEOUT)?;
    let mut receipt = crossed.get_mut("receiptPayload").map(std::mem::take)
        .ok_or_else(|| "caduceus-blocklist-receipt-missing".to_string())?;
    let failed_exit = crossed.get("ok").and_then(Value::as_bool) != Some(true);
    let exit_signal = || {
        crossed.get("firstMissingSignal").and_then(Value::as_str)
            .filter(|signal| !signal.is_empty() && *signal != "none")
            .unwrap_or("caduceus-agathodaimon-refused")
    };
    if !receipt.is_object() {
        return Err(if failed_exit { exit_signal() } else { "caduceus-staff-invalid-receipt" }.into());
    }
    let stop_bound = crate::routes::leaf_schema::bound(&receipt, band);
    let door_signal = if failed_exit && receipt.get("ok").and_then(Value::as_bool) != Some(false) {
        Some(exit_signal())
    } else if !stop_bound {
        Some("caduceus-schema-desync")
    } else {
        None
    };
    if let (Some(signal), Some(fields)) = (door_signal, receipt.as_object_mut()) {
        fields.entry("doorSignal").or_insert_with(|| json!(signal));
    }
    Ok(with_public_receipt(receipt, &["outcome", "domainCount", "sources", "firstFailingSource"]))
}

#[cfg(carapace_feature_unbound)]
fn carry_pin_marker(payload: &mut serde_json::Map<String, Value>, flags: Option<&Value>) {
    use crate::gate::ADMINISTRATIVE_PIN_REDACTED;

    // Forward the HTTP gate's marker, never a credential or arbitrary flags.
    if flags.and_then(|value| value.pointer("/exousia/pin")).and_then(Value::as_str)
        == Some(ADMINISTRATIVE_PIN_REDACTED)
    {
        payload.insert("flags".into(), json!({"exousia": {"pin": ADMINISTRATIVE_PIN_REDACTED}}));
    }
}

pub fn status_json() -> Result<Value, String> {
    invoke("network/dns/status", json!({}))
}

pub fn read_json() -> Result<Value, String> {
    invoke("network/dns/read", json!({}))
}

#[cfg(carapace_feature_unbound)]
pub fn resolver_json(action: &str, metadata: Option<Value>) -> Result<Value, String> {
    let metadata = metadata.unwrap_or(Value::Null);
    let mut extra = metadata.as_object().cloned().unwrap_or_default();
    for key in ["flags", "exousia", "pin", "oldPin", "newPin"] {
        extra.remove(key);
    }
    // Presence itself refuses at the snake; preserve any active spelling.
    let mut dry_run = None;
    for key in ["dry-run", "dryRun", "dry_run"] {
        if let Some(value) = extra.remove(key) {
            if dry_run.is_none() && !value.is_null() && value != Value::Bool(false) {
                dry_run = Some(value);
            }
        }
    }
    if let Some(value) = dry_run {
        extra.insert("dry-run".into(), value);
    }
    let mut payload = match action {
        "adblock" => {
            extra.insert("enabled".into(), metadata.get("enabled").cloned().unwrap_or(Value::Null));
            extra
        }
        "blocklist-update" => serde_json::Map::new(),
        "upstream" => {
            for key in ["preset", "custom", "dot"] {
                extra.insert(key.into(), metadata.get(key).cloned().unwrap_or(Value::Null));
            }
            extra
        }
        _ => return Err("dns-verb-unknown".into()),
    };
    carry_pin_marker(&mut payload, metadata.get("flags"));
    let payload = Value::Object(payload);
    let band = format!("network/dns/resolver/{action}");
    if action == "blocklist-update" {
        invoke_blocklist(&band, payload)
    } else {
        invoke(&band, payload)
    }
}

#[cfg(carapace_feature_unbound)]
pub fn blocklist_source_json(verb: &str, payload: Value) -> Result<Value, String> {
    invoke_blocklist(&format!("network/dns/blocklist/source/{verb}"), payload)
}

#[cfg(carapace_feature_unbound)]
pub fn intent_json(method: &str, route: &str, metadata: Value) -> Result<Value, String> {
    if method != DNS_INTENT_METHOD || route != DNS_INTENT_ROUTE {
        return Err("dns-intent-not-admitted".into());
    }
    let mut payload = serde_json::Map::new();
    for key in ["target", "dropIn"] {
        if let Some(value) = metadata.get(key) {
            payload.insert(key.into(), value.clone());
        }
    }
    if let Some(value) = metadata.get("dryRun") {
        payload.insert("dry-run".into(), value.clone());
    }
    carry_pin_marker(&mut payload, metadata.get("flags"));
    invoke("network/dns/drop-in/apply", Value::Object(payload))
}

use axum::{extract::Json, http::StatusCode, Router};
#[cfg(carapace_feature_unbound)]
use axum::http::{HeaderMap};
#[cfg(carapace_feature_unbound)]
use serde::Deserialize;
use crate::gate::{api_error, api_error_signal, ApiErrorBody};
#[cfg(carapace_feature_unbound)]
use crate::gate::{administrative_admits, mutation_status};
#[cfg(carapace_feature_unbound)]
use crate::shared::policy;
#[cfg(carapace_feature_unbound)]
use crate::routes::{dns_control, dns};

#[cfg(carapace_feature_unbound)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsDeviceNameBody {
    hostname: String,
    ip: Option<String>,
    r#move: Option<bool>,
    adopt: Option<bool>,
    #[serde(default)]
    flags: Option<Value>,
}

#[cfg(carapace_feature_unbound)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsDeviceNameRemoveBody {
    hostname: String,
    ip: String,
    #[serde(default)]
    flags: Option<Value>,
}

#[cfg(carapace_feature_unbound)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsAliasBody {
    label: String,
    hostname: String,
    #[serde(default)]
    flags: Option<Value>,
}

#[cfg(carapace_feature_unbound)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsAdblockBody {
    pub(crate) enabled: bool,
    #[serde(default)]
    flags: Option<Value>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

#[cfg(carapace_feature_unbound)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DnsUpstreamBody {
    preset: Option<String>,
    custom: Option<Vec<String>>,
    dot: bool,
    #[serde(default)]
    flags: Option<Value>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

#[cfg(carapace_feature_unbound)]
#[derive(Deserialize)]
struct DnsBlocklistSourceBody {
    url: String,
    #[serde(default)]
    flags: Option<Value>,
}

#[cfg(carapace_feature_unbound)]
impl DnsBlocklistSourceBody {
    fn into_payload(self) -> Value {
        let mut payload = serde_json::Map::new();
        payload.insert("url".into(), json!(self.url));
        carry_pin_marker(&mut payload, self.flags.as_ref());
        Value::Object(payload)
    }
}

#[cfg(carapace_feature_unbound)]
fn dns_mutation_admits(
    command: &'static str,
    route: &'static str,
    headers: &HeaderMap,
    body: &Value,
) -> Result<(), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(command)),
        Err(_) => return Err(api_error_signal(command, "caduceus-carapace-desync")),
    }
    administrative_admits(headers, body, route)
        .map_err(|signal| api_error_signal(command, &signal))
}

#[cfg(carapace_feature_unbound)]
async fn dns_mutation_response<F>(
    command: &'static str,
    operation: F,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)>
where
    F: FnOnce() -> Result<Value, String> + Send + 'static,
{
    let result = crate::gate::blocking_task(command, operation).await?;
    result
        .map(|receipt| {
            // The receipt (including any doorSignal) governs HTTP; the publicReceipt is a view.
            (mutation_status(&receipt), Json(receipt))
        })
        .map_err(|err| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ApiErrorBody {
                    ok: false,
                    command: command.to_string(),
                    first_missing_signal: err,
                }),
            )
        })
}

async fn dns_status_read_route() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    network_read_route("network dns status").await
}

async fn dns_resolver_status_route() -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let (status, Json(mut value)) = network_read_route("network dns resolver status").await?;
    if status == StatusCode::NOT_FOUND {
        return Ok((status, Json(value)));
    }
    if status != StatusCode::OK {
        return Ok((status, Json(with_public_receipt(value, &[]))));
    }
    let Some(fields) = value.get_mut("payload")
        .filter(|receipt| crate::routes::leaf_schema::bound(receipt, "network/dns/resolver/status"))
        .and_then(Value::as_object_mut)
    else {
        // The configured native read override can answer an unseated readback.
        return Ok((status, Json(value)));
    };
    let mut receipt = std::mem::take(fields);
    // Coronatio's current pane checks payload.ok before finding the resolver fields.
    receipt.entry("payload").or_insert_with(|| json!({"ok": true}));
    if let Some(context) = value.get_mut("load_context").map(std::mem::take) {
        let key = if receipt.contains_key("load_context") { "caduceus_load_context" } else { "load_context" };
        receipt.entry(key).or_insert(context);
    }
    Ok((status, Json(with_public_receipt(Value::Object(receipt), &[]))))
}

#[cfg(carapace_feature_unbound)]
async fn dns_resolver_adblock_route(
    headers: HeaderMap,
    Json(body): Json<DnsAdblockBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns resolver adblock";
    dns_mutation_admits(
        COMMAND,
        "/api/v1/network/dns/adblock",
        &headers,
        &json!({"flags": body.flags.as_ref()}),
    )?;
    dns_mutation_response(COMMAND, move || {
        let mut metadata = body.extra;
        metadata.insert("enabled".into(), json!(body.enabled));
        if let Some(flags) = body.flags {
            metadata.insert("flags".into(), flags);
        }
        dns_control::resolver_json("adblock", Some(Value::Object(metadata)))
    })
    .await
}

#[cfg(carapace_feature_unbound)]
async fn dns_resolver_blocklist_update_route(
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns resolver blocklist-update";
    let metadata = serde_json::from_slice(&body).ok();
    dns_mutation_admits(
        COMMAND,
        "/api/v1/network/dns/blocklist/update",
        &headers,
        metadata.as_ref().unwrap_or(&Value::Null),
    )?;
    dns_mutation_response(COMMAND, move || {
        dns_control::resolver_json("blocklist-update", metadata)
    })
    .await
}

#[cfg(carapace_feature_unbound)]
async fn dns_resolver_upstream_route(
    headers: HeaderMap,
    Json(body): Json<DnsUpstreamBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns resolver upstream";
    dns_mutation_admits(
        COMMAND,
        "/api/v1/network/dns/upstream",
        &headers,
        &json!({"flags": body.flags.as_ref()}),
    )?;
    dns_mutation_response(COMMAND, move || {
        let mut metadata = body.extra;
        metadata.insert("preset".into(), json!(body.preset));
        metadata.insert("custom".into(), json!(body.custom));
        metadata.insert("dot".into(), json!(body.dot));
        if let Some(flags) = body.flags {
            metadata.insert("flags".into(), flags);
        }
        dns_control::resolver_json(
            "upstream",
            Some(Value::Object(metadata)),
        )
    })
    .await
}

#[cfg(carapace_feature_unbound)]
async fn dns_blocklist_source_add_route(
    headers: HeaderMap,
    Json(body): Json<DnsBlocklistSourceBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns blocklist source add";
    dns_mutation_admits(COMMAND, "/api/v1/network/dns/blocklist/source/add", &headers, &json!({"flags": body.flags.as_ref()}))?;
    dns_mutation_response(COMMAND, move || dns_control::blocklist_source_json("add", body.into_payload())).await
}

#[cfg(carapace_feature_unbound)]
async fn dns_blocklist_source_remove_route(
    headers: HeaderMap,
    Json(body): Json<DnsBlocklistSourceBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns blocklist source remove";
    dns_mutation_admits(COMMAND, "/api/v1/network/dns/blocklist/source/remove", &headers, &json!({"flags": body.flags.as_ref()}))?;
    dns_mutation_response(COMMAND, move || dns_control::blocklist_source_json("remove", body.into_payload())).await
}

#[cfg(carapace_feature_unbound)]
async fn dns_device_name_create_route(
    headers: HeaderMap,
    Json(body): Json<DnsDeviceNameBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns device-name create";
    dns_mutation_admits(
        COMMAND,
        "/api/v1/network/dns/device-name/create",
        &headers,
        &json!({"flags": body.flags.as_ref()}),
    )?;
    let hostname = body.hostname;
    let ip = body.ip;
    dns_mutation_response(COMMAND, move || {
        dns::device_name_create_json(&hostname, ip.as_deref(), body.r#move, body.adopt)
    })
    .await
}

#[cfg(carapace_feature_unbound)]
async fn dns_device_name_remove_route(
    headers: HeaderMap,
    Json(body): Json<DnsDeviceNameRemoveBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns device-name remove";
    dns_mutation_admits(
        COMMAND,
        "/api/v1/network/dns/device-name/remove",
        &headers,
        &json!({"flags": body.flags.as_ref()}),
    )?;
    let hostname = body.hostname;
    let ip = body.ip;
    dns_mutation_response(COMMAND, move || dns::device_name_json("remove", &hostname, &ip))
        .await
}

#[cfg(carapace_feature_unbound)]
async fn dns_alias_create_route(
    headers: HeaderMap,
    Json(body): Json<DnsAliasBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns alias create";
    dns_mutation_admits(
        COMMAND,
        "/api/v1/network/dns/alias/create",
        &headers,
        &json!({"flags": body.flags.as_ref()}),
    )?;
    let label = body.label;
    let hostname = body.hostname;
    dns_mutation_response(COMMAND, move || dns::alias_json("create", &label, &hostname)).await
}

#[cfg(carapace_feature_unbound)]
async fn dns_alias_remove_route(
    headers: HeaderMap,
    Json(body): Json<DnsAliasBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns alias remove";
    dns_mutation_admits(
        COMMAND,
        "/api/v1/network/dns/alias/remove",
        &headers,
        &json!({"flags": body.flags.as_ref()}),
    )?;
    let label = body.label;
    let hostname = body.hostname;
    dns_mutation_response(COMMAND, move || dns::alias_json("remove", &label, &hostname)).await
}

#[cfg(carapace_feature_unbound)]
async fn network_dns_route(
    headers: HeaderMap,
    Json(metadata): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network dns intent";
    const TARGET: &str = "/api/dns/unbound/drop-in";
    dns_mutation_admits(
        COMMAND,
        "/api/v1/network/dns",
        &headers,
        &metadata,
    )?;
    dns_mutation_response(COMMAND, move || dns_control::intent_json("POST", TARGET, metadata)).await
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    let router = router
        .route(
            "/api/v1/network/dns/status",
            axum::routing::get(dns_status_read_route),
        )
        .route(
            "/api/v1/network/dns/resolver/status",
            axum::routing::get(dns_resolver_status_route),
        );
    #[cfg(carapace_feature_unbound)]
    let router = router
        .route(
            "/api/v1/network/dns/adblock",
            axum::routing::post(dns_resolver_adblock_route),
        )
        .route(
            "/api/v1/network/dns/blocklist/update",
            axum::routing::post(dns_resolver_blocklist_update_route),
        )
        .route("/api/v1/network/dns/blocklist/source/add", axum::routing::post(dns_blocklist_source_add_route))
        .route("/api/v1/network/dns/blocklist/source/remove", axum::routing::post(dns_blocklist_source_remove_route))
        .route(
            "/api/v1/network/dns/upstream",
            axum::routing::post(dns_resolver_upstream_route),
        )
        .route(
            "/api/v1/network/dns/device-name/create",
            axum::routing::post(dns_device_name_create_route),
        )
        .route(
            "/api/v1/network/dns/device-name/remove",
            axum::routing::post(dns_device_name_remove_route),
        )
        .route(
            "/api/v1/network/dns/alias/create",
            axum::routing::post(dns_alias_create_route),
        )
        .route(
            "/api/v1/network/dns/alias/remove",
            axum::routing::post(dns_alias_remove_route),
        )
        .route("/api/v1/network/dns", axum::routing::post(network_dns_route));
    router
}
