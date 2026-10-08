// Firewall staff command, crossed only through agathodaimon network firewall.
use serde_json::Value;

pub fn invoke(intent: Value) -> Result<Value, Value> {
    crate::gate::snake::crossing_path("network/firewall", &intent)
        .map_err(|e| serde_json::json!({"error":e}))
}
pub fn command_json(intent: Value) -> Result<Value, Value> {
    match invoke(intent) {
        Ok(v) => Ok(v),
        Err(v) => {
            let signal = v
                .get("error")
                .and_then(Value::as_str)
                .or_else(|| v.get("firstMissingSignal").and_then(Value::as_str))
                .unwrap_or("firewall-staff-refused");
            let signal = if signal == "caduceus-agathodaimon-output-too-large" {
                "firewall-staff-output-too-large"
            } else {
                signal
            };
            Err(serde_json::json!({"ok":false,"firstMissingSignal":signal}))
        }
    }
}

use crate::gate::ApiErrorBody;
use crate::routes::firewall;
use crate::shared::policy;
use axum::{
    extract::{Json, Path},
    http::StatusCode,
    Router,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirewallChildBody {
    schema: String,
    mac: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirewallWhitelistBody {
    schema: String,
    mac: String,
    hostnames: Vec<String>,
    expected_revision: String,
}

fn firewall_status(value: &Value) -> StatusCode {
    let signal = value
        .get("firstMissingSignal")
        .or_else(|| value.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("");
    match signal {
        signal if signal.contains("policy-not-found") => StatusCode::NOT_FOUND,
        signal if signal.contains("revision-conflict") || signal.contains("binding-mismatch") => {
            StatusCode::CONFLICT
        }
        signal if signal.contains("rollback") && signal.contains("failed") => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
        signal
            if signal.contains("staff-")
                || signal.contains("unavailable")
                || signal.contains("live-command") =>
        {
            StatusCode::SERVICE_UNAVAILABLE
        }
        signal
            if signal.contains("invalid")
                || signal.contains("refused")
                || signal.contains("foreign")
                || signal.contains("ambiguous")
                || signal.contains("validator")
                || signal.contains("config") =>
        {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

async fn firewall_invoke_http(
    command: &str,
    intent: Value,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let result = crate::gate::blocking_task(command, move || firewall::invoke(intent))
        .await
        .map_err(|(status, Json(body))| (status, Json(serde_json::json!(body))))?;
    result
        .map(Json)
        .map_err(|value| (firewall_status(&value), Json(value)))
}

fn firewall_refusal(status: StatusCode, signal: &str) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(serde_json::json!({"ok": false, "firstMissingSignal": signal})),
    )
}

fn firewall_mac(value: &str) -> Option<String> {
    let compact = value.to_ascii_lowercase().replace('-', ":");
    let canonical = if compact.len() == 12 && compact.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        compact
            .as_bytes()
            .chunks(2)
            .map(|pair| std::str::from_utf8(pair).ok())
            .collect::<Option<Vec<_>>>()?
            .join(":")
    } else {
        compact
    };
    let valid = canonical.len() == 17
        && canonical
            .split(':')
            .all(|part| part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit()))
        && canonical != "00:00:00:00:00:00"
        && canonical != "ff:ff:ff:ff:ff:ff";
    valid.then_some(canonical)
}

fn firewall_fqdns(sites: &[String]) -> bool {
    sites.iter().all(|site| {
        if site.is_empty()
            || site.len() > 253
            || site.ends_with(".home.arpa")
            || site.ends_with(".home.arpa.")
        {
            return false;
        }
        let name = site.trim_end_matches('.');
        name.split('.').count() >= 2
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            })
    })
}

fn firewall_digest(value: &str) -> bool {
    value.len() == 64
        && value.bytes().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

async fn firewall_read(
    action: &str,
    mac: Option<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let command = "caduceus.network.firewall.read";
    match policy::allows_command(command) {
        Ok(true) => {
            let mut intent = serde_json::json!({"action": action});
            if let Some(mac) = mac {
                intent["mac"] = Value::String(mac);
            }
            firewall_invoke_http(command, intent).await
        }
        Ok(false) => Err(firewall_refusal(
            StatusCode::FORBIDDEN,
            "caduceus-public-action-not-allowed",
        )),
        Err(_) => Err(firewall_refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "caduceus-profile-missing",
        )),
    }
}

async fn firewall_observed_route() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_read("observed", None).await
}

async fn firewall_children_route() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_read("list", None).await
}

async fn firewall_child_whitelist_route(
    Path(mac): Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mac = firewall_mac(&mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    firewall_read("whitelist-get", Some(mac)).await
}

async fn firewall_register_route(
    headers: HeaderMap,
    Json(body): Json<FirewallChildBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let command = "caduceus.network.firewall.put";
    let mac = firewall_mac(&body.mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    if body.schema != "caduceus.network.firewall.child.v1" {
        return Err(firewall_refusal(
            StatusCode::BAD_REQUEST,
            "firewall-input-invalid",
        ));
    }
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => {
            return Err(firewall_refusal(
                StatusCode::FORBIDDEN,
                "caduceus-public-action-not-allowed",
            ))
        }
        Err(_) => {
            return Err(firewall_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "caduceus-profile-missing",
            ))
        }
    }
    attendance_admits(
        FIREWALL_DOCUMENT_TARGET,
        headers
            .get("x-caduceus-document")
            .and_then(|value| value.to_str().ok()),
        headers
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| firewall_refusal(StatusCode::FORBIDDEN, &signal))?;
    firewall_invoke_http(command, serde_json::json!({"action":"register", "mac":mac}))
        .await
        .map(|value| (StatusCode::OK, value))
}

async fn firewall_unregister_route(
    headers: HeaderMap,
    Path(path_mac): Path<String>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let command = "caduceus.network.firewall.delete";
    let mac = firewall_mac(&path_mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => {
            return Err(firewall_refusal(
                StatusCode::FORBIDDEN,
                "caduceus-public-action-not-allowed",
            ))
        }
        Err(_) => {
            return Err(firewall_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "caduceus-profile-missing",
            ))
        }
    }
    attendance_admits(
        FIREWALL_DOCUMENT_TARGET,
        headers
            .get("x-caduceus-document")
            .and_then(|value| value.to_str().ok()),
        headers
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| firewall_refusal(StatusCode::FORBIDDEN, &signal))?;
    firewall_invoke_http(command, serde_json::json!({"action":"unregister", "mac":mac}))
        .await
        .map(|value| (StatusCode::OK, value))
}

async fn firewall_whitelist_set_route(
    headers: HeaderMap,
    Path(path_mac): Path<String>,
    Json(body): Json<FirewallWhitelistBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let command = "caduceus.network.firewall.put";
    let path = firewall_mac(&path_mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    let mac = firewall_mac(&body.mac)
        .filter(|mac| mac == &path)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-mismatch"))?;
    if body.schema != "caduceus.network.firewall.whitelist.v1"
        || !(0..=64).contains(&body.hostnames.len())
        || !firewall_fqdns(&body.hostnames)
        || !firewall_digest(&body.expected_revision)
    {
        return Err(firewall_refusal(
            StatusCode::BAD_REQUEST,
            "firewall-input-invalid",
        ));
    }
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => {
            return Err(firewall_refusal(
                StatusCode::FORBIDDEN,
                "caduceus-public-action-not-allowed",
            ))
        }
        Err(_) => {
            return Err(firewall_refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "caduceus-profile-missing",
            ))
        }
    }
    attendance_admits(
        FIREWALL_DOCUMENT_TARGET,
        headers
            .get("x-caduceus-document")
            .and_then(|value| value.to_str().ok()),
        headers
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| firewall_refusal(StatusCode::FORBIDDEN, &signal))?;
    firewall_invoke_http(command, serde_json::json!({
        "action":"whitelist-set",
        "mac":mac,
        "hostnames":body.hostnames,
        "revision":body.expected_revision
    }))
    .await
    .map(|value| (StatusCode::OK, value))
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router
        .route(
            "/api/v1/network/firewall/observed",
            axum::routing::get(firewall_observed_route),
        )
        .route(
            "/api/v1/network/firewall/children",
            axum::routing::get(firewall_children_route).post(firewall_register_route).layer(
                axum::extract::DefaultBodyLimit::max(8192),
            ),
        )
        .route(
            "/api/v1/network/firewall/children/:mac",
            axum::routing::delete(firewall_unregister_route),
        )
        .route(
            "/api/v1/network/firewall/children/:mac/whitelist",
            axum::routing::get(firewall_child_whitelist_route)
                .put(firewall_whitelist_set_route)
                .layer(axum::extract::DefaultBodyLimit::max(8192)),
        )
}
