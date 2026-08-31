// Firewall staff command, crossed only through agathodaimon network firewall.
use serde_json::Value;

pub fn invoke(intent: Value) -> Result<Value, Value> {
    crate::gate::snake::crossing_path("network/firewall", &intent).map_err(|e| serde_json::json!({"error":e}))
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


use axum::{extract::{Json, Path}, http::StatusCode, Router};
use serde::Deserialize;
use crate::gate::ApiErrorBody;
use crate::routes::firewall;
use crate::shared::policy;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirewallPutBody {
    schema: String,
    mac: String,
    mode: String,
    sites: Vec<String>,
    expected_revision: String,
    pub(crate) enabled: bool,
    enforcement: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FirewallDeleteBody {
    schema: String,
    mac: String,
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

fn firewall_read(
    action: &str,
    mac: Option<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match policy::allows_command("caduceus.network.firewall.read") {
        Ok(true) => {
            let mut intent = serde_json::json!({"action": action});
            if let Some(mac) = mac {
                intent["mac"] = Value::String(mac);
            }
            firewall::invoke(intent)
                .map(Json)
                .map_err(|value| (firewall_status(&value), Json(value)))
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

async fn firewall_status_route() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_read("status", None)
}

async fn firewall_policies_route() -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    firewall_read("list", None)
}

async fn firewall_policy_route(
    axum::extract::Path(mac): axum::extract::Path<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mac = firewall_mac(&mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    firewall_read("get", Some(mac))
}

async fn firewall_put_route(
    headers: HeaderMap,
    axum::extract::Path(path_mac): axum::extract::Path<String>,
    Json(body): Json<FirewallPutBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let command = "caduceus.network.firewall.put";
    let path = firewall_mac(&path_mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    let mac = firewall_mac(&body.mac)
        .filter(|mac| mac == &path)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-mismatch"))?;
    if body.schema != "caduceus.network.firewall.policy.v1"
        || body.mode != "allow-only"
        || body.enforcement != "dns-policy"
        || !(1..=64).contains(&body.sites.len())
        || !firewall_fqdns(&body.sites)
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
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| firewall_refusal(StatusCode::FORBIDDEN, &signal))?;
    let intent = if body.enabled {
        serde_json::json!({"action":"put", "mac":mac, "fqdns":body.sites, "revision":body.expected_revision})
    } else {
        serde_json::json!({"action":"delete", "mac":mac, "revision":body.expected_revision})
    };
    firewall::invoke(intent)
        .map(|value| (StatusCode::OK, Json(value)))
        .map_err(|value| (firewall_status(&value), Json(value)))
}

async fn firewall_delete_route(
    headers: HeaderMap,
    axum::extract::Path(path_mac): axum::extract::Path<String>,
    Json(body): Json<FirewallDeleteBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let command = "caduceus.network.firewall.delete";
    let path = firewall_mac(&path_mac)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-invalid"))?;
    let mac = firewall_mac(&body.mac)
        .filter(|mac| mac == &path)
        .ok_or_else(|| firewall_refusal(StatusCode::BAD_REQUEST, "firewall-mac-mismatch"))?;
    if body.schema != "caduceus.network.firewall.policy.delete.v1"
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
            .get("x-caduceus-attendance")
            .and_then(|value| value.to_str().ok()),
    )
    .map_err(|signal| firewall_refusal(StatusCode::FORBIDDEN, &signal))?;
    firewall::invoke(
        serde_json::json!({"action":"delete", "mac":mac, "revision":body.expected_revision}),
    )
    .map(|value| (StatusCode::OK, Json(value)))
    .map_err(|value| (firewall_status(&value), Json(value)))
}

/// Canonical registration seam for this leaf.
pub fn register(router: Router) -> Router {
    router
        .route(
            "/api/v1/network/firewall/status",
            axum::routing::get(firewall_status_route),
        )
        .route(
            "/api/v1/network/firewall/policies",
            axum::routing::get(firewall_policies_route),
        )
        .route(
            "/api/v1/network/firewall/policies/:mac",
            axum::routing::get(firewall_policy_route)
                .put(axum::routing::put(firewall_put_route).layer(
                    axum::extract::DefaultBodyLimit::max(8192),
                ))
                .delete(axum::routing::delete(firewall_delete_route).layer(
                    axum::extract::DefaultBodyLimit::max(8192),
                )),
        )
}
