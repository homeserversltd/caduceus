use axum::{
    extract::{rejection::JsonRejection, Json},
    http::{HeaderMap, StatusCode},
    Router,
};
use serde_json::{json, Map, Value};
use std::time::Instant;

type ApiError = (StatusCode, Json<crate::gate::ApiErrorBody>);
type ApiResponse = Result<(StatusCode, Json<Value>), ApiError>;

const COMMAND: &str = "transmission vpn settings";
const SCHEMA: &str = "caduceus.transmission.vpn.settings.v1";
const HTTP_PATH: &str = "/api/v1/transmission/vpn/settings";
const CONFIG_PATH: &str = "/etc/appliance/config.json";

fn profile_admits() -> Result<(), ApiError> {
    if crate::routes::profile_routes::ACTIVE_PROFILE != "homeserver" {
        return Err(crate::gate::api_error(COMMAND));
    }
    match crate::shared::policy::allows_command(COMMAND) {
        Ok(true) => Ok(()),
        Ok(false) => Err(crate::gate::api_error(COMMAND)),
        Err(_) => Err(crate::gate::api_error_signal(
            COMMAND,
            "caduceus-carapace-desync",
        )),
    }
}

fn seat() -> Result<&'static Value, ApiError> {
    crate::routes::leaf_schema::declaration(SCHEMA).ok_or_else(|| {
        crate::gate::service_unavailable(COMMAND, "caduceus-schema-desync")
    })
}

fn vpn_fields(seat: &Value) -> Result<&Map<String, Value>, ApiError> {
    seat.pointer("/fields/vpn/properties")
        .and_then(Value::as_object)
        .ok_or_else(|| crate::gate::service_unavailable(COMMAND, "caduceus-schema-desync"))
}

fn rescan_field(seat: &Value) -> Result<&Value, ApiError> {
    seat.pointer("/fields/rescan")
        .ok_or_else(|| crate::gate::service_unavailable(COMMAND, "caduceus-schema-desync"))
}

fn default_value(spec: &Value) -> Value {
    spec.get("default").cloned().unwrap_or(Value::Null)
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn matches_type(spec: &Value, value: &Value) -> bool {
    let actual = value_type(value);
    let declared_type = spec.get("type");
    let type_matches = match declared_type {
        Some(Value::String(expected)) => {
            expected == actual || (expected == "number" && actual == "integer")
        }
        Some(Value::Array(expected)) => expected.iter().any(|entry| {
            entry.as_str().is_some_and(|kind| {
                kind == actual || (kind == "number" && actual == "integer")
            })
        }),
        _ => true,
    };
    type_matches
        && spec
            .get("enum")
            .and_then(Value::as_array)
            .map_or(true, |values| values.iter().any(|allowed| allowed == value))
}

fn parse_patch(
    body: &Value,
    seat: &Value,
) -> Result<(Map<String, Value>, Option<Value>), String> {
    let object = body.as_object().ok_or_else(|| "request".to_string())?;
    let fields = seat
        .pointer("/fields/vpn/properties")
        .and_then(Value::as_object)
        .ok_or_else(|| "schema".to_string())?;
    let mut vpn = Map::new();
    let nested_vpn = object.get("vpn");
    for (name, spec) in fields {
        if let Some(value) = object.get(name) {
            if nested_vpn.is_some_and(|nested| {
                nested.is_null()
                    || nested
                        .as_object()
                        .is_some_and(|nested| nested.contains_key(name))
            }) {
                return Err(name.clone());
            }
            if !matches_type(spec, value) {
                return Err(name.clone());
            }
            vpn.insert(name.clone(), value.clone());
        }
    }
    if let Some(value) = nested_vpn {
        match value {
            Value::Null => {
                for (name, spec) in fields {
                    vpn.insert(name.clone(), default_value(spec));
                }
            }
            Value::Object(nested) => {
                for (name, spec) in fields {
                    if let Some(value) = nested.get(name) {
                        if !matches_type(spec, value) {
                            return Err(name.clone());
                        }
                        vpn.insert(name.clone(), value.clone());
                    }
                }
            }
            _ => return Err("vpn".to_string()),
        }
    }
    let rescan = match object.get("rescan") {
        Some(value) => {
            let spec = seat
                .pointer("/fields/rescan")
                .ok_or_else(|| "schema".to_string())?;
            if !matches_type(spec, value) {
                return Err("rescan".to_string());
            }
            Some(value.clone())
        }
        None => None,
    };
    Ok((vpn, rescan))
}

fn response(document: &Value, seat: &Value, changed: Option<bool>) -> Result<Value, ApiError> {
    let fields = vpn_fields(seat)?;
    let rescan_spec = rescan_field(seat)?;
    let transmission = document.get("transmission").and_then(Value::as_object);
    let mut result = Map::new();
    if let Some(transmission) = transmission {
        for (name, value) in transmission {
            if !matches!(
                name.as_str(),
                "schema"
                    | "ok"
                    | "vpn"
                    | "rescan"
                    | "firstMissingSignal"
                    | "changed"
                    | "appliesOnNextStart"
            ) {
                result.insert(name.clone(), value.clone());
            }
        }
    }
    let mut vpn = transmission
        .and_then(|value| value.get("vpn"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    for (name, spec) in fields {
        vpn.entry(name.clone())
            .or_insert_with(|| default_value(spec));
    }
    let rescan = transmission
        .and_then(|value| value.get("rescan"))
        .cloned()
        .unwrap_or_else(|| default_value(rescan_spec));
    result.insert("schema".to_string(), Value::String(SCHEMA.to_string()));
    result.insert("ok".to_string(), Value::Bool(true));
    result.insert("vpn".to_string(), Value::Object(vpn));
    result.insert("rescan".to_string(), rescan);
    result.insert(
        "firstMissingSignal".to_string(),
        Value::String("none".to_string()),
    );
    if let Some(changed) = changed {
        result.insert("changed".to_string(), Value::Bool(changed));
        result.insert("appliesOnNextStart".to_string(), Value::Bool(true));
    }
    Ok(Value::Object(result))
}

fn record_deed(
    ok: bool,
    signal: &str,
    first_missing_field: Option<&str>,
    started: Instant,
) -> Result<(), String> {
    crate::shared::hyalos::reflect_json(json!({
        "organ": "caduceus",
        "kind": "transmission-vpn-settings",
        "correlation_id": uuid::Uuid::new_v4().to_string(),
        "ok": ok,
        "level": if ok {"info"} else {"warn"},
        "message": "transmission VPN settings",
        "attributes_redacted": {
            "who": "caduceus",
            "verb": "write",
            "target": "transmission.vpn.settings",
            "outcome": if ok {"success"} else {"failure"},
            "duration_ms": started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "signal": signal,
            "first_missing_field": first_missing_field
        }
    }))
    .map(|_| ())
}

fn unavailable(started: Instant, signal: &'static str) -> ApiError {
    let _ = record_deed(false, signal, None, started);
    crate::gate::service_unavailable(COMMAND, signal)
}

fn invalid_request(started: Instant, field: &str) -> ApiError {
    let signal = format!("caduceus-transmission-vpn-settings-invalid-{field}");
    let _ = record_deed(false, &signal, Some(field), started);
    (
        StatusCode::BAD_REQUEST,
        Json(crate::gate::ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: COMMAND.to_string(),
            first_missing_signal: signal,
        }),
    )
}

fn checked_response(document: &Value, seat: &Value, changed: Option<bool>) -> Result<Value, ApiError> {
    let output = response(document, seat, changed)?;
    if !crate::routes::leaf_schema::accepts(SCHEMA, &output) {
        return Err(crate::gate::service_unavailable(
            COMMAND,
            "caduceus-schema-desync",
        ));
    }
    Ok(output)
}

async fn get_route() -> ApiResponse {
    profile_admits()?;
    let seat = seat()?;
    let shown = crate::shared::config::show_json().map_err(|_| {
        crate::gate::service_unavailable(COMMAND, "caduceus-household-config-unavailable")
    })?;
    let document = shown.get("document").cloned().ok_or_else(|| {
        crate::gate::service_unavailable(COMMAND, "caduceus-household-config-invalid")
    })?;
    let output = checked_response(&document, seat, None)?;
    Ok((StatusCode::OK, Json(output)))
}

async fn post_route(headers: HeaderMap, body: Result<Json<Value>, JsonRejection>) -> ApiResponse {
    profile_admits()?;
    let started = Instant::now();
    let mut body = match body {
        Ok(Json(body)) => body,
        Err(_) => return Err(invalid_request(started, "request")),
    };
    crate::gate::access_attendance_admits(&headers, &body, HTTP_PATH)?;
    crate::gate::strip_administrative_flags(&mut body);
    let seat = match seat() {
        Ok(seat) => seat,
        Err(_) => return Err(unavailable(started, "caduceus-schema-desync")),
    };
    if vpn_fields(seat).is_err() || rescan_field(seat).is_err() {
        return Err(unavailable(started, "caduceus-schema-desync"));
    }
    let (vpn_updates, rescan_update) = match parse_patch(&body, seat) {
        Ok(patch) => patch,
        Err(field) => return Err(invalid_request(started, &field)),
    };

    let guard = crate::shared::config::transaction_lock()
        .map_err(|_| unavailable(started, "caduceus-config-lock-poisoned"))?;
    let shown = crate::shared::config::show_json()
        .map_err(|_| unavailable(started, "caduceus-household-config-unavailable"))?;
    let before = shown
        .get("document")
        .cloned()
        .ok_or_else(|| unavailable(started, "caduceus-household-config-invalid"))?;
    let transmission = before.get("transmission").and_then(Value::as_object);
    let existing_transmission_invalid = before
        .get("transmission")
        .is_some_and(|value| !value.is_null() && !value.is_object());
    if existing_transmission_invalid {
        return Err(unavailable(started, "caduceus-household-config-invalid"));
    }
    if !vpn_updates.is_empty()
        && transmission
            .and_then(|value| value.get("vpn"))
            .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        return Err(unavailable(started, "caduceus-household-config-invalid"));
    }

    let fields = vpn_fields(seat)?;
    let mut vpn_changes = Map::new();
    for (name, value) in vpn_updates {
        let spec = fields
            .get(&name)
            .ok_or_else(|| unavailable(started, "caduceus-schema-desync"))?;
        let current = transmission
            .and_then(|value| value.get("vpn"))
            .and_then(Value::as_object)
            .and_then(|value| value.get(&name))
            .cloned()
            .unwrap_or_else(|| default_value(spec));
        if current != value {
            vpn_changes.insert(name, value);
        }
    }
    let rescan_spec = rescan_field(seat)?;
    let rescan_changed = if let Some(value) = rescan_update {
        let current = transmission
            .and_then(|value| value.get("rescan"))
            .cloned()
            .unwrap_or_else(|| default_value(rescan_spec));
        (current != value).then_some(value)
    } else {
        None
    };

    let changed = !vpn_changes.is_empty() || rescan_changed.is_some();
    if !changed {
        drop(guard);
        let output = checked_response(&before, seat, Some(false))?;
        return Ok((StatusCode::OK, Json(output)));
    }

    let mut document = before.clone();
    let root = document
        .as_object_mut()
        .ok_or_else(|| unavailable(started, "caduceus-household-config-invalid"))?;
    let transmission_value = root
        .entry("transmission".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    if transmission_value.is_null() {
        *transmission_value = Value::Object(Map::new());
    }
    let transmission = transmission_value
        .as_object_mut()
        .ok_or_else(|| unavailable(started, "caduceus-household-config-invalid"))?;
    if !vpn_changes.is_empty() {
        let vpn_value = transmission
            .entry("vpn".to_string())
            .or_insert_with(|| Value::Object(Map::new()));
        if vpn_value.is_null() {
            *vpn_value = Value::Object(Map::new());
        }
        let vpn = vpn_value
            .as_object_mut()
            .ok_or_else(|| unavailable(started, "caduceus-household-config-invalid"))?;
        for (name, value) in vpn_changes {
            vpn.insert(name, value);
        }
    }
    if let Some(value) = rescan_changed {
        transmission.insert("rescan".to_string(), value);
    }

    let mut bytes = serde_json::to_vec_pretty(&document)
        .map_err(|_| unavailable(started, "caduceus-household-config-serialize-failed"))?;
    bytes.push(b'\n');
    if let Err(error) = crate::shared::config::atomic_write_owned(
        &crate::shared::config::path(CONFIG_PATH),
        &bytes,
        0o660,
    ) {
        let signal = if error == "caduceus-config-target-symlink" {
            "caduceus-config-target-symlink"
        } else {
            "caduceus-household-config-write-failed"
        };
        return Err(unavailable(started, signal));
    }
    drop(guard);
    if record_deed(true, "none", None, started).is_err() {
        return Err(crate::gate::service_unavailable(
            COMMAND,
            "caduceus-transmission-vpn-settings-log-failed",
        ));
    }
    let output = checked_response(&document, seat, Some(true))?;
    Ok((StatusCode::OK, Json(output)))
}

pub fn register(router: Router) -> Router {
    router.route(
        HTTP_PATH,
        axum::routing::get(get_route).post(post_route),
    )
}
