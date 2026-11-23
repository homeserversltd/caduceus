use crate::shared::config;
use axum::extract::rejection::JsonRejection;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Instant;

const SCHEMA: &str = "caduceus.portals.v2";
const HOMESERVER_PORTALS: &str = "tabs.portals.data.portals";
const FACTORY_UNREADABLE: &str = "caduceus-portals-factory-unreadable";
const FACTORY_INVALID: &str = "caduceus-portals-factory-invalid";

fn homeserver_profile() -> bool {
    crate::routes::profile_routes::ACTIVE_PROFILE == "homeserver"
}

fn name_slug(name: &str) -> String {
    let mut slug = String::new();
    let mut separator = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_alphanumeric() {
            slug.push(ch);
            separator = false;
        } else if !separator {
            slug.push('-');
            separator = true;
        }
    }
    slug
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty() && name_slug(slug) == slug
}

fn valid_url(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 2048
        || value
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control() || ch == '\\')
    {
        return false;
    }
    if value.starts_with('/') {
        return !value.starts_with("//");
    }
    url::Url::parse(value).is_ok_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
    })
}

fn entry(value: &Value) -> Result<Value, String> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or("caduceus-portals-entry-invalid")?;
    let seat =
        crate::routes::leaf_schema::declaration(SCHEMA).ok_or("caduceus-portals-schema-desync")?;
    let required = seat["forms"]["entry"]["required"]
        .as_array()
        .ok_or("caduceus-portals-schema-desync")?;
    if required
        .iter()
        .any(|field| !field.as_str().is_some_and(|key| object.contains_key(key)))
    {
        return Err("caduceus-portals-entry-kernel-missing".into());
    }
    if !object
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|name| !name.trim().is_empty())
    {
        return Err("caduceus-portals-name-invalid".into());
    }
    for field in ["description", "services", "type", "localURL"] {
        let default = seat["forms"]["entry"]["fields"][field]
            .get("default")
            .ok_or("caduceus-portals-schema-desync")?;
        object.entry(field).or_insert_with(|| default.clone());
    }
    if !object["description"].is_string() || !object["type"].is_string() {
        return Err("caduceus-portals-entry-invalid".into());
    }
    if !object["services"]
        .as_array()
        .is_some_and(|services| services.iter().all(Value::is_string))
    {
        return Err("caduceus-portals-services-invalid".into());
    }
    if !object["localURL"]
        .as_str()
        .is_some_and(|url| url.is_empty() || valid_url(url))
    {
        return Err("caduceus-portals-url-invalid".into());
    }
    if object.get("port").is_some_and(|port| {
        !port.is_null() && !port.as_u64().is_some_and(|port| port <= u16::MAX as u64)
    }) {
        return Err("caduceus-portals-port-invalid".into());
    }
    if object.get("remoteURL").is_some_and(|url| {
        !url.is_null() && !url.as_str().is_some_and(|url| url.is_empty() || valid_url(url))
    }) {
        return Err("caduceus-portals-url-invalid".into());
    }
    // Coronatio derives these for the face; they never become configuration.
    object.remove("status");
    object.remove("visible");
    object.remove("native");
    Ok(Value::Object(object))
}

fn legacy_entry(value: &Value) -> Result<Value, String> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or("caduceus-portals-entry-invalid")?;
    let name = object.remove("title").ok_or("caduceus-portals-name-invalid")?;
    let local_url = object.remove("url").ok_or("caduceus-portals-url-invalid")?;
    for field in ["slug", "kind", "health"] {
        object.remove(field);
    }
    object.insert("name".into(), name);
    object.insert("localURL".into(), local_url);
    object.insert("type".into(), json!("link"));
    entry(&Value::Object(object))
}

fn registry(block: Option<&Value>) -> Result<Value, String> {
    let mut object = match block {
        None | Some(Value::Null) => {
            let seat = crate::routes::leaf_schema::declaration(SCHEMA)
                .ok_or("caduceus-portals-schema-desync")?;
            let factory = seat["storage"].get("factory_entry")
                .ok_or("caduceus-portals-schema-desync")?;
            json!({"entries":[factory]}).as_object().unwrap().clone()
        }
        Some(value) => value.as_object().cloned()
            .ok_or("caduceus-portals-registry-invalid")?,
    };
    let legacy = !object.contains_key("entries") && object.contains_key("tiles");
    if object.get("schema").is_some_and(|schema| {
        !schema.is_null()
            && schema.as_str() != Some(SCHEMA)
            && !(legacy && schema.as_str() == Some("caduceus.portals.v1"))
    }) {
        return Err("caduceus-portals-schema-desync".into());
    }
    let raw = object.get(if legacy { "tiles" } else { "entries" })
        .and_then(Value::as_array)
        .ok_or("caduceus-portals-registry-invalid")?;
    let mut slugs = BTreeSet::new();
    let mut entries = Vec::with_capacity(raw.len());
    for value in raw {
        let checked = if legacy { legacy_entry(value)? } else { entry(value)? };
        let slug = name_slug(checked["name"].as_str().unwrap());
        if !slugs.insert(slug) {
            return Err("caduceus-portals-slug-duplicate".into());
        }
        entries.push(checked);
    }
    object.remove("tiles");
    if object.contains_key("schema") {
        object.insert("schema".into(), json!(SCHEMA));
    }
    object.insert("entries".into(), json!(entries));
    Ok(Value::Object(object))
}

fn slugs(block: Option<&Value>) -> Result<BTreeSet<String>, String> {
    let value = registry(block)?;
    Ok(value["entries"].as_array().unwrap().iter()
        .map(|entry| name_slug(entry["name"].as_str().unwrap()))
        .collect())
}

fn native_slugs() -> Result<BTreeSet<String>, String> {
    let birth = std::fs::read(crate::shared::config::path("/etc/appliance/config.factory"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    slugs(birth.as_ref().and_then(|value| value.get("portals")))
        .or_else(|_| slugs(None))
}

fn homeserver_native_slugs() -> Result<BTreeSet<String>, String> {
    let bytes = std::fs::read(config::path("/etc/appliance/config.factory"))
        .map_err(|_| FACTORY_UNREADABLE)?;
    let birth: Value = serde_json::from_slice(&bytes).map_err(|_| FACTORY_INVALID)?;
    let entries = HOMESERVER_PORTALS
        .split('.')
        .try_fold(&birth, |value, key| value.get(key))
        .and_then(Value::as_array)
        .ok_or(FACTORY_INVALID)?;
    entries
        .iter()
        .map(|entry| {
            entry
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.trim().is_empty())
                .map(name_slug)
                .ok_or_else(|| FACTORY_INVALID.to_owned())
        })
        .collect()
}

pub(crate) fn guard_native_portals(before: &Value, after: &Value) -> Result<(), String> {
    // Mounting this leaf on HomeServer must not enable the legacy config guard.
    if !homeserver_profile() && before.get("portals") != after.get("portals") {
        let remaining = slugs(after.get("portals"))?;
        if !native_slugs()?.is_subset(&remaining) {
            return Err("caduceus-portals-native-entry".into());
        }
    }
    Ok(())
}

fn projection(block: Option<&Value>, changed: Option<bool>) -> Result<Value, String> {
    let mut value = registry(block)?;
    let native = native_slugs()?;
    for entry in value["entries"].as_array_mut().unwrap() {
        let slug = name_slug(entry["name"].as_str().unwrap());
        entry["native"] = json!(native.contains(&slug));
    }
    value["schema"] = json!(SCHEMA);
    value["ok"] = json!(true);
    if let Some(changed) = changed {
        value["changed"] = json!(changed);
    } else {
        value.as_object_mut().unwrap().remove("changed");
    }
    if !crate::routes::leaf_schema::accepts(SCHEMA, &value) {
        return Err("caduceus-portals-schema-desync".into());
    }
    Ok(value)
}

pub(crate) fn read() -> Result<Value, String> {
    // The services census uses this legacy fallback when there is no tabs array.
    match config::get_json("portals") {
        Ok(value) => projection(value.get("value"), None),
        Err(signal) if signal == "caduceus-household-config-key-missing" => projection(None, None),
        Err(signal) => Err(signal),
    }
}

fn homeserver_projection(entries: Vec<Value>, changed: Option<bool>) -> Result<Value, String> {
    let mut reply = json!({"schema": SCHEMA, "ok": true, "entries": entries});
    if let Some(changed) = changed {
        reply["changed"] = Value::Bool(changed);
    }
    if !crate::routes::leaf_schema::accepts(SCHEMA, &reply) {
        return Err("caduceus-portals-schema-desync".into());
    }
    Ok(reply)
}

fn read_door() -> Result<Value, String> {
    if !homeserver_profile() {
        return read();
    }
    let entries = match config::get_json(HOMESERVER_PORTALS) {
        Ok(mut value) => match value["value"].take() {
            Value::Array(entries) => entries,
            _ => return Err("caduceus-portals-registry-invalid".into()),
        },
        Err(signal) if signal == "caduceus-household-config-key-missing" => Vec::new(),
        Err(signal) => return Err(signal),
    };
    homeserver_projection(entries, None)
}

fn upsert_homeserver(slug: &str, body: &Value, offered: Value) -> Result<Value, String> {
    // Check the response seat before touching the configuration.
    let mut reply = homeserver_projection(Vec::new(), Some(false))?;
    let (entries, changed) = config::update_array_entry_json(HOMESERVER_PORTALS, |entries| {
        let mut matches = entries.iter().enumerate().filter(|(_, value)| {
            value["name"].as_str().is_some_and(|name| name_slug(name) == slug)
        });
        let Some((index, existing)) = matches.next() else {
            return Ok((entries.len(), offered));
        };
        if matches.next().is_some() {
            return Err("caduceus-portals-slug-duplicate".into());
        }
        let mut merged = existing.as_object().unwrap().clone();
        // Defaults apply on append, not to omitted fields of a stored entry.
        merged.extend(
            offered
                .as_object()
                .unwrap()
                .iter()
                .filter(|(key, _)| body.get(*key).is_some())
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        Ok((index, Value::Object(merged)))
    })?;
    reply["entries"] = Value::Array(entries);
    reply["changed"] = Value::Bool(changed);
    Ok(reply)
}

fn upsert(slug: &str, body: Value) -> Result<Value, String> {
    // The central administrative gate removes its PIN, not additive entry fields.
    let offered = entry(&body)?;
    if name_slug(offered["name"].as_str().unwrap()) != slug {
        return Err("caduceus-portals-slug-mismatch".into());
    }
    if homeserver_profile() {
        return upsert_homeserver(slug, &body, offered);
    }
    let (block, changed) = config::update_block_json("portals", |current| {
        let mut block = registry(current)?;
        let entries = block["entries"].as_array_mut().unwrap();
        if let Some(existing) = entries
            .iter_mut()
            .find(|value| name_slug(value["name"].as_str().unwrap()) == slug)
        {
            let mut merged = existing.as_object().unwrap().clone();
            // A missing optional PortalEntry value is absent, not the old value.
            for field in ["port", "remoteURL"] {
                if !offered.as_object().unwrap().contains_key(field) {
                    merged.remove(field);
                }
            }
            merged.extend(offered.as_object().unwrap().clone());
            *existing = entry(&Value::Object(merged))?;
        } else {
            entries.push(offered);
        }
        projection(Some(&block), Some(true))?;
        Ok(Some(block))
    })?;
    projection(block.as_ref(), Some(changed))
}

fn remove_homeserver(slug: &str) -> Result<Value, String> {
    if homeserver_native_slugs()?.contains(slug) {
        return Err("caduceus-portals-native-entry".into());
    }
    let mut reply = homeserver_projection(Vec::new(), Some(false))?;
    let (entries, changed) = config::remove_array_entry_json(HOMESERVER_PORTALS, |entries| {
        let mut matches = entries.iter().enumerate().filter(|(_, entry)| {
            entry["name"].as_str().is_some_and(|name| name_slug(name) == slug)
        });
        let index = matches.next().map(|(index, _)| index);
        if matches.next().is_some() {
            return Err("caduceus-portals-slug-duplicate".into());
        }
        Ok(index)
    })?;
    reply["entries"] = Value::Array(entries);
    reply["changed"] = Value::Bool(changed);
    Ok(reply)
}

fn remove(slug: &str) -> Result<Value, String> {
    if !valid_slug(slug) {
        return Err("caduceus-portals-slug-invalid".into());
    }
    if homeserver_profile() {
        return remove_homeserver(slug);
    }
    if native_slugs()?.contains(slug) {
        return Err("caduceus-portals-native-entry".into());
    }
    let (block, changed) = config::update_block_json("portals", |current| {
        let mut block = registry(current)?;
        let entries = block["entries"].as_array_mut().unwrap();
        if !entries.iter().any(|value| name_slug(value["name"].as_str().unwrap()) == slug) {
            return Ok(current.cloned());
        }
        entries.retain(|value| name_slug(value["name"].as_str().unwrap()) != slug);
        projection(Some(&block), Some(true))?;
        Ok(Some(block))
    })?;
    projection(block.as_ref(), Some(changed))
}

fn response(result: Result<Value, String>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(signal) => {
            let status = if signal.contains("schema-desync")
                || signal.contains("household-config")
                || matches!(signal.as_str(), FACTORY_UNREADABLE | FACTORY_INVALID)
            {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            };
            let (noun, verb) = crate::shared::load_trace::refusal_stop("portals");
            (
                status,
                Json(json!({
                    "schema": "caduceus.staff.receipt.v1",
                    "ok": false,
                    "stop": {"noun": noun, "verb": verb},
                    "observed": {"command": "portals"},
                    "could_change_to": null,
                    "attempt": null,
                    "final_receipt": {"ok": false, "firstMissingSignal": signal},
                    "firstMissingSignal": signal,
                    "command": "portals",
                })),
            )
                .into_response()
        }
    }
}

fn deed(verb: &'static str, started: Instant, result: Result<Value, String>) -> Response {
    let signal = result.as_ref().err().map(String::as_str).unwrap_or("none");
    let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({
        "organ":"portals", "kind":verb, "ok":result.is_ok(),
        "level":if result.is_ok() { "info" } else { "error" },
        "message":"portal entry mutation",
        "attributes_redacted":{
            "who":"owner", "verb":verb, "target":"portals",
            "outcome":if result.is_ok() { "success" } else { "refused" },
            "duration_ms":started.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "signal":signal
        }
    }));
    response(result)
}

async fn get() -> Response {
    match crate::gate::blocking_task("portals read", read_door).await {
        Ok(result) => response(result),
        Err(error) => error.into_response(),
    }
}

async fn put(Path(slug): Path<String>, body: Result<Json<Value>, JsonRejection>) -> Response {
    let started = Instant::now();
    let body = match body {
        Ok(Json(body)) => body,
        Err(_) => return deed("put", started, Err("caduceus-portals-json-invalid".into())),
    };
    match crate::gate::blocking_task("portals put", move || upsert(&slug, body)).await {
        Ok(result) => deed("put", started, result),
        Err(error) => error.into_response(),
    }
}

async fn delete(Path(slug): Path<String>) -> Response {
    let started = Instant::now();
    match crate::gate::blocking_task("portals delete", move || remove(&slug)).await {
        Ok(result) => deed("delete", started, result),
        Err(error) => error.into_response(),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router
        .route("/api/v1/portals", axum::routing::get(get))
        .route(
            "/api/v1/portals/:slug",
            axum::routing::put(put).delete(delete),
        )
}
