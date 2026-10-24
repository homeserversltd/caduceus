use crate::shared::config;
use axum::extract::rejection::JsonRejection;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::time::Instant;

const SCHEMA: &str = "caduceus.portals.v1";

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && slug.as_bytes()[0].is_ascii_alphanumeric()
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

fn tile(value: &Value) -> Result<Value, String> {
    let mut object = value
        .as_object()
        .cloned()
        .ok_or("caduceus-portals-tile-invalid")?;
    let seat =
        crate::routes::leaf_schema::declaration(SCHEMA).ok_or("caduceus-portals-schema-desync")?;
    let required = seat["forms"]["tile"]["required"]
        .as_array()
        .ok_or("caduceus-portals-schema-desync")?;
    if required
        .iter()
        .any(|field| !field.as_str().is_some_and(|key| object.contains_key(key)))
    {
        return Err("caduceus-portals-tile-kernel-missing".into());
    }
    if !object
        .get("slug")
        .and_then(Value::as_str)
        .is_some_and(valid_slug)
    {
        return Err("caduceus-portals-slug-invalid".into());
    }
    if !object
        .get("title")
        .and_then(Value::as_str)
        .is_some_and(|title| {
            !title.trim().is_empty()
                && title.chars().count() <= 128
                && !title.chars().any(char::is_control)
        })
    {
        return Err("caduceus-portals-title-invalid".into());
    }
    if !matches!(
        object.get("kind").and_then(Value::as_str),
        Some("link" | "subsite" | "hybrid")
    ) {
        return Err("caduceus-portals-kind-invalid".into());
    }
    if !object
        .get("url")
        .and_then(Value::as_str)
        .is_some_and(valid_url)
    {
        return Err("caduceus-portals-url-invalid".into());
    }
    let port = object.entry("port").or_insert(Value::Null);
    if !port.is_null()
        && !port
            .as_u64()
            .is_some_and(|port| (1..=65535).contains(&port))
    {
        return Err("caduceus-portals-port-invalid".into());
    }
    let health = object.entry("health").or_insert(Value::Null);
    if !health.is_null() && !health.as_str().is_some_and(valid_url) {
        return Err("caduceus-portals-health-invalid".into());
    }
    Ok(Value::Object(object))
}

fn registry(block: Option<&Value>) -> Result<Value, String> {
    let block = match block {
        None | Some(Value::Null) => json!({"tiles":[{
            "slug":"manual", "title":"Manual", "kind":"subsite", "url":"/manual/",
            "port":null, "health":null
        }]}),
        Some(value) => value.clone(),
    };
    if block
        .get("schema")
        .is_some_and(|schema| schema.as_str() != Some(SCHEMA))
    {
        return Err("caduceus-portals-schema-desync".into());
    }
    let tiles = block
        .get("tiles")
        .and_then(Value::as_array)
        .ok_or("caduceus-portals-registry-invalid")?;
    let mut slugs = BTreeSet::new();
    for raw in tiles {
        let checked = tile(raw)?;
        if !slugs.insert(checked["slug"].as_str().unwrap().to_owned()) {
            return Err("caduceus-portals-slug-duplicate".into());
        }
    }
    Ok(block)
}

fn projection(block: Option<&Value>, changed: Option<bool>) -> Result<Value, String> {
    let mut value = registry(block)?;
    let tiles = value["tiles"]
        .as_array()
        .unwrap()
        .iter()
        .map(tile)
        .collect::<Result<Vec<_>, _>>()?;
    value["tiles"] = json!(tiles);
    value["schema"] = json!(SCHEMA);
    value["ok"] = json!(true);
    if let Some(changed) = changed {
        value["changed"] = json!(changed);
    }
    if !crate::routes::leaf_schema::accepts(SCHEMA, &value) {
        return Err("caduceus-portals-schema-desync".into());
    }
    Ok(value)
}

fn read() -> Result<Value, String> {
    match config::get_json("portals") {
        Ok(value) => projection(value.get("value"), None),
        Err(signal) if signal == "caduceus-household-config-key-missing" => projection(None, None),
        Err(signal) => Err(signal),
    }
}

fn upsert(slug: &str, mut body: Value) -> Result<Value, String> {
    if !valid_slug(slug) {
        return Err("caduceus-portals-slug-invalid".into());
    }
    let object = body
        .as_object_mut()
        .ok_or("caduceus-portals-tile-invalid")?;
    // Administrative envelope fields never enter the tile declaration.
    object.remove("flags");
    if object
        .get("slug")
        .is_some_and(|value| value.as_str() != Some(slug))
    {
        return Err("caduceus-portals-slug-mismatch".into());
    }
    object.insert("slug".into(), json!(slug));
    // Validate the entire offered tile before acquiring the write boundary.
    let offered = tile(&body)?;
    let (block, changed) = config::update_block_json("portals", |current| {
        let mut block = registry(current)?;
        let tiles = block["tiles"].as_array_mut().unwrap();
        if let Some(existing) = tiles
            .iter_mut()
            .find(|tile| tile["slug"].as_str() == Some(slug))
        {
            let mut merged = existing.as_object().unwrap().clone();
            merged.extend(offered.as_object().unwrap().clone());
            *existing = tile(&Value::Object(merged))?;
        } else {
            tiles.push(offered);
        }
        // Validate and project before durable bytes can change.
        projection(Some(&block), Some(true))?;
        Ok(Some(block))
    })?;
    projection(block.as_ref(), Some(changed))
}

fn remove(slug: &str) -> Result<Value, String> {
    if !valid_slug(slug) {
        return Err("caduceus-portals-slug-invalid".into());
    }
    let (block, changed) = config::update_block_json("portals", |current| {
        let mut block = registry(current)?;
        let tiles = block["tiles"].as_array_mut().unwrap();
        if !tiles.iter().any(|tile| tile["slug"].as_str() == Some(slug)) {
            return Ok(current.cloned());
        }
        tiles.retain(|tile| tile["slug"].as_str() != Some(slug));
        projection(Some(&block), Some(true))?;
        Ok(Some(block))
    })?;
    projection(block.as_ref(), Some(changed))
}

fn response(result: Result<Value, String>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(signal) => {
            let status = if signal.contains("schema-desync") || signal.contains("household-config")
            {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::UNPROCESSABLE_ENTITY
            };
            (
                status,
                Json(json!({"schema":"caduceus.api.error.v1", "ok":false,
                "command":"portals", "firstMissingSignal":signal})),
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
        "message":"portal tile mutation",
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
    match crate::gate::blocking_task("portals read", read).await {
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
