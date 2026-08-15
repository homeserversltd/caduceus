use crate::shared::{harmonia, receipts};
use serde_json::{json, Value};

pub fn read_json() -> Result<Value, String> {
    match harmonia::route("sync_now") {
        Ok(_) => Ok(json!({
            "schema": "caduceus.sync.status.v1",
            "routePresent": true,
            "firstMissingSignal": "none",
            "ok": true
        })),
        Err(err) => Ok(json!({
            "schema": "caduceus.sync.status.v1",
            "routePresent": false,
            "firstMissingSignal": err,
            "ok": false
        })),
    }
}

pub fn invoke_now_json(rest: &[String]) -> Value {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("sync_now", &flags, dry_run);
    if !dry_run {
        let _ = receipts::write_latest(&body);
    }
    harmonia::invoke_body_to_json("sync_now", code, &body)
}

pub fn status() -> i32 {
    match read_json() {
        Ok(value) => {
            println!("schema=caduceus.sync.status.v1");
            println!("route_present={}", value["routePresent"]);
            println!("first_missing_signal={}", value["firstMissingSignal"]);
            if value["ok"].as_bool() == Some(true) {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("caduceus-sync-status-failed: {err}");
            1
        }
    }
}

pub fn now(rest: &[String]) -> i32 {
    let value = invoke_now_json(rest);
    if let Some(body) = value.get("body").and_then(Value::as_str) {
        print!("{body}");
    } else {
        println!(
            "schema={}",
            value.get("schema").and_then(Value::as_str).unwrap_or("")
        );
        if let Some(route) = value.get("route").and_then(Value::as_str) {
            println!("route={route}");
        }
        if let Some(ok) = value.get("ok") {
            println!("ok={ok}");
        }
        if let Some(signal) = value.get("firstMissingSignal").and_then(Value::as_str) {
            println!("first_missing_signal={signal}");
        }
    }
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        0
    } else {
        1
    }
}

async fn gui_update() -> Result<(axum::http::StatusCode, axum::Json<serde_json::Value>), (axum::http::StatusCode, axum::Json<crate::gate::ApiErrorBody>)> { crate::gate::gated_mutation("gui update now", || { let mut v=crate::routes::open_settings_pane::invoke_update_now_json(&[]); v["action"]=serde_json::json!("gui_update_now"); v }).await }

/// Canonical registration seam for this leaf.
// HOIST: obliterate after counterparty realignment
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/update/now",
            axum::routing::post(crate::routes::update_support::update_now_route),
        )
        .route(
            "/api/v1/harmonia/update",
            axum::routing::post(crate::routes::update_support::harmonia_update_route),
        )
        .route("/api/v1/gui/update/now", axum::routing::post(gui_update))
        .route(
            "/api/v1/sync/now",
            axum::routing::post(crate::routes::update_support::sync_now_route),
        )
}
