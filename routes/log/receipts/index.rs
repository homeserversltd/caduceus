use crate::routes::leaf_schema;
use crate::shared::config;
use serde_json::{json, Value};
use std::io::Read;
use std::process::{Command, Stdio};

pub fn read_latest_json() -> Result<Value, String> {
    match config::read_public_file("var/lib/caduceus/receipts/latest/run.txt") {
        Ok(text) => Ok(json!({
            "schema": "caduceus.receipts.latest.v1",
            "ok": true,
            "body": text,
            "firstMissingSignal": "none"
        })),
        Err(_) => Ok(json!({
            "schema": "caduceus.receipts.latest.v1",
            "ok": false,
            "firstMissingSignal": "caduceus-receipt-missing"
        })),
    }
}

pub fn read_ledger_json(
    page: usize,
    per_page: usize,
    module: Option<&str>,
) -> Result<Value, String> {
    const UNREADABLE: &str = "caduceus-harmonia-ledger-unreadable";
    const MAX_PAGE_BYTES: u64 = 4 * 1024 * 1024;
    const PAGE_SEAT: &str = "caduceus.receipts.ledger.v1";
    // An unseated page stays on the primitive identity/presence path. A loaded
    // declaration is authoritative, but its absence is not a command failure.
    let seat = leaf_schema::declaration(PAGE_SEAT);
    if seat.is_some_and(|seat| seat.get("schema").and_then(Value::as_str) != Some(PAGE_SEAT)) {
        return Err(UNREADABLE.to_string());
    }
    let mut command = Command::new("harmonia");
    command.args([
        "ledger",
        "--json",
        "--page",
        &page.max(1).to_string(),
        "--per-page",
        &per_page.clamp(1, 25).to_string(),
    ]);
    if let Some(module) = module {
        command.args(["--module", module]);
    }
    // This is a query, not a press: no sudo, transient service, transcript or log.
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| UNREADABLE.to_string())?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .unwrap()
        .take(MAX_PAGE_BYTES + 1)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() as u64 > MAX_PAGE_BYTES {
        let _ = child.kill();
        let _ = child.wait();
        return Err(UNREADABLE.to_string());
    }
    if !child.wait().map_err(|_| UNREADABLE.to_string())?.success() {
        return Err(UNREADABLE.to_string());
    }
    let mut page: Value = serde_json::from_slice(&bytes).map_err(|_| UNREADABLE.to_string())?;
    if page.get("schema").and_then(Value::as_str) != Some(PAGE_SEAT)
        || !page.is_object()
        || page.get("ok").and_then(Value::as_bool) == Some(false)
    {
        return Err(UNREADABLE.to_string());
    }
    // Preserve the producer's page and every additive field, not a private shape.
    page["ledgerPath"] = Value::Null;
    if seat.is_some() && !leaf_schema::accepts(PAGE_SEAT, &page) {
        return Err(UNREADABLE.to_string());
    }
    Ok(page)
}

pub fn latest() -> i32 {
    match read_latest_json() {
        Ok(value) => {
            println!("schema=caduceus.receipts.latest.v1");
            if value["ok"].as_bool() == Some(true) {
                if let Some(body) = value["body"].as_str() {
                    print!("{body}");
                }
                0
            } else {
                println!("ok=false");
                println!("first_missing_signal=caduceus-receipt-missing");
                1
            }
        }
        Err(err) => {
            eprintln!("caduceus-receipts-latest-failed: {err}");
            1
        }
    }
}

/// Canonical registration seam for this leaf.
async fn latest_http() -> Result<
    axum::Json<Value>,
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    crate::gate::gated_json("receipts latest", read_latest_json).await
}

async fn receipts_http(
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<
    axum::Json<Value>,
    (
        axum::http::StatusCode,
        axum::Json<crate::gate::ApiErrorBody>,
    ),
> {
    if query.contains_key("page")
        || query.contains_key("per_page")
        || query.contains_key("perPage")
        || query.contains_key("module")
    {
        crate::routes::update_support::receipts_ledger_route(axum::extract::Query(query)).await
    } else {
        latest_http().await
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    let router = router.route("/api/v1/log/receipts", axum::routing::get(receipts_http));
    router
}
