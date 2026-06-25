use crate::tools::{config, harmonia};
use serde_json::{json, Value};

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

fn ledger_path() -> Result<String, String> {
    let profile = harmonia::load_profile_value()?;
    profile
        .get("services")
        .and_then(|services| services.get("ledger"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| "caduceus-ledger-path-missing".to_string())
}

pub fn read_ledger_json(page: usize, per_page: usize) -> Result<Value, String> {
    let path = ledger_path()?;
    let text = config::read_file_at(&path).unwrap_or_default();
    let page = page.max(1);
    let per_page = per_page.clamp(1, 25);
    let mut entries = Vec::new();
    for (idx, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<Value>(trimmed) {
            entries.push(json!({
                "ordinal": idx + 1,
                "entry": entry
            }));
        }
    }
    entries.reverse();
    let total_entries = entries.len();
    let total_pages = total_entries.div_ceil(per_page).max(1);
    let bounded_page = page.min(total_pages);
    let start = (bounded_page - 1) * per_page;
    let page_entries: Vec<Value> = entries.into_iter().skip(start).take(per_page).collect();
    Ok(json!({
        "schema": "caduceus.receipts.ledger.v1",
        "ledgerPath": path,
        "page": bounded_page,
        "perPage": per_page,
        "totalEntries": total_entries,
        "totalPages": total_pages,
        "entries": page_entries,
        "ok": true,
        "firstMissingSignal": if total_entries == 0 { "caduceus-ledger-empty" } else { "none" }
    }))
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
