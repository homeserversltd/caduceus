use serde_json::{json, Value};

const MANIFEST: &str = include_str!("../../data/homeserver-sbin/manifest.json");

pub fn manifest_json() -> Result<Value, String> {
    serde_json::from_str(MANIFEST)
        .map_err(|err| format!("caduceus-homeserver-sbin-manifest-invalid: {err}"))
}

pub fn list_json() -> Result<Value, String> {
    let manifest = manifest_json()?;
    let entries = manifest
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "caduceus-homeserver-sbin-entries-missing".to_string())?;
    let summarized: Vec<Value> = entries
        .iter()
        .map(|entry| {
            json!({
                "id": entry.get("id").cloned().unwrap_or(Value::Null),
                "name": entry.get("name").cloned().unwrap_or(Value::Null),
                "language": entry.get("language").cloned().unwrap_or(Value::Null),
                "sourcePath": entry.get("sourcePath").cloned().unwrap_or(Value::Null),
                "classification": entry.get("classification").cloned().unwrap_or(Value::Null),
                "execution": entry.get("execution").cloned().unwrap_or(Value::Null),
                "legacyIntent": entry.get("legacyIntent").cloned().unwrap_or(Value::Null),
                "riskClass": entry.get("riskClass").cloned().unwrap_or(Value::Null),
                "targetProfile": entry.get("targetProfile").cloned().unwrap_or(Value::Null),
                "replacementBand": entry.get("replacementBand").cloned().unwrap_or(Value::Null),
                "conversionStatus": entry.get("conversionStatus").cloned().unwrap_or(Value::Null),
                "sudoGrantFiles": entry.get("sudoGrantFiles").cloned().unwrap_or(Value::Null)
            })
        })
        .collect();
    Ok(json!({
        "schema": "caduceus.homeserver_sbin.list.v1",
        "ok": true,
        "count": summarized.len(),
        "entries": summarized,
        "firstMissingSignal": "none"
    }))
}

pub fn show_json(script_id: &str) -> Result<Value, String> {
    let manifest = manifest_json()?;
    let entries = manifest
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| "caduceus-homeserver-sbin-entries-missing".to_string())?;
    entries
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(script_id))
        .cloned()
        .map(|entry| {
            json!({
                "schema": "caduceus.homeserver_sbin.show.v1",
                "ok": true,
                "entry": entry,
                "firstMissingSignal": "none"
            })
        })
        .ok_or_else(|| "caduceus-homeserver-sbin-script-missing".to_string())
}

pub fn list() -> i32 {
    match list_json() {
        Ok(value) => {
            println!("schema=caduceus.homeserver_sbin.list.v1");
            println!("count={}", value["count"]);
            if let Some(entries) = value.get("entries").and_then(Value::as_array) {
                for entry in entries {
                    let sudo = entry
                        .get("sudoGrantFiles")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    println!(
                        "script={} language={} execution={} intent={} risk={} target={} band={} status={} sudo={} name={}",
                        entry.get("id").and_then(Value::as_str).unwrap_or(""),
                        entry.get("language").and_then(Value::as_str).unwrap_or(""),
                        entry.get("execution").and_then(Value::as_str).unwrap_or(""),
                        entry.get("legacyIntent").and_then(Value::as_str).unwrap_or(""),
                        entry.get("riskClass").and_then(Value::as_str).unwrap_or(""),
                        entry.get("targetProfile").and_then(Value::as_str).unwrap_or(""),
                        entry.get("replacementBand").and_then(Value::as_str).unwrap_or(""),
                        entry.get("conversionStatus").and_then(Value::as_str).unwrap_or(""),
                        sudo,
                        entry.get("name").and_then(Value::as_str).unwrap_or("")
                    );
                }
            }
            0
        }
        Err(err) => {
            eprintln!("caduceus-homeserver-sbin-list-failed: {err}");
            1
        }
    }
}

pub fn show(script_id: &str) -> i32 {
    match show_json(script_id) {
        Ok(value) => {
            let entry = &value["entry"];
            println!("schema=caduceus.homeserver_sbin.show.v1");
            println!(
                "id={}",
                entry.get("id").and_then(Value::as_str).unwrap_or("")
            );
            println!(
                "name={}",
                entry.get("name").and_then(Value::as_str).unwrap_or("")
            );
            println!(
                "language={}",
                entry.get("language").and_then(Value::as_str).unwrap_or("")
            );
            println!("execution=not-executed-by-caduceus");
            println!("--- body ---");
            print!(
                "{}",
                entry.get("body").and_then(Value::as_str).unwrap_or("")
            );
            0
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}
