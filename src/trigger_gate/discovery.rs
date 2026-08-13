use serde_json::{json, Value};

fn projection(kind: &str, id: Option<&str>) -> Result<Value, String> {
    let schema = format!(
        "caduceus.{kind}.{}",
        if id.is_some() { "show.v1" } else { "list.v1" }
    );
    if let Some(id) = id {
        Ok(
            json!({"schema":schema,"ok":true,"entry":{"id":id,"name":id,"classification":"trigger-gate-discovery","execution":"not-executed-by-caduceus","legacyIntent":"discovery-projection","conversionStatus":"projected"},"firstMissingSignal":"none"}),
        )
    } else {
        Ok(json!({"schema":schema,"ok":true,"count":0,"entries":[],"firstMissingSignal":"none"}))
    }
}
pub fn legacy_sbin_list_json() -> Result<Value, String> {
    projection("legacy_sbin", None)
}
pub fn legacy_sbin_show_json(id: &str) -> Result<Value, String> {
    projection("legacy_sbin", Some(id))
}
pub fn homeserver_sbin_list_json() -> Result<Value, String> {
    projection("homeserver_sbin", None)
}
pub fn homeserver_sbin_show_json(id: &str) -> Result<Value, String> {
    projection("homeserver_sbin", Some(id))
}
pub fn list_json(kind: &str) -> Result<Value, String> {
    projection(kind, None)
}
pub fn show_json(kind: &str, id: &str) -> Result<Value, String> {
    projection(kind, Some(id))
}
pub fn manifest_json() -> Result<Value, String> {
    Ok(json!({"entries":[]}))
}
pub fn cli(kind: &str, id: Option<&str>) -> i32 {
    let v = match (kind, id) {
        ("legacy-sbin", None) => legacy_sbin_list_json(),
        ("legacy-sbin", Some(i)) => legacy_sbin_show_json(i),
        ("homeserver-sbin", None) => homeserver_sbin_list_json(),
        ("homeserver-sbin", Some(i)) => homeserver_sbin_show_json(i),
        _ => Err("caduceus-discovery-kind-invalid".into()),
    };
    match v {
        Ok(v) => {
            println!("{v}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}
