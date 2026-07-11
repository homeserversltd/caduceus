use crate::tools::hyalos;
use serde_json::json;

pub fn write_latest(body: &str) -> Result<(), String> {
    hyalos::reflect_json(json!({
        "organ": "caduceus",
        "kind": "receipt",
        "ok": true,
        "message": body,
        "attributes_redacted": {"source": "receipts::write_latest"}
    }))
    .map(|_| ())
}
