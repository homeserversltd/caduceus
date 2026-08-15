// DHCP staff command, crossed only through agathodaimon network dhcp.
use serde_json::{json, Value};

pub fn invoke(args: &[String]) -> Result<Value, String> {
    if args.is_empty() {
        return Err("caduceus-network-dhcp-command-missing".into());
    }
    crate::gate::snake::crossing_path("network/dhcp", &json!({"args": args}))
}
pub fn command_json(args: &[String]) -> Result<Value, String> {
    invoke(args)
}
pub fn command(args: &[String]) -> i32 {
    match invoke(args) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}
pub fn status_json() -> Result<Value, String> {
    invoke(&["status".into()])
}
pub fn intent_json(method: &str, route: &str, metadata: Value) -> Result<Value, String> {
    invoke(&[
        "intent".into(),
        method.into(),
        route.into(),
        "--metadata-json".into(),
        serde_json::to_string(&metadata).map_err(|_| "caduceus-network-dhcp-metadata-invalid")?,
    ])
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
