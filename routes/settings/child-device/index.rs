// Child-device staff command, crossed only through agathodaimon network child-device.
use serde_json::{json, Value};

pub fn invoke(args: &[String]) -> Result<Value, String> {
    if args.is_empty() {
        return Err("child-device-command-missing".into());
    }
    crate::gate::snake::crossing_path("network/child-device", &json!({"args": args}))
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

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
