// DHCP staff command, crossed through its stops network/dhcp/*.
use serde_json::{json, Map, Value};

const ROUTE_INVALID: &str = "caduceus-dhcp-route-invalid";
const REQUEST_INVALID: &str = "caduceus-dhcp-request-invalid";

fn cross(stop: &str, input: Map<String, Value>) -> Result<Value, Value> {
    match crate::gate::snake::crossing_path_receipt(&format!("network/dhcp/{stop}"), &Value::Object(input)) {
        Ok(receipt) if receipt.get("ok").and_then(Value::as_bool) == Some(true) => Ok(receipt),
        Ok(receipt) => Err(receipt),
        Err(error) => Err(Value::String(error)),
    }
}

pub fn invoke(args: &[String]) -> Result<Value, Value> {
    let Some(first) = args.first() else {
        return Err("caduceus-network-dhcp-command-missing".into());
    };
    let mut input = Map::new();
    match first.as_str() {
        "config" | "validate" if args.len() == 1 => cross(first.as_str(), Map::new()),
        "boundary" if args.len() == 1 || (args.len() == 2 && args[1] == "show") => {
            cross("boundary/show", Map::new())
        }
        "add-reservation" if args.len() >= 2 && !args[1].starts_with('-') => {
            input.insert("hw_address".into(), json!(args[1]));
            let mut pos = 2;
            while pos < args.len() {
                let key = match args[pos].as_str() {
                    "--ip-address" => "ip_address",
                    "--hostname" => "hostname",
                    _ => return Err(ROUTE_INVALID.into()),
                };
                if pos + 1 >= args.len() || args[pos + 1].starts_with('-') {
                    return Err(ROUTE_INVALID.into());
                }
                input.insert(key.into(), json!(args[pos + 1]));
                pos += 2;
            }
            cross("add-reservation", input)
        }
        "remove-reservation" if args.len() == 2 && !args[1].starts_with('-') => {
            input.insert("identifier".into(), json!(args[1]));
            cross("remove-reservation", input)
        }
        "update-reservation-ip" if args.len() == 3 && !args[1].starts_with('-') && !args[2].starts_with('-') => {
            input.insert("identifier".into(), json!(args[1]));
            input.insert("new_ip".into(), json!(args[2]));
            cross("update-reservation-ip", input)
        }
        "update-pool-boundary" if args.len() == 2 => {
            let boundary: i64 = args[1].parse().map_err(|_| REQUEST_INVALID.to_string())?;
            input.insert("max_reservations".into(), json!(boundary));
            cross("update-pool-boundary", input)
        }
        _ => Err(ROUTE_INVALID.into()),
    }
}
pub fn command(args: &[String]) -> i32 {
    match invoke(args) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            0
        }
        Err(e) => {
            if let Some(error) = e.as_str() {
                eprintln!("{error}");
            } else {
                eprintln!("{e}");
            }
            1
        }
    }
}
pub fn intent_json(method: &str, route: &str, metadata: Value) -> Result<Value, String> {
    let mut input = Map::new();
    let stop = match (method, route) {
        ("POST", "/api/dhcp") | ("POST", "/api/dhcp/reservations") => {
            let mac = metadata.get("mac").and_then(Value::as_str).ok_or(REQUEST_INVALID)?;
            input.insert("hw_address".into(), json!(mac));
            for (source, target) in [("ip", "ip_address"), ("hostname", "hostname")] {
                if let Some(value) = metadata.get(source) {
                    let value = value.as_str().ok_or(REQUEST_INVALID)?;
                    input.insert(target.into(), json!(value));
                }
            }
            "add-reservation"
        }
        ("POST", "/api/dhcp/pool-boundary") => {
            let value = metadata.get("max_reservations").ok_or(REQUEST_INVALID)?;
            if !value.is_i64() && !value.is_u64() {
                return Err(REQUEST_INVALID.into());
            }
            input.insert("max_reservations".into(), value.clone());
            "update-pool-boundary"
        }
        ("PUT" | "DELETE", _) => {
            let id = route.strip_prefix("/api/dhcp/reservations/").ok_or(ROUTE_INVALID)?;
            if id.is_empty() || id.contains('/') {
                return Err(ROUTE_INVALID.into());
            }
            input.insert("identifier".into(), json!(id));
            if method == "PUT" {
                let ip = metadata.get("ip").and_then(Value::as_str).ok_or(REQUEST_INVALID)?;
                input.insert("new_ip".into(), json!(ip));
                "update-reservation-ip"
            } else {
                "remove-reservation"
            }
        }
        _ => return Err(ROUTE_INVALID.into()),
    };
    cross(stop, input).map_err(|error| {
        error.as_str()
            .or_else(|| error.get("firstMissingSignal").and_then(Value::as_str))
            .unwrap_or("caduceus-agathodaimon-refused")
            .to_string()
    })
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
}
