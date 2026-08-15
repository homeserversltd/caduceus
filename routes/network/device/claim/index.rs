// Caduceus network-identity claim band — public Rust face over the pinned
// `network.identity.claim` staff actuator. Rust validates the public shape and
// relays the exact claim argv; selection, transaction, and rollback stay staff-side.

use serde_json::Value;

pub fn valid_claim_args(args: &[String]) -> bool {
    let mut mac = false;
    let mut hostname = false;
    let mut ip = false;
    let mut auto_ip = false;
    let mut index = 0;
    if args.first().map(String::as_str) != Some("claim") {
        return false;
    }
    index += 1;
    while index < args.len() {
        match args[index].as_str() {
            "--mac" if !mac && index + 1 < args.len() => {
                mac = true;
                index += 2;
            }
            "--hostname" if !hostname && index + 1 < args.len() => {
                hostname = true;
                index += 2;
            }
            "--ip" if !ip && !auto_ip && index + 1 < args.len() => {
                ip = true;
                index += 2;
            }
            "--auto-ip" if !auto_ip && !ip => {
                auto_ip = true;
                index += 1;
            }
            _ => return false,
        }
    }
    mac && hostname && (ip || auto_ip)
}

pub fn invoke(args: &[String]) -> Result<Value, String> {
    if !valid_claim_args(args) {
        return Err("caduceus-network-identity-claim-arguments-invalid".into());
    }
    crate::shared::agathodaimon::crossing("network", "identity", &serde_json::json!({"args": args}))
}

pub fn command(args: &[String]) -> i32 {
    match invoke(args) {
        Ok(receipt) => {
            println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
            0
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}


use axum::{extract::Json, http::StatusCode, Router};
use serde::Deserialize;
use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::policy;
use crate::routes::network_identity;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NetworkDeviceClaimBody {
    mac: String,
    ip: Option<String>,
    #[serde(default)]
    auto_ip: bool,
    hostname: String,
}

async fn device_claim_route(
    Json(body): Json<NetworkDeviceClaimBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    const COMMAND: &str = "network device claim";
    match policy::allows_command(COMMAND) {
        Ok(true) => {
            if body.ip.is_some() == body.auto_ip || body.mac.is_empty() || body.hostname.is_empty()
            {
                return Err(api_error_signal(
                    COMMAND,
                    "caduceus-network-identity-claim-arguments-invalid",
                ));
            }
            let mut args = vec!["claim".to_string(), "--mac".to_string(), body.mac];
            if let Some(ip) = body.ip {
                if ip.is_empty() {
                    return Err(api_error_signal(
                        COMMAND,
                        "caduceus-network-identity-claim-arguments-invalid",
                    ));
                }
                args.extend(["--ip".to_string(), ip]);
            } else {
                args.push("--auto-ip".to_string());
            }
            args.extend(["--hostname".to_string(), body.hostname]);
            network_identity::invoke(&args)
                .map(|receipt| (StatusCode::OK, Json(receipt)))
                .map_err(|signal| api_error_signal(COMMAND, &signal))
        }
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/device/claim", axum::routing::post(device_claim_route))
}
