//! Caduceus network-identity claim band — public Rust face over the pinned
//! `network.identity.claim` staff actuator. Rust validates the public shape and
//! relays the exact claim argv; selection, transaction, and rollback stay staff-side.

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
