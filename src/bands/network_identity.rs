//! Caduceus network-identity claim band — public Rust face over the pinned
//! `network.identity.claim` staff actuator. Rust validates the public shape and
//! relays the exact claim argv; selection, transaction, and rollback stay staff-side.

use serde_json::Value;
use std::{env, process::Command};

fn claim_cmd() -> (String, Vec<String>) {
    if let Ok(command) = env::var("CADUCEUS_NETWORK_IDENTITY_CLAIM_CMD") {
        let parts: Vec<String> = command.split_whitespace().map(str::to_string).collect();
        if let Some((program, prefix)) = parts.split_first() {
            return (program.clone(), prefix.to_vec());
        }
    }
    ("caduceus-network-identity-claim".into(), Vec::new())
}

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
    let (program, prefix) = claim_cmd();
    let output = Command::new(program)
        .args(prefix)
        .args(args)
        .output()
        .map_err(|err| format!("caduceus-network-identity-claim-unavailable: {err}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "caduceus-network-identity-claim-empty: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let receipt: Value = serde_json::from_str(&stdout)
        .map_err(|err| format!("caduceus-network-identity-claim-invalid-json: {err}"))?;
    match receipt.get("state").and_then(Value::as_str) {
        Some("applied" | "noop" | "rolled_back" | "rollback_failed" | "blocked") => Ok(receipt),
        _ => Err("caduceus-network-identity-claim-receipt-invalid".into()),
    }
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
