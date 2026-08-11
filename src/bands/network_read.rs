//! Profile-indexed public read delegation for DHCP, DNS, and device roster data.
//!
//! This native band selects only admitted read actuators and never reads or
//! mutates appliance network state itself.

use crate::bands::staff;
use serde_json::{json, Value};
use std::{env, process::Command};

#[derive(Clone, Copy)]
pub struct ReadCommand {
    pub command: &'static str,
    pub actuator_id: &'static str,
    pub args: &'static [&'static str],
}

pub const COMMANDS: &[ReadCommand] = &[
    ReadCommand {
        command: "network dhcp status",
        actuator_id: "network.dhcp.status",
        args: &["status"],
    },
    ReadCommand {
        command: "network dhcp leases",
        actuator_id: "network.dhcp.leases",
        args: &["leases"],
    },
    ReadCommand {
        command: "network dhcp reservations list",
        actuator_id: "network.dhcp.reservations",
        args: &["reservations", "list"],
    },
    ReadCommand {
        command: "network dhcp boundary show",
        actuator_id: "network.dhcp.boundary",
        args: &["boundary", "show"],
    },
    ReadCommand {
        command: "network dhcp statistics",
        actuator_id: "network.dhcp.statistics",
        args: &["statistics"],
    },
    ReadCommand {
        command: "network dhcp health",
        actuator_id: "network.dhcp.health",
        args: &["health"],
    },
    ReadCommand {
        command: "network dns status",
        actuator_id: "network.dns.status",
        args: &["status"],
    },
    ReadCommand {
        command: "network dns read",
        actuator_id: "network.dns.read",
        args: &["read"],
    },
    ReadCommand {
        command: "network device list",
        actuator_id: "network.identity.device_list",
        args: &["list"],
    },
];

pub fn named(command: &str) -> Option<&'static ReadCommand> {
    COMMANDS
        .iter()
        .find(|candidate| candidate.command == command)
}

fn launcher(command: &ReadCommand) -> Result<(String, Vec<String>), String> {
    if let Ok(override_command) = env::var("CADUCEUS_NETWORK_READ_CMD") {
        let parts: Vec<String> = override_command
            .split_whitespace()
            .map(str::to_string)
            .collect();
        if let Some((program, prefix)) = parts.split_first() {
            return Ok((program.clone(), prefix.to_vec()));
        }
    }
    let profile = staff::profile_json()?;
    let actuator = profile
        .get("actuators")
        .and_then(Value::as_array)
        .and_then(|actuators| {
            actuators
                .iter()
                .find(|entry| entry.get("id") == Some(&json!(command.actuator_id)))
        })
        .ok_or_else(|| {
            format!(
                "caduceus-network-read-actuator-missing:{}",
                command.actuator_id
            )
        })?;
    let launcher = actuator
        .get("launcher")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            format!(
                "caduceus-network-read-launcher-missing:{}",
                command.actuator_id
            )
        })?;
    Ok((launcher.to_string(), Vec::new()))
}

pub fn invoke(command: &ReadCommand) -> Result<Value, String> {
    let (program, prefix) = launcher(command)?;
    let output = Command::new(program)
        .args(prefix)
        .args(command.args)
        .env("CADUCEUS_STAFF_ACTUATOR_ID", command.actuator_id)
        .output()
        .map_err(|err| {
            format!(
                "caduceus-network-read-unavailable:{}:{err}",
                command.actuator_id
            )
        })?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "caduceus-network-read-empty:{}:status={} stderr={}",
            command.actuator_id,
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let payload: Value = serde_json::from_str(&stdout).map_err(|err| {
        format!(
            "caduceus-network-read-invalid-json:{}:{err}",
            command.actuator_id
        )
    })?;
    if !output.status.success() || payload.get("ok") == Some(&json!(false)) {
        let signal = payload
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-network-read-failed");
        return Err(format!(
            "caduceus-network-read-failed:{}:{}",
            command.actuator_id, signal
        ));
    }
    Ok(json!({
        "schema": "caduceus.network.read.v1",
        "ok": true,
        "command": command.command,
        "actuatorId": command.actuator_id,
        "payload": payload,
        "firstMissingSignal": "none"
    }))
}

pub fn command(command: &ReadCommand) -> i32 {
    match invoke(command) {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}
