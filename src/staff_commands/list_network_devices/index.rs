use crate::shared::config;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
struct NetworkProbe {
    openvpn_present: bool,
    openvpn_interface: Option<String>,
    openvpn_has_address: bool,
    port_forwarding_process_present: bool,
    tailscale_present: bool,
    tailscale_has_address: bool,
}

pub fn status_json() -> Result<Value, String> {
    let probe = probe_network();
    let ok = probe.openvpn_present
        && probe.openvpn_has_address
        && probe.port_forwarding_process_present
        && probe.tailscale_present
        && probe.tailscale_has_address;
    let first_missing_signal = first_missing_signal(&probe);
    Ok(json!({
        "schema": "caduceus.network.status.v1",
        "ok": ok,
        "openvpnPresent": probe.openvpn_present,
        "openvpnInterface": probe.openvpn_interface,
        "openvpnHasAddress": probe.openvpn_has_address,
        "portForwardingProcessPresent": probe.port_forwarding_process_present,
        "tailscalePresent": probe.tailscale_present,
        "tailscaleHasAddress": probe.tailscale_has_address,
        "firstMissingSignal": first_missing_signal
    }))
}

fn probe_network() -> NetworkProbe {
    let openvpn_interface = find_openvpn_interface();
    let tailscale_present = interface_present("tailscale0");
    NetworkProbe {
        openvpn_present: openvpn_interface.is_some(),
        openvpn_has_address: openvpn_interface
            .as_deref()
            .map(interface_has_address)
            .unwrap_or(false),
        openvpn_interface,
        port_forwarding_process_present: process_cmdline_contains("port_forwarding.sh"),
        tailscale_present,
        tailscale_has_address: tailscale_present && interface_has_address("tailscale0"),
    }
}

fn first_missing_signal(probe: &NetworkProbe) -> &'static str {
    if !probe.openvpn_present {
        "caduceus-network-openvpn-interface-missing"
    } else if !probe.openvpn_has_address {
        "caduceus-network-openvpn-address-missing"
    } else if !probe.port_forwarding_process_present {
        "caduceus-network-port-forwarding-process-missing"
    } else if !probe.tailscale_present {
        "caduceus-network-tailscale-interface-missing"
    } else if !probe.tailscale_has_address {
        "caduceus-network-tailscale-address-missing"
    } else {
        "none"
    }
}

fn find_openvpn_interface() -> Option<String> {
    let net_root = config::path("sys/class/net");
    fs::read_dir(&net_root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .find(|name| name.starts_with("tun"))
}

fn interface_present(interface: &str) -> bool {
    config::path(&format!("sys/class/net/{interface}")).exists()
}

fn interface_has_address(interface: &str) -> bool {
    let fixture_addr = config::path(&format!("var/lib/caduceus/network/{interface}.addr"));
    if fixture_addr.exists() {
        return fs::read_to_string(fixture_addr)
            .map(|text| text.lines().any(|line| !line.trim().is_empty()))
            .unwrap_or(false);
    }

    if config::root() != Path::new("/") {
        return false;
    }

    Command::new("ip")
        .args(["-o", "addr", "show", "dev", interface])
        .output()
        .map(|output| {
            output.status.success() && String::from_utf8_lossy(&output.stdout).contains("inet ")
        })
        .unwrap_or(false)
}

fn process_cmdline_contains(needle: &str) -> bool {
    let proc_root = config::path("proc");
    fs::read_dir(proc_root)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .filter_map(|entry| {
            entry.file_name().to_str().and_then(|name| {
                name.chars()
                    .all(|ch| ch.is_ascii_digit())
                    .then(|| entry.path())
            })
        })
        .any(|pid_path| {
            fs::read(pid_path.join("cmdline"))
                .map(|bytes| {
                    String::from_utf8_lossy(&bytes)
                        .replace('\0', " ")
                        .contains(needle)
                })
                .unwrap_or(false)
        })
}

pub fn status() -> i32 {
    match status_json() {
        Ok(value) => {
            println!("schema=caduceus.network.status.v1");
            println!("openvpn_present={}", value["openvpnPresent"]);
            println!(
                "openvpn_interface={}",
                value["openvpnInterface"].as_str().unwrap_or("")
            );
            println!("openvpn_has_address={}", value["openvpnHasAddress"]);
            println!(
                "port_forwarding_process_present={}",
                value["portForwardingProcessPresent"]
            );
            println!("tailscale_present={}", value["tailscalePresent"]);
            println!("tailscale_has_address={}", value["tailscaleHasAddress"]);
            println!("ok={}", value["ok"]);
            println!(
                "first_missing_signal={}",
                value["firstMissingSignal"].as_str().unwrap_or("")
            );
            0
        }
        Err(err) => {
            eprintln!("caduceus-network-status-failed: {err}");
            1
        }
    }
}

// Profile-indexed public read delegation for DHCP, DNS, and device roster data.
//
// This native band selects only admitted read actuators and never reads or
// mutates appliance network state itself.

use crate::staff_commands::staff;
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
        command: "network dns resolver status",
        actuator_id: "network.dns.resolver.status",
        args: &["resolver", "status"],
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
