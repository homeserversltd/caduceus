use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PjlinkDevice {
    pub id: String,
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_timeout_ms")]
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PjlinkReceipt {
    pub schema: &'static str,
    pub ok: bool,
    pub device_id: String,
    pub host: String,
    pub port: u16,
    pub command: String,
    pub requested_state: Option<String>,
    pub mutation: bool,
    pub dry_run: bool,
    pub response: Option<String>,
    pub first_missing_signal: String,
}

fn default_port() -> u16 {
    4352
}

fn default_timeout_ms() -> u64 {
    1500
}

pub fn power_command(state: &str) -> Result<&'static str, String> {
    match state {
        "on" => Ok("%1POWR 1\r"),
        "off" => Ok("%1POWR 0\r"),
        _ => Err("caduceus-pjlink-power-state-invalid".to_string()),
    }
}

pub fn query_power_command() -> &'static str {
    "%1POWR ?\r"
}

pub fn run_power(device: &PjlinkDevice, state: &str, dry_run: bool) -> PjlinkReceipt {
    let command = match power_command(state) {
        Ok(value) => value,
        Err(err) => return failure(device, "power", Some(state), dry_run, err),
    };
    if dry_run {
        return PjlinkReceipt {
            schema: "caduceus.pjlink.power.v1",
            ok: true,
            device_id: device.id.clone(),
            host: device.host.clone(),
            port: device.port,
            command: command.trim_end().to_string(),
            requested_state: Some(state.to_string()),
            mutation: false,
            dry_run: true,
            response: None,
            first_missing_signal: "none".to_string(),
        };
    }
    exchange(
        device,
        command,
        "caduceus.pjlink.power.v1",
        Some(state.to_string()),
        true,
    )
}

pub fn run_power_query(device: &PjlinkDevice) -> PjlinkReceipt {
    exchange(
        device,
        query_power_command(),
        "caduceus.pjlink.power-status.v1",
        None,
        false,
    )
}

fn exchange(
    device: &PjlinkDevice,
    command: &str,
    schema: &'static str,
    requested_state: Option<String>,
    mutation: bool,
) -> PjlinkReceipt {
    match pjlink_exchange(device, command) {
        Ok(response) => PjlinkReceipt {
            schema,
            ok: response.starts_with("%1POWR=") || response.starts_with("%1POWR "),
            device_id: device.id.clone(),
            host: device.host.clone(),
            port: device.port,
            command: command.trim_end().to_string(),
            requested_state,
            mutation,
            dry_run: false,
            first_missing_signal: if response.starts_with("%1POWR=")
                || response.starts_with("%1POWR ")
            {
                "none".to_string()
            } else {
                "caduceus-pjlink-unexpected-response".to_string()
            },
            response: Some(response),
        },
        Err(err) => failure(
            device,
            command.trim_end(),
            requested_state.as_deref(),
            false,
            err,
        ),
    }
}

fn failure(
    device: &PjlinkDevice,
    command: &str,
    requested_state: Option<&str>,
    dry_run: bool,
    first_missing_signal: String,
) -> PjlinkReceipt {
    PjlinkReceipt {
        schema: "caduceus.pjlink.power.v1",
        ok: false,
        device_id: device.id.clone(),
        host: device.host.clone(),
        port: device.port,
        command: command.to_string(),
        requested_state: requested_state.map(str::to_string),
        mutation: false,
        dry_run,
        response: None,
        first_missing_signal,
    }
}

fn pjlink_exchange(device: &PjlinkDevice, command: &str) -> Result<String, String> {
    let addr = (device.host.as_str(), device.port)
        .to_socket_addrs()
        .map_err(|err| format!("caduceus-pjlink-resolve-failed:{err}"))?
        .next()
        .ok_or_else(|| "caduceus-pjlink-resolve-empty".to_string())?;
    let timeout = Duration::from_millis(device.timeout_ms);
    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|err| format!("caduceus-pjlink-connect-failed:{err}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|err| format!("caduceus-pjlink-read-timeout-set-failed:{err}"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|err| format!("caduceus-pjlink-write-timeout-set-failed:{err}"))?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|err| format!("caduceus-pjlink-stream-clone-failed:{err}"))?,
    );
    let mut greeting = String::new();
    reader
        .read_line(&mut greeting)
        .map_err(|err| format!("caduceus-pjlink-greeting-read-failed:{err}"))?;
    let payload = authenticated_payload(greeting.trim_end(), command, device.password.as_deref())?;
    stream
        .write_all(payload.as_bytes())
        .map_err(|err| format!("caduceus-pjlink-write-failed:{err}"))?;
    stream
        .flush()
        .map_err(|err| format!("caduceus-pjlink-flush-failed:{err}"))?;
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|err| format!("caduceus-pjlink-response-read-failed:{err}"))?;
    Ok(response.trim_end().to_string())
}

fn authenticated_payload(
    greeting: &str,
    command: &str,
    password: Option<&str>,
) -> Result<String, String> {
    if greeting == "PJLINK 0" {
        return Ok(command.to_string());
    }
    if let Some(seed) = greeting.strip_prefix("PJLINK 1 ") {
        let Some(password) = password else {
            return Err("caduceus-pjlink-password-required".to_string());
        };
        let digest = format!("{:x}", md5::compute(format!("{seed}{password}")));
        return Ok(format!("{digest}{command}"));
    }
    Err("caduceus-pjlink-greeting-invalid".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthenticated_payload_is_plain_pjlink_command() {
        assert_eq!(
            authenticated_payload("PJLINK 0", "%1POWR 1\r", None).unwrap(),
            "%1POWR 1\r"
        );
    }

    #[test]
    fn authenticated_payload_requires_password() {
        assert_eq!(
            authenticated_payload("PJLINK 1 abcd", "%1POWR 1\r", None).unwrap_err(),
            "caduceus-pjlink-password-required"
        );
    }
}
