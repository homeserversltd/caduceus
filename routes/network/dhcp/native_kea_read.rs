use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

const LEASE_COMMAND: &str = "network dhcp leases";
const RESERVATION_COMMAND: &str = "network dhcp reservations list";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub last_activity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRow {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
}

fn missing(reason: &str) -> String {
    format!("caduceus-network-dhcp-{reason}")
}

fn configuration_path() -> PathBuf {
    crate::shared::config::path("etc/kea/kea-dhcp4.conf")
}

fn read_config() -> Result<Value, String> {
    let path = configuration_path();
    let text = fs::read_to_string(&path).map_err(|_| missing("config-missing"))?;
    let stripped = strip_comments(&text).ok_or_else(|| missing("config-invalid"))?;
    let root: Value = serde_json::from_str(&stripped).map_err(|_| missing("config-invalid"))?;
    root.get("Dhcp4")
        .and_then(Value::as_object)
        .ok_or_else(|| missing("config-invalid"))?;
    Ok(root)
}

fn strip_comments(input: &str) -> Option<String> {
    let chars: Vec<char> = input.chars().collect();
    let (mut out, mut index, mut quoted, mut escaped) = (String::new(), 0, false, false);
    while index < chars.len() {
        let ch = chars[index];
        if quoted {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            index += 1;
            continue;
        }
        if ch == '"' {
            quoted = true;
            out.push(ch);
            index += 1;
        } else if ch == '#' {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            if index < chars.len() {
                out.push('\n');
                index += 1;
            }
        } else if ch == '/' && chars.get(index + 1) == Some(&'/') {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            if index < chars.len() {
                out.push('\n');
                index += 1;
            }
        } else {
            out.push(ch);
            index += 1;
        }
    }
    (!quoted).then_some(out)
}

fn lease_file(dhcp: &Value) -> PathBuf {
    let name = dhcp
        .get("lease-database")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or("/var/lib/kea/kea-leases4.csv");
    crate::shared::config::path(name)
}

fn csv_record(line: &str) -> Option<Vec<String>> {
    let mut fields = Vec::new();
    let (mut field, mut quoted, mut chars) = (String::new(), false, line.chars().peekable());
    while let Some(ch) = chars.next() {
        match ch {
            '"' if quoted && chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            _ => field.push(ch),
        }
    }
    if quoted {
        return None;
    }
    fields.push(field.trim_end_matches('\r').to_string());
    Some(fields)
}

fn normalized_mac(value: &str) -> Option<String> {
    let compact = value.trim().replace('-', ":").to_ascii_lowercase();
    let parts: Vec<&str> = compact.split(':').collect();
    (parts.len() == 6
        && parts
            .iter()
            .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit())))
    .then(|| parts.join(":"))
}

fn column(header: &[String], name: &str) -> Option<usize> {
    header.iter().position(|value| value.trim() == name)
}

fn cell<'a>(row: &'a [String], index: Option<usize>) -> Option<&'a str> {
    row.get(index?).map(|value| value.trim())
}

pub fn read_leases() -> Result<Vec<LeaseRow>, String> {
    let root = read_config()?;
    let dhcp = &root["Dhcp4"];
    let base = lease_file(dhcp);
    let candidates = [
        PathBuf::from(format!("{}.2", base.display())),
        PathBuf::from(format!("{}.1", base.display())),
        base,
    ];
    let existing: Vec<PathBuf> = candidates
        .into_iter()
        .filter(|path| path.exists())
        .collect();
    if existing.is_empty() {
        return Err(missing("leases-missing"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| missing("clock-invalid"))?
        .as_secs();
    let mut latest: BTreeMap<String, Option<LeaseRow>> = BTreeMap::new();
    for path in existing {
        let text = fs::read_to_string(&path).map_err(|_| missing("leases-invalid"))?;
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());
        let header = csv_record(lines.next().ok_or_else(|| missing("leases-invalid"))?)
            .ok_or_else(|| missing("leases-invalid"))?;
        let required = ["address", "hwaddr", "expire", "hostname", "state"];
        if required.iter().any(|name| column(&header, name).is_none()) {
            return Err(missing("leases-invalid"));
        }
        for line in lines {
            let fields = csv_record(line).ok_or_else(|| missing("leases-invalid"))?;
            if fields.len() != header.len() {
                return Err(missing("leases-invalid"));
            }
            let mac = cell(
                &fields,
                column(&header, "hwaddr").or_else(|| column(&header, "hw-address")),
            )
            .and_then(normalized_mac)
            .ok_or_else(|| missing("leases-invalid"))?;
            let ip = cell(&fields, column(&header, "address")).unwrap_or("");
            let expiry = cell(&fields, column(&header, "expire"))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| missing("leases-invalid"))?;
            let state = cell(&fields, column(&header, "state"))
                .and_then(|value| value.parse::<u32>().ok())
                .ok_or_else(|| missing("leases-invalid"))?;
            let row = if state == 0 && expiry > now {
                Some(LeaseRow {
                    mac: mac.clone(),
                    ip: ip.to_string(),
                    hostname: cell(&fields, column(&header, "hostname"))
                        .unwrap_or("")
                        .to_string(),
                    last_activity: expiry.to_string(),
                })
            } else {
                None
            };
            // Processing rollover files in Kea load order means each later occurrence wins.
            latest.insert(mac, row);
        }
    }
    Ok(latest.into_values().flatten().collect())
}

fn reservation(value: &Value) -> Result<ReservationRow, String> {
    let mac = value
        .get("hw-address")
        .and_then(Value::as_str)
        .and_then(normalized_mac)
        .ok_or_else(|| missing("reservations-invalid"))?;
    let ip = value
        .get("ip-address")
        .and_then(Value::as_str)
        .ok_or_else(|| missing("reservations-invalid"))?;
    let hostname = value.get("hostname").and_then(Value::as_str).unwrap_or("");
    Ok(ReservationRow {
        mac,
        ip: ip.to_string(),
        hostname: hostname.to_string(),
    })
}

pub fn read_reservations() -> Result<Vec<ReservationRow>, String> {
    let root = read_config()?;
    let dhcp = &root["Dhcp4"];
    let mut rows = Vec::new();
    if let Some(global) = dhcp.get("reservations").and_then(Value::as_array) {
        rows.extend(
            global
                .iter()
                .map(reservation)
                .collect::<Result<Vec<_>, _>>()?,
        );
    }
    if let Some(subnets) = dhcp.get("subnet4").and_then(Value::as_array) {
        for subnet in subnets {
            if let Some(reservations) = subnet.get("reservations").and_then(Value::as_array) {
                rows.extend(
                    reservations
                        .iter()
                        .map(reservation)
                        .collect::<Result<Vec<_>, _>>()?,
                );
            }
        }
    }
    rows.sort_by(|a, b| (&a.mac, &a.ip, &a.hostname).cmp(&(&b.mac, &b.ip, &b.hostname)));
    Ok(rows)
}

pub fn response(command: &str) -> Value {
    let (action, actuator, result, inner_schema, failure) = match command {
        LEASE_COMMAND => match read_leases() {
            Ok(rows) => (
                "leases",
                "network.dhcp.leases",
                Value::Array(
                    rows.into_iter()
                        .map(|row| {
                            json!({
                                "mac": row.mac,
                                "ip": row.ip,
                                "hostname": row.hostname,
                                "last_activity": row.last_activity,
                                "provenance": "observed"
                            })
                        })
                        .collect(),
                ),
                "caduceus.staff.network.dhcp.v1",
                None,
            ),
            Err(error) => (
                "leases",
                "network.dhcp.leases",
                Value::Null,
                "caduceus.network.dhcp.leases.v1",
                Some(error),
            ),
        },
        RESERVATION_COMMAND => match read_reservations() {
            Ok(rows) => (
                "reservations",
                "network.dhcp.reservations",
                Value::Array(
                    rows.into_iter()
                        .map(|row| {
                            json!({
                                "mac": row.mac,
                                "ip": row.ip,
                                "hostname": row.hostname,
                                "provenance": "declared"
                            })
                        })
                        .collect(),
                ),
                "caduceus.staff.network.dhcp.v1",
                None,
            ),
            Err(error) => (
                "reservations",
                "network.dhcp.reservations",
                Value::Null,
                "caduceus.network.dhcp.reservations.v1",
                Some(error),
            ),
        },
        _ => {
            return json!({
                "actuatorId": "network.dhcp.read",
                "command": command,
                "firstMissingSignal": "caduceus-network-dhcp-read-command-invalid",
                "ok": false,
                "payload": {
                    "action": "read",
                    "actuator": "network.dhcp.read",
                    "firstMissingSignal": "caduceus-network-dhcp-read-command-invalid",
                    "mutationPerformed": false,
                    "ok": false,
                    "result": Value::Null,
                    "schema": "caduceus.network.dhcp.read.v1"
                },
                "schema": "caduceus.network.read.v1"
            })
        }
    };
    let ok = failure.is_none();
    let signal = failure.as_deref().unwrap_or("none");
    json!({
        "actuatorId": actuator,
        "command": command,
        "firstMissingSignal": signal,
        "ok": ok,
        "payload": {
            "action": action,
            "actuator": actuator,
            "firstMissingSignal": signal,
            "mutationPerformed": false,
            "ok": ok,
            "result": result,
            "schema": inner_schema
        },
        "schema": "caduceus.network.read.v1"
    })
}
