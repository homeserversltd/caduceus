use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const LEASE_COMMAND: &str = "network dhcp leases";
pub(crate) const RESERVATION_COMMAND: &str = "network dhcp reservations list";
pub(crate) const DOORWAYS_COMMAND: &str = "network dhcp doorways list";
const DHCP_STAFF_SCHEMA: &str = "caduceus.staff.network.dhcp.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseRow {
    pub mac: String,
    pub ip: String,
    pub hostname: String,
    pub last_activity: String,
    pub expires: String,
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

fn read_kea_file(path: &Path) -> Option<Vec<u8>> {
    if unsafe { libc::geteuid() } == 0 {
        fs::read(path).ok()
    } else {
        let output = Command::new("/usr/bin/sudo")
            .args(["-n", "/usr/bin/cat"])
            .arg(path)
            .output()
            .ok()?;
        output.status.success().then_some(output.stdout)
    }
}

fn read_config() -> Result<Value, String> {
    let path = configuration_path();
    let text = read_kea_file(&path)
        .and_then(|bytes| String::from_utf8(bytes).ok())
        .ok_or_else(|| missing("config-missing"))?;
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
    let (mut field, mut quoted, mut closed_quote, mut chars) =
        (String::new(), false, false, line.chars().peekable());
    while let Some(ch) = chars.next() {
        if quoted {
            match ch {
                '"' if chars.peek() == Some(&'"') => {
                    field.push('"');
                    chars.next();
                }
                '"' => {
                    quoted = false;
                    closed_quote = true;
                }
                _ => field.push(ch),
            }
            continue;
        }
        match ch {
            ',' => {
                fields.push(std::mem::take(&mut field));
                closed_quote = false;
            }
            '"' if field.is_empty() && !closed_quote => quoted = true,
            _ if closed_quote => return None,
            '"' => return None,
            _ => field.push(ch),
        }
    }
    if quoted {
        return None;
    }
    fields.push(field.trim_end_matches('\r').to_string());
    Some(fields)
}

pub(crate) fn normalized_mac(value: &str) -> Option<String> {
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
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root && candidates.iter().all(|path| !path.exists()) {
        return Err(missing("leases-missing"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| missing("clock-invalid"))?
        .as_secs();
    let mut latest: BTreeMap<String, Option<(u64, LeaseRow)>> = BTreeMap::new();
    let mut readable = false;
    let mut present = false;
    for path in candidates {
        let Some(bytes) = read_kea_file(&path) else {
            continue;
        };
        present = true;
        let Ok(text) = String::from_utf8(bytes) else {
            continue;
        };
        readable = true;
        let mut lines = text.lines().filter(|line| !line.trim().is_empty());
        let header_line = lines.next().ok_or_else(|| missing("leases-invalid"))?;
        let header = csv_record(header_line).ok_or_else(|| missing("leases-invalid"))?;
        let required = ["address", "hwaddr", "expire", "hostname", "state"];
        if required.iter().any(|name| column(&header, name).is_none()) {
            return Err(missing("leases-invalid"));
        }
        for line in lines {
            let Some(fields) = csv_record(line) else {
                continue;
            };
            if fields.len() != header.len() {
                continue;
            }
            let Some(mac) = cell(
                &fields,
                column(&header, "hwaddr").or_else(|| column(&header, "hw-address")),
            )
            .and_then(normalized_mac) else {
                continue;
            };
            let Some(expiry) = cell(&fields, column(&header, "expire"))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            let Some(state) =
                cell(&fields, column(&header, "state")).and_then(|value| value.parse::<u32>().ok())
            else {
                continue;
            };
            let ip = cell(&fields, column(&header, "address")).unwrap_or("");
            let row = if state == 0 && expiry > now {
                Some((expiry, LeaseRow {
                    mac: mac.clone(),
                    ip: ip.to_string(),
                    hostname: cell(&fields, column(&header, "hostname"))
                        .unwrap_or("")
                        .to_string(),
                    last_activity: cell(&fields, column(&header, "valid_lifetime"))
                        .and_then(|value| value.parse::<u64>().ok())
                        .and_then(|lifetime| expiry.checked_sub(lifetime))
                        .map(|renewal| renewal.to_string())
                        .unwrap_or_default(),
                    expires: expiry.to_string(),
                }))
            } else {
                None
            };
            // Processing rollover files in Kea load order means each later address occurrence wins.
            latest.insert(ip.to_string(), row);
        }
    }
    if !readable {
        return Err(missing(if is_root || present { "leases-invalid" } else { "leases-missing" }));
    }
    let mut by_mac: BTreeMap<String, (u64, LeaseRow)> = BTreeMap::new();
    for (expiry, row) in latest.into_values().flatten() {
        let entry = by_mac.entry(row.mac.clone()).or_insert_with(|| (expiry, row.clone()));
        if expiry > entry.0 {
            *entry = (expiry, row);
        }
    }
    Ok(by_mac.into_values().map(|(_, row)| row).collect())
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

/// Read each reservation independently without changing the strict legacy reader.
pub(crate) fn read_reservations_partial() -> Result<(Vec<ReservationRow>, Vec<Value>), String> {
    let root = read_config()?;
    let dhcp = &root["Dhcp4"];
    let mut rows = Vec::new();
    let mut skipped = Vec::new();
    let mut collect = |entries: &Vec<Value>| {
        for entry in entries {
            match reservation(entry) {
                Ok(row) => rows.push(row),
                Err(_) => {
                    let reason = if entry.get("hw-address").and_then(Value::as_str).and_then(normalized_mac).is_none() {
                        "invalid-or-missing-hw-address"
                    } else {
                        "missing-ip-address"
                    };
                    skipped.push(json!({"entry": entry, "reason": reason}));
                }
            }
        }
    };
    if let Some(entries) = dhcp.get("reservations").and_then(Value::as_array) {
        collect(entries);
    }
    if let Some(subnets) = dhcp.get("subnet4").and_then(Value::as_array) {
        for subnet in subnets {
            if let Some(entries) = subnet.get("reservations").and_then(Value::as_array) {
                collect(entries);
            }
        }
    }
    rows.sort_by(|a, b| (&a.mac, &a.ip, &a.hostname).cmp(&(&b.mac, &b.ip, &b.hostname)));
    Ok((rows, skipped))
}

fn doorway_mac(suffix: &str) -> Option<String> {
    let literal = suffix.trim_start().strip_prefix("==")?;
    let literal = literal.trim_start().strip_prefix("0x")?;
    let (hex, tail) = literal.split_at_checked(12)?;
    if !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
        || tail.as_bytes().first().is_some_and(u8::is_ascii_hexdigit)
    {
        return None;
    }
    Some(format!(
        "{}:{}:{}:{}:{}:{}",
        &hex[..2],
        &hex[2..4],
        &hex[4..6],
        &hex[6..8],
        &hex[8..10],
        &hex[10..],
    ))
}

fn read_doorways() -> Result<Value, String> {
    let root = read_config()?;
    let mut rows = Vec::new();
    if let Some(classes) = root["Dhcp4"]["client-classes"].as_array() {
        for class in classes {
            let (Some(name), Some(test)) = (class["name"].as_str(), class["test"].as_str()) else {
                continue;
            };
            let test = test.to_ascii_lowercase();
            for (start, token) in test.match_indices("pkt4.mac") {
                if test[..start]
                    .chars()
                    .next_back()
                    .is_some_and(|ch| ch.is_alphanumeric() || ch == '_')
                {
                    continue;
                }
                if let Some(mac) = doorway_mac(&test[start + token.len()..]) {
                    rows.push((mac, name));
                }
            }
        }
    }
    rows.sort_unstable();
    Ok(Value::Array(
        rows.into_iter()
            .map(|(mac, class)| json!({"mac": mac, "class": class}))
            .collect(),
    ))
}

fn gateway_read<T>(read: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    if cfg!(carapace_feature_kea) {
        read()
    } else {
        Err(crate::routes::network_read::NOT_THE_GATEWAY.into())
    }
}

pub fn response(command: &str) -> Value {
    let (action, actuator, result, inner_schema, failure) = match command {
        LEASE_COMMAND => match gateway_read(read_leases) {
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
                "caduceus.network.dhcp.leases.v1",
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
        RESERVATION_COMMAND => match gateway_read(read_reservations) {
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
                "caduceus.network.dhcp.reservations.v1",
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
        DOORWAYS_COMMAND => {
            let (result, failure) = match gateway_read(read_doorways) {
                Ok(rows) => (rows, None),
                Err(error) => (Value::Null, Some(error)),
            };
            (
                "doorways",
                "network.dhcp.doorways",
                result,
                DHCP_STAFF_SCHEMA,
                failure,
            )
        }
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
