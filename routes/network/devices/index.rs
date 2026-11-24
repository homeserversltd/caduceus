use axum::{routing::get, Json, Router};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use crate::routes::native_kea_read::{self, LeaseRow, ReservationRow};

#[derive(Default)]
struct Device {
    reservation: Option<ReservationRow>,
    lease: Option<LeaseRow>,
    neighbour: Option<Value>,
}

fn answer() -> Value {
    let mut devices: BTreeMap<String, Device> = BTreeMap::new();
    let mut unavailable = Vec::new();
    let mut skipped = Vec::new();

    let neighbours = crate::gate::snake::crossing_path_receipt("network/neighbor/read", &json!({}));
    match neighbours {
        Ok(value) if value.get("ok").and_then(Value::as_bool) == Some(true)
            && value.get("doorSignal").is_none()
            && value.get("neighbors").and_then(Value::as_array).is_some() => {
            for row in value["neighbors"].as_array().unwrap() {
                if let Some(mac) = row.get("mac").and_then(Value::as_str).and_then(native_kea_read::normalized_mac) {
                    devices.entry(mac).or_default().neighbour = Some(json!({
                        "ip": row.get("ip"), "state": row.get("state"), "interface": "lan0"
                    }));
                }
            }
        }
        _ => unavailable.push("neighbour"),
    }
    let names = match crate::routes::unbound_names::read() {
        Ok(records) => records,
        Err(_) => { unavailable.push("unbound"); Vec::new() }
    };
    match native_kea_read::read_leases() {
        Ok(rows) => for row in rows {
            if let Some(mac) = native_kea_read::normalized_mac(&row.mac) {
                devices.entry(mac).or_default().lease = Some(row);
            }
        },
        Err(_) => unavailable.push("leases"),
    }
    match native_kea_read::read_reservations_partial() {
        Ok((rows, bad)) => {
            skipped = bad;
            for row in rows {
                if let Some(mac) = native_kea_read::normalized_mac(&row.mac) {
                    devices.entry(mac).or_default().reservation = Some(row);
                }
            }
        }
        Err(_) => unavailable.push("reservations"),
    }
    let records: Vec<Value> = devices.into_iter().map(|(mac, device)| {
        let reservation_ip = device.reservation.as_ref().map(|r| r.ip.as_str());
        let lease_ip = device.lease.as_ref().map(|r| r.ip.as_str());
        let mut device_names = BTreeSet::new();
        let mut aliases = BTreeSet::new();
        let mut reservation_has_name = false;
        for record in &names {
            if Some(record.ip.as_str()) == reservation_ip || Some(record.ip.as_str()) == lease_ip {
                if record.alias { aliases.insert(record.name.clone()); }
                else {
                    device_names.insert(record.name.clone());
                    if Some(record.ip.as_str()) == reservation_ip { reservation_has_name = true; }
                }
            }
        }
        let mut mismatches: Vec<String> = Vec::new();
        if let (Some(a), Some(b)) = (reservation_ip, lease_ip) {
            if a != b { mismatches.push("reservation-ip-differs-from-observed-lease".into()); }
        }
        if device.reservation.is_some() && !reservation_has_name {
            mismatches.push("reservation-without-dns-record".into());
        }
        for part in &unavailable { mismatches.push(format!("{part}-unavailable")); }
        let claim = if device.reservation.is_some() && reservation_has_name { "claimed" }
            else if device.reservation.is_some() || device.lease.is_some() || !device_names.is_empty() { "partial" }
            else { "unclaimed" };
        let neighbour_ip = device.neighbour.as_ref().and_then(|n| n.get("ip")).and_then(Value::as_str);
        let (address, source) = if let Some(ip) = neighbour_ip { (Some(ip), Some("neighbour")) }
            else if let Some(ip) = lease_ip { (Some(ip), Some("lease")) }
            else if let Some(ip) = reservation_ip { (Some(ip), Some("reservation")) }
            else { (None, None) };
        let online = if unavailable.contains(&"neighbour") { None }
            else if let Some(neighbour) = &device.neighbour {
                match neighbour.get("state").and_then(Value::as_str).map(|s| s.to_ascii_uppercase()).as_deref() {
                    Some("REACHABLE" | "STALE" | "DELAY" | "PROBE" | "PERMANENT" | "NOARP") => Some(true),
                    Some("FAILED" | "INCOMPLETE" | "NONE") => Some(false),
                    _ => None,
                }
            } else { Some(false) };
        json!({
            "mac": mac,
            "reservation": device.reservation.as_ref().map(|r| json!({"ip":r.ip,"hostname":r.hostname})),
            "lease": device.lease.as_ref().map(|r| json!({"ip":r.ip,"hostname":r.hostname,"expires":r.last_activity})),
            "neighbour": device.neighbour,
            "names": device_names, "aliases": aliases, "address": address, "address_source": source,
            "online": online, "claim_state": claim, "mismatches": mismatches
        })
    }).collect();
    let signal = unavailable.first().map(|part| format!("{part}-unavailable")).unwrap_or_else(|| "none".into());
    json!({
        "schema":"caduceus.staff.receipt.v1", "ok":true,
        "stop":{"noun":"network","verb":"devices"},
        "observed":{"devices":records,"unavailable_parts":unavailable,"skipped_reservations":skipped},
        "could_change_to":{"deferred":["child","enforcement","notes","owner","label","aliases","first_seen","last_seen","ruyi","backup_pair"]},
        "attempt":null, "final_receipt":{"ok":true,"firstMissingSignal":signal}
    })
}

async fn devices_route() -> Json<Value> {
    match tokio::task::spawn_blocking(answer).await {
        Ok(receipt) => Json(receipt),
        Err(_) => Json(json!({"schema":"caduceus.staff.receipt.v1", "ok":true,
            "stop":{"noun":"network","verb":"devices"},
            "observed":{"devices":[],"unavailable_parts":["neighbour","unbound","leases","reservations"],"skipped_reservations":[]},
            "could_change_to":{"deferred":["child","enforcement","notes","owner","label","aliases","first_seen","last_seen","ruyi","backup_pair"]},
            "attempt":null,"final_receipt":{"ok":true,"firstMissingSignal":"neighbour-unavailable"}})),
    }
}

pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/devices", get(devices_route))
}
