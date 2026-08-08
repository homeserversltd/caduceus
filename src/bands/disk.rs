//! Read-only filtered block-device census for the appliance disk manager.
//!
//! The census deliberately invokes only `lsblk` and `df`. It never opens,
//! mounts, formats, unlocks, or otherwise changes a block device.

use serde_json::{json, Map, Value};
use std::process::Command;

const NAS_FILESYSTEMS: &[&str] = &["ext4", "xfs"];
const SYSTEM_CRITICAL_MOUNTS: &[&str] = &[
    "/",
    "/boot",
    "/boot/efi",
    "/home",
    "/usr",
    "/var",
    "/etc",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/opt",
    "/srv",
    "/tmp",
    "/swap",
    "[SWAP]",
];
const HIDDEN_MOUNTS: &[&str] = &["/vault"];

pub fn census_json() -> Result<Value, String> {
    let output = Command::new("lsblk")
        .args([
            "--json",
            "--bytes",
            "--output",
            "NAME,KNAME,PKNAME,TYPE,SIZE,FSTYPE,LABEL,PARTLABEL,MOUNTPOINTS",
        ])
        .output()
        .map_err(|err| format!("caduceus-disk-census-lsblk-unavailable:{err}"))?;
    if !output.status.success() {
        return Err(format!(
            "caduceus-disk-census-lsblk-failed:{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let tree: Value = serde_json::from_slice(&output.stdout)
        .map_err(|err| format!("caduceus-disk-census-lsblk-invalid-json:{err}"))?;
    let devices = tree
        .get("blockdevices")
        .and_then(Value::as_array)
        .ok_or_else(|| "caduceus-disk-census-blockdevices-missing".to_string())?;

    let mut census = Vec::new();
    for device in devices {
        if excluded_parent(device) {
            continue;
        }
        collect_candidates(device, device, &mut census);
    }
    Ok(json!({
        "schema": "caduceus.disk.census.v1",
        "ok": true,
        "readOnly": true,
        "devices": census,
        "firstMissingSignal": "none"
    }))
}

pub fn show() -> i32 {
    match census_json() {
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

fn excluded_parent(device: &Value) -> bool {
    let name = string(device, "name").unwrap_or_default();
    name.starts_with("loop")
        || has_tmpfs(device)
        || descendants(device).any(|entry| {
            mountpoints(entry)
                .iter()
                .any(|mount| SYSTEM_CRITICAL_MOUNTS.contains(&mount.as_str()))
        })
}

fn has_tmpfs(entry: &Value) -> bool {
    string(entry, "fstype") == Some("tmpfs")
        || entry
            .get("children")
            .and_then(Value::as_array)
            .is_some_and(|children| children.iter().any(has_tmpfs))
}

fn descendants(entry: &Value) -> Box<dyn Iterator<Item = &Value> + '_> {
    Box::new(
        std::iter::once(entry).chain(
            entry
                .get("children")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .flat_map(descendants),
        ),
    )
}

fn collect_candidates(parent: &Value, entry: &Value, census: &mut Vec<Value>) {
    if mountpoints(entry)
        .iter()
        .any(|mount| HIDDEN_MOUNTS.contains(&mount.as_str()))
    {
        return;
    }
    let fstype = string(entry, "fstype").unwrap_or_default();
    let is_luks = fstype.eq_ignore_ascii_case("crypto_luks");
    if NAS_FILESYSTEMS.contains(&fstype) || is_luks {
        census.push(receipt(parent, entry, is_luks));
        return;
    }
    if let Some(children) = entry.get("children").and_then(Value::as_array) {
        for child in children {
            collect_candidates(parent, child, census);
        }
    }
}

fn receipt(parent: &Value, entry: &Value, locked_luks: bool) -> Value {
    let mountpoint = mountpoints(entry).into_iter().next();
    let mapper = if string(entry, "type") == Some("crypt") {
        string(entry, "name").map(str::to_string)
    } else {
        None
    };
    let encryption = if locked_luks {
        json!({ "state": "locked", "mapper": Value::Null })
    } else if let Some(mapper) = mapper {
        json!({ "state": "unlocked", "mapper": mapper })
    } else {
        json!({ "state": "none", "mapper": Value::Null })
    };
    let mut value = Map::new();
    value.insert("name".to_string(), json!(string(parent, "name")));
    value.insert(
        "partition".to_string(),
        json!((parent != entry).then(|| string(entry, "name")).flatten()),
    );
    value.insert(
        "label".to_string(),
        json!(string(entry, "label").or_else(|| string(entry, "partlabel"))),
    );
    value.insert(
        "sizeBytes".to_string(),
        entry.get("size").cloned().unwrap_or(Value::Null),
    );
    value.insert("fstype".to_string(), json!(string(entry, "fstype")));
    value.insert("encryption".to_string(), encryption);
    value.insert("mountpoint".to_string(), json!(mountpoint));
    value.insert("space".to_string(), space_usage(mountpoint.as_deref()));
    Value::Object(value)
}

fn space_usage(mountpoint: Option<&str>) -> Value {
    let Some(mountpoint) = mountpoint else {
        return Value::Null;
    };
    let output = match Command::new("df")
        .args(["-B1", "--output=size,used,avail", mountpoint])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Value::Null,
    };
    let fields: Vec<u64> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .nth(1)
        .into_iter()
        .flat_map(str::split_whitespace)
        .filter_map(|field| field.parse().ok())
        .collect();
    match fields.as_slice() {
        [size, used, available] => json!({
            "sizeBytes": size,
            "usedBytes": used,
            "availableBytes": available
        }),
        _ => Value::Null,
    }
}

fn mountpoints(entry: &Value) -> Vec<String> {
    entry
        .get("mountpoints")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter(|mount| !mount.is_empty())
        .map(str::to_string)
        .collect()
}

fn string<'a>(entry: &'a Value, key: &str) -> Option<&'a str> {
    entry
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}
