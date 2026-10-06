// Read-only filtered block-device census for the appliance disk manager.
//
// The census deliberately invokes only `lsblk` and `df`. It never opens,
// mounts, formats, unlocks, or otherwise changes a block device.

use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
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
    crate::stats::disk_census::current()
}

/// Collector/explicit CLI observation, never called by the HTTP read path.
pub(crate) fn collect_json() -> Result<Value, String> {
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

    let space = space_usage();
    let mut census = Vec::new();
    for device in devices {
        if excluded_parent(device) {
            continue;
        }
        collect_candidates(device, device, &space, &mut census);
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
    match collect_json() {
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

fn collect_candidates(
    parent: &Value,
    entry: &Value,
    space: &BTreeMap<String, Value>,
    census: &mut Vec<Value>,
) {
    if mountpoints(entry)
        .iter()
        .any(|mount| HIDDEN_MOUNTS.contains(&mount.as_str()))
    {
        return;
    }
    let fstype = string(entry, "fstype").unwrap_or_default();
    let is_luks = fstype.eq_ignore_ascii_case("crypto_luks");
    if NAS_FILESYSTEMS.contains(&fstype) || is_luks {
        census.push(receipt(parent, entry, is_luks, space));
        return;
    }
    if let Some(children) = entry.get("children").and_then(Value::as_array) {
        for child in children {
            collect_candidates(parent, child, space, census);
        }
    }
}

fn receipt(
    parent: &Value,
    entry: &Value,
    locked_luks: bool,
    space: &BTreeMap<String, Value>,
) -> Value {
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
    value.insert(
        "space".to_string(),
        mountpoint
            .as_ref()
            .and_then(|mount| space.get(mount))
            .cloned()
            .unwrap_or(Value::Null),
    );
    Value::Object(value)
}

fn space_usage() -> BTreeMap<String, Value> {
    let mut usage = BTreeMap::new();
    let output = match Command::new("df")
        .env("LC_ALL", "C")
        .args(["-B1", "--all", "--output=size,used,avail,target"])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return usage,
    };
    for line in String::from_utf8_lossy(&output.stdout).lines().skip(1) {
        let mut rest = line;
        let mut numbers = Vec::with_capacity(3);
        for _ in 0..3 {
            let Some((field, remaining)) = rest.trim_start().split_once(char::is_whitespace) else {
                break;
            };
            let Ok(number) = field.parse::<u64>() else {
                break;
            };
            numbers.push(number);
            rest = remaining;
        }
        // Only numeric columns are split. The target remainder retains embedded spaces.
        let mount = rest.trim_start();
        if let [size, used, available] = numbers.as_slice() {
            if !mount.is_empty() {
                usage.insert(
                    mount.to_owned(),
                    json!({
                        "sizeBytes": size,
                        "usedBytes": used,
                        "availableBytes": available
                    }),
                );
            }
        }
    }
    usage
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

pub fn mutation_target_admitted(target: &str) -> Result<(), String> {
    let wanted = target
        .strip_prefix("/dev/")
        .filter(|name| {
            !name.is_empty()
                && name.len() <= 128
                && name.as_bytes()[0].is_ascii_alphanumeric()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
        })
        .ok_or_else(|| "caduceus-disk-device-invalid".to_string())?;
    // Custody must observe the device now, not admit against the UI's held snapshot.
    let census = collect_json()?;
    let admitted = census
        .get("devices")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|entry| {
            string(entry, "name") == Some(wanted) || string(entry, "partition") == Some(wanted)
        });
    if admitted {
        Ok(())
    } else {
        Err("caduceus-disk-target-census-excluded".to_string())
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/storage/disk/census",
            axum::routing::get(crate::routes::storage_support::disk_census_route),
        )
}
