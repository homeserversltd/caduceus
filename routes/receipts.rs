use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[cfg(leaf_portals_deploy)]
use crate::routes::linker;
use crate::routes::{dhcp, dns_control};
use crate::shared::hyalos;

pub fn status_json() -> Result<Value, String> {
    let declaration = crate::crossings::declaration()?;
    let observed_profile = crate::crossings::observed_profile()?;
    let band_count = declaration
        .get("bands")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let cli_probe = crate::gate::snake::probe_cli();
    let ok = cli_probe.get("ok").and_then(Value::as_bool) == Some(true);
    Ok(json!({
        "schema": "caduceus.staff.status.v1",
        "ok": ok,
        "profile": observed_profile,
        "declaration": declaration.get("profile").cloned().unwrap_or(Value::Null),
        "bandCount": band_count,
        "cliProbe": cli_probe,
        "firstMissingSignal": if ok { "none" } else { "caduceus-crossings-probe-failed" }
    }))
}

pub fn status() -> i32 {
    match status_json() {
        Ok(value) => {
            println!("schema=caduceus.staff.status.v1");
            println!("profile={}", value["profile"].as_str().unwrap_or(""));
            println!(
                "declaration={}",
                value["declaration"].as_str().unwrap_or("")
            );
            println!("band_count={}", value["bandCount"]);
            println!(
                "cli_probe={}",
                serde_json::to_string(&value["cliProbe"]).unwrap()
            );
            println!(
                "first_missing_signal={}",
                value["firstMissingSignal"]
                    .as_str()
                    .unwrap_or("caduceus-crossings-probe-failed")
            );
            if value["ok"] == true {
                0
            } else {
                1
            }
        }
        Err(err) => {
            eprintln!("caduceus-staff-status-failed: {err}");
            1
        }
    }
}

fn executable(path: &Path) -> bool {
    path.is_file()
        && std::fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
}

fn resolve_program(program: &str) -> Option<PathBuf> {
    let path = Path::new(program);
    if path.is_absolute() || program.contains('/') {
        return executable(path).then(|| path.to_path_buf());
    }
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|directory| directory.join(program))
            .find(|candidate| executable(candidate))
    })
}

fn special_program(noun: &str, verb: &str) -> Result<Option<PathBuf>, Value> {
    for (matches, variable) in [
        (noun == "time", "CADUCEUS_TIME_CMD"),
        (noun == "network" && verb == "dns", "CADUCEUS_DNS_CMD"),
    ] {
        if matches {
            let Some(command_line) = std::env::var_os(variable) else {
                continue;
            };
            let command_line = command_line.to_string_lossy();
            let Some(program) = command_line.split_whitespace().next() else {
                continue;
            };
            let program = program.to_string();
            return resolve_program(&program).map(Some).ok_or_else(|| {
                json!({"ok":false,"class":"resolve","exit":null,"stderr":format!("{variable} program unavailable: {program}")})
            });
        }
    }
    Ok(None)
}

fn selected_cli() -> Result<PathBuf, Value> {
    let cli = crate::gate::snake::cli_path();
    resolve_program(&cli.to_string_lossy()).ok_or_else(|| {
        json!({"ok":false,"class":"resolve","exit":null,"stderr":format!("agathodaimon cli unavailable: {}", cli.display())})
    })
}

fn child_names(index: &Value) -> Vec<String> {
    match index.get("children") {
        Some(Value::Object(children)) => children.keys().cloned().collect(),
        Some(Value::Array(children)) => children
            .iter()
            .filter_map(|child| match child {
                Value::String(name) => Some(name.clone()),
                Value::Object(child) => ["name", "noun", "verb", "namespace"]
                    .iter()
                    .find_map(|key| child.get(*key).and_then(Value::as_str).map(str::to_string)),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn shelf_component(noun: &str) -> &str {
    match noun {
        "cert" => "network/cert",
        "vault" => "storage/vault",
        "backup" => "storage/backup",
        "forgejo" => "storage/backup/forgejo",
        "time" => "settings/datetime",
        other => other,
    }
}

fn resolve_manifest_entry(noun: &str, verb: &str) -> Value {
    match special_program(noun, verb) {
        Ok(Some(program)) => {
            return json!({"ok":true,"resolution":"executable-program","program":program});
        }
        Ok(None) => {}
        Err(error) => return error,
    }
    if noun == "cert"
        && verb == "house-ca"
        && std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_none()
    {
        let program = Path::new("/usr/local/sbin/caduceus-house-ca");
        return if executable(program) {
            json!({"ok":true,"resolution":"executable-program","program":program})
        } else {
            json!({"ok":false,"class":"resolve","exit":null,"stderr":"caduceus-house-ca unavailable"})
        };
    }
    let cli = match selected_cli() {
        Ok(path) => path,
        Err(error) => return error,
    };
    let root = cli.parent().unwrap_or_else(|| Path::new("."));
    let components = shelf_component(noun)
        .split('/')
        .chain(std::iter::once(verb));
    let mut current = root.to_path_buf();
    for component in components {
        let index_path = current.join("index.json");
        let index_text = match std::fs::read_to_string(&index_path) {
            Ok(text) => text,
            Err(error) => {
                return json!({"ok":false,"class":"resolve","exit":null,"stderr":error.to_string()})
            }
        };
        let index: Value = match serde_json::from_str(&index_text) {
            Ok(value) => value,
            Err(error) => {
                return json!({"ok":false,"class":"resolve","exit":null,"stderr":error.to_string()})
            }
        };
        if !child_names(&index).iter().any(|name| name == component) {
            return json!({"ok":false,"class":"resolve","exit":null,"stderr":format!("missing shelf child: {component}")});
        }
        current.push(component);
    }
    let seat = current.join("index.py");
    if !seat.is_file() {
        return json!({"ok":false,"class":"resolve","exit":null,"stderr":format!("missing seat index.py: {}", seat.display())});
    }
    json!({"ok":true,"class":Value::Null,"exit":null,"stderr":"","seat":seat})
}

pub fn crossings_json() -> Result<Value, String> {
    let manifest = crate::protocol::seat()?
        .get("crossings")
        .and_then(Value::as_object)
        .and_then(|value| value.get("entries"))
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "caduceus-crossings-manifest-missing".to_string())?;
    if manifest.is_empty() {
        return Err("caduceus-crossings-manifest-empty".to_string());
    }
    let sentinel = crate::gate::snake::probe_cli();
    let mut observed = Vec::new();
    let mut all_ok = sentinel.get("ok").and_then(Value::as_bool) == Some(true);
    for (index, entry) in manifest.into_iter().enumerate() {
        let object = entry
            .as_object()
            .ok_or_else(|| format!("caduceus-crossings-manifest-entry-invalid:{index}"))?;
        if object.len() != 2 || !object.contains_key("noun") || !object.contains_key("verb") {
            return Err(format!("caduceus-crossings-manifest-entry-invalid:{index}"));
        }
        let noun = object
            .get("noun")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("caduceus-crossings-manifest-entry-invalid:{index}:noun"))?;
        let verb = object
            .get("verb")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("caduceus-crossings-manifest-entry-invalid:{index}:verb"))?;
        let result = resolve_manifest_entry(noun, verb);
        let ok = result.get("ok").and_then(Value::as_bool) == Some(true);
        all_ok &= ok;
        let mut step = json!({"noun":noun,"verb":verb,"attempt":1,"ok":ok,"result":result});
        if !ok {
            step["class"] = result.get("class").cloned().unwrap_or(Value::Null);
            step["exit"] = result.get("exit").cloned().unwrap_or(Value::Null);
            step["stderr"] = result
                .get("stderr")
                .cloned()
                .unwrap_or(Value::String(String::new()));
        }
        observed.push(step);
    }
    let summary = hyalos::reflect_json(json!({
        "organ":"agathodaimon",
        "kind":"crossings-self-check",
        "level": if all_ok { "info" } else { "error" },
        "ok":all_ok,
        "message":"agathodaimon crossings self-check",
        "attributes_redacted":{"entryCount":observed.len(),"ok":all_ok}
    }))
    .unwrap_or_else(|error| json!({"ok":false,"firstMissingSignal":error}));
    Ok(json!({
        "schema":"caduceus.staff.crossings.v1",
        "observed":observed,
        "sentinel":sentinel,
        "couldChange":false,
        "attemptPerStep":true,
        "final":{"resolved":all_ok,"firstMissingSignal":if all_ok {"none"} else {"caduceus-crossings-probe-failed"}},
        "ok":all_ok,
        "hyalos":summary,
        "firstMissingSignal":if all_ok {"none"} else {"caduceus-crossings-probe-failed"}
    }))
}

pub fn crossings() -> i32 {
    match crossings_json() {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            if value["ok"] == true {
                0
            } else {
                1
            }
        }
        Err(error) => {
            eprintln!("caduceus-staff-crossings-failed: {error}");
            1
        }
    }
}

pub fn intent_json(
    method: &str,
    route: &str,
    classification: Option<&str>,
    metadata: Option<Value>,
) -> Result<Value, String> {
    if route == "/api/files/upload"
        && method == "POST"
        && metadata
            .as_ref()
            .and_then(|value| value.get("payload"))
            .and_then(Value::as_array)
            .is_some()
    {
        return execute_file_ingress(metadata.unwrap_or_else(|| json!({})));
    }
    let declaration = crate::crossings::declaration()?;
    let actuator_count = declaration
        .get("bands")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    let mut privileged = method != "GET" && method != "HEAD" && method != "OPTIONS";
    if route.contains("/admin/")
        || route.contains("/status/vpn")
        || route.contains("/status/tailscale")
        || route.contains("/upload/")
        || route.contains("/service/control")
    {
        privileged = true;
    }
    let class = classification.unwrap_or(if privileged {
        "privileged-mutation"
    } else {
        "readback"
    });
    if route.starts_with("/api/dhcp/") || route == "/api/dhcp" {
        return dhcp::intent_json(method, route, metadata.unwrap_or_else(|| json!({})));
    }
    if route.starts_with("/api/dns/") || route == "/api/dns" {
        return dns_control::intent_json(method, route, metadata.unwrap_or_else(|| json!({})));
    }
    if route == "/api/upload/force-permissions" && method == "POST" {
        return execute_force_permissions(metadata.unwrap_or_else(|| json!({})));
    }
    let upload = if route.contains("/api/files/upload") || route.contains("/api/upload/") {
        json!({
            "schema": "caduceus.staff.upload_intent.v1",
            "accepted": true,
            "metadata": metadata.clone().unwrap_or_else(|| json!({})),
            "destination": metadata
                .as_ref()
                .and_then(|value| value.get("destination"))
                .cloned()
                .unwrap_or_else(|| json!("/mnt/nas")),
            "nextBoundary": "typed upload actuator writes payload and receipt"
        })
    } else {
        Value::Null
    };
    Ok(json!({
        "schema": "caduceus.staff.intent.v1",
        "ok": true,
        "accepted": true,
        "method": method,
        "route": route,
        "classification": class,
        "privileged": privileged,
        "actuatorCount": actuator_count,
        "authority": "Caduceus staff membrane received the Coronatio Rust website route intent",
        "mutationPerformed": false,
        "upload": upload,
        "metadata": metadata.unwrap_or_else(|| json!({})),
        "execution": if route.contains("/api/files/upload") { "upload-queued-behind-typed-actuator" } else if privileged { "queued-behind-typed-actuator" } else { "readback-only" },
        "firstMissingSignal": if privileged && actuator_count == 0 { "caduceus-staff-actuator-missing" } else { "none" },
        "nextBoundary": if route.contains("/api/files/upload") { "typed upload actuator execution receipt" } else if privileged { "typed staff actuator execution receipt" } else { "Coronatio readback route" }
    }))
}

pub fn named_actuator_json(actuator_id: &str, metadata: Value) -> Result<Value, String> {
    match actuator_id {
        "storage/upload/ingress" => execute_file_ingress(metadata),
        "storage/upload/force-permissions" => execute_force_permissions(metadata),
        "network-dhcp" => dhcp::intent_json("POST", "/api/dhcp/reservations", metadata),
        #[cfg(leaf_portals_deploy)]
        "linker" => linker::intent_json(metadata),
        "backblaze-b2-recover" => staff_actuator_receipt(
            "backblaze-b2-recover",
            "storage/backup/backblaze-recover",
            metadata,
        ),
        "backblaze-forgejo-b2-push" => staff_actuator_receipt(
            "backblaze-forgejo-b2-push",
            "storage/backup/forgejo/backup-b2",
            metadata,
        ),
        "backblaze-forgejo-migrate" => staff_actuator_receipt(
            "backblaze-forgejo-migrate",
            "storage/backup/forgejo/migrate",
            metadata,
        ),
        "backblaze-config" => staff_actuator_receipt(
            "backblaze-config",
            "storage/backup/backblaze-config",
            metadata,
        ),
        "calibre-helper-daemon" => {
            staff_actuator_receipt("calibre-helper-daemon", "portals/calibre", metadata)
        }
        "calibre-watch" => staff_actuator_receipt("calibre-watch", "portals/calibre", metadata),
        "keyman-doors" => staff_actuator_receipt("keyman-doors", "storage/vault/keyman", metadata),
        "service-control-doors" => {
            staff_actuator_receipt("service-control-doors", "portals/service-control", metadata)
        }
        "disk-doors" => staff_actuator_receipt("disk-doors", "storage/disk-doors", metadata),
        "wake-on-lan" => staff_actuator_receipt("wake-on-lan", "network/wake-on-lan", metadata),
        "child-device" => staff_actuator_receipt("child-device", "network/child-device", metadata),
        "nas-sync" => staff_actuator_receipt("nas-sync", "storage/backup/nas-sync", metadata),
        _ => Err("caduceus-staff-actuator-unmapped".to_string()),
    }
}

fn staff_actuator_receipt(actuator_id: &str, band: &str, metadata: Value) -> Result<Value, String> {
    let walked = if matches!(
        actuator_id,
        "backblaze-forgejo-b2-push" | "backblaze-forgejo-migrate"
    ) {
        crate::gate::snake::crossing_path_with_timeout(band, &metadata, Duration::from_secs(30))?
    } else {
        let input = json!({"actuator": actuator_id, "metadata": metadata});
        let envelope = json!({
            "schema": crate::protocol::SCHEMA_ID,
            "intent_id": format!("caduceus-{band}"),
            "transition": band,
            "origin_of_intent": "near",
            "payload": input.clone(),
            "actuator": actuator_id,
            "metadata": input["metadata"].clone(),
        });
        crate::gate::snake::run(band, &envelope)?
    };
    let receipt = walked
        .get("receiptPayload")
        .cloned()
        .filter(Value::is_object)
        .ok_or_else(|| "caduceus-staff-invalid-receipt".to_string())?;
    if actuator_id == "backblaze-config"
        && receipt.get("ok").and_then(Value::as_bool) == Some(false)
    {
        return Ok(receipt);
    }
    if walked.get("ok").and_then(Value::as_bool) != Some(true)
        || receipt.get("ok").and_then(Value::as_bool) == Some(false)
    {
        return Err(receipt
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-staff-refused")
            .to_string());
    }
    Ok(receipt)
}

fn ingress_root() -> PathBuf {
    std::env::var_os("CADUCEUS_FILE_INGRESS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/mnt/nas"))
}

fn admitted_destination(metadata: &Value) -> Result<PathBuf, String> {
    let root = ingress_root();
    let requested = metadata
        .get("destination")
        .and_then(Value::as_str)
        .unwrap_or("/mnt/nas");
    let relative = if requested == "/mnt/nas" || requested == root.to_string_lossy() {
        Path::new("")
    } else if let Some(value) = requested.strip_prefix("/mnt/nas/") {
        Path::new(value)
    } else if let Ok(value) = Path::new(requested).strip_prefix(&root) {
        value
    } else {
        return Err("caduceus-file-ingress-destination-outside-root".to_string());
    };
    if relative
        .components()
        .any(|part| !matches!(part, std::path::Component::Normal(_)))
        && !relative.as_os_str().is_empty()
    {
        return Err("caduceus-file-ingress-destination-invalid".to_string());
    }
    Ok(root.join(relative))
}

pub fn file_ingress_target(path: &str) -> Result<PathBuf, String> {
    let root = ingress_root();
    let relative = if path == "/mnt/nas" || path == root.to_string_lossy() {
        Path::new("")
    } else if let Some(value) = path.strip_prefix("/mnt/nas/") {
        Path::new(value)
    } else if let Ok(value) = Path::new(path).strip_prefix(&root) {
        value
    } else {
        return Err("caduceus-file-ingress-destination-outside-root".to_string());
    };
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
    {
        return Err("caduceus-file-ingress-destination-invalid".to_string());
    }
    Ok(root.join(relative))
}

fn staff_band_receipt(band: &str, metadata: Value) -> Result<Value, String> {
    let envelope = json!({
        "schema": crate::protocol::SCHEMA_ID,
        "intent_id": format!("caduceus-{band}"),
        "transition": band,
        "origin_of_intent": "near",
        "metadata": metadata,
    });
    let walked = match crate::gate::snake::run(band, &envelope) {
        Ok(walked) => walked,
        Err(signal) => {
            return Ok(json!({
                "schema": "caduceus.staff.v1",
                "ok": false,
                "mutationPerformed": false,
                "bandPath": band,
                "firstMissingSignal": signal,
            }));
        }
    };
    let caduceus = walked
        .get("envelope")
        .and_then(|value| value.get("caduceusReceipt"))
        .ok_or_else(|| "caduceus-snake-receipt-missing".to_string())?;
    let receipt = caduceus
        .get("stepReceipt")
        .cloned()
        .ok_or_else(|| "caduceus-snake-staff-receipt-missing".to_string())?;
    if walked.get("ok").and_then(Value::as_bool) != Some(true) {
        return Ok(json!({
            "schema": "caduceus.staff.v1",
            "ok": false,
            "bandPath": band,
            "staffReceipt": receipt,
            "firstMissingSignal": walked
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .unwrap_or("caduceus-agathodaimon-refused")
        }));
    }
    Ok(receipt)
}

fn staff_mutation_performed(receipt: &Value) -> bool {
    receipt
        .get("mutationPerformed")
        .and_then(Value::as_bool)
        .unwrap_or(true)
}

fn file_ingress_reflection(target: &Path, bytes: usize) -> Result<Value, String> {
    let filename = target
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| "caduceus-file-ingress-filename-invalid".to_string())?;
    let destination = target
        .parent()
        .ok_or_else(|| "caduceus-file-ingress-destination-invalid".to_string())?;
    hyalos::reflect_json(json!({
        "organ": "file-ingress",
        "kind": "upload",
        "level": "info",
        "ok": true,
        "message": format!("uploaded {filename}"),
        "attributes_redacted": {
            "classification": "file-ingress",
            "filename": filename,
            "destination": destination,
            "path": target,
            "bytes": bytes
        }
    }))
}

#[cfg(test)]
pub fn file_ingress_open(path: &str) -> Result<(std::fs::File, PathBuf), String> {
    let target = file_ingress_target(path)?;
    let parent = target
        .parent()
        .ok_or_else(|| "caduceus-file-ingress-destination-invalid".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|err| format!("caduceus-file-ingress-create-destination-failed: {err}"))?;
    let file = std::fs::File::create(&target)
        .map_err(|err| format!("caduceus-file-ingress-write-failed: {err}"))?;
    Ok((file, target))
}

#[cfg(test)]
pub fn file_ingress_receipt(target: &Path, bytes: usize) -> Result<Value, String> {
    let reflection = file_ingress_reflection(target, bytes)?;
    Ok(
        json!({"schema":"caduceus.staff.file_ingress.v1","ok":true,"accepted":true,"classification":"file-ingress","mutationPerformed":true,"execution":"staff-snake","path":target,"bytes":bytes,"hyalos":reflection,"firstMissingSignal":"none"}),
    )
}

fn execute_file_ingress(metadata: Value) -> Result<Value, String> {
    let destination = admitted_destination(&metadata)?;
    let filename = metadata
        .get("filename")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-file-ingress-filename-missing".to_string())?;
    if filename.is_empty()
        || Path::new(filename).file_name().and_then(|v| v.to_str()) != Some(filename)
    {
        return Err("caduceus-file-ingress-filename-invalid".to_string());
    }
    let bytes = metadata
        .get("payload")
        .and_then(Value::as_array)
        .ok_or_else(|| "caduceus-file-ingress-payload-missing".to_string())?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|v| *v <= 255)
                .map(|v| v as u8)
                .ok_or_else(|| "caduceus-file-ingress-payload-invalid".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let target = destination.join(filename);
    let mode = metadata
        .get("mode")
        .and_then(Value::as_u64)
        .unwrap_or(0o664);
    let supplied_uid = metadata.get("uid").and_then(Value::as_u64);
    let supplied_gid = metadata.get("gid").and_then(Value::as_u64);
    let spool_root = std::env::var_os("CADUCEUS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
        .join("var/lib/caduceus/spool/file-ingress");
    std::fs::create_dir_all(&spool_root)
        .map_err(|err| format!("caduceus-file-ingress-spool-unavailable: {err}"))?;
    let spool_path = spool_root.join(format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "caduceus-file-ingress-spool-clock-invalid".to_string())?
            .as_nanos()
    ));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&spool_path)
        .map_err(|err| format!("caduceus-file-ingress-spool-open-failed: {err}"))?;
    file.write_all(&bytes)
        .map_err(|err| format!("caduceus-file-ingress-spool-write-failed: {err}"))?;
    let mut request = metadata;
    let object = request
        .as_object_mut()
        .ok_or_else(|| "caduceus-file-ingress-request-invalid".to_string())?;
    object.remove("payload");
    object.insert("spoolPath".into(), json!(spool_path));
    object.insert("path".into(), json!(target));
    object.insert("targetPath".into(), json!(target));
    object.insert("mode".into(), json!(mode));
    if let Some(uid) = supplied_uid {
        object.insert("uid".into(), json!(uid));
    }
    if let Some(gid) = supplied_gid {
        object.insert("gid".into(), json!(gid));
    }
    let staff = staff_band_receipt("storage/upload/ingress", request)?;
    let _ = std::fs::remove_file(&spool_path);
    let ok = staff.get("ok").and_then(Value::as_bool) == Some(true);
    let mutation_performed = ok && staff_mutation_performed(&staff);
    let signal = staff.get("firstMissingSignal").cloned().unwrap_or_else(|| {
        json!(if ok {
            "none"
        } else {
            "caduceus-agathodaimon-refused"
        })
    });
    let hyalos = if ok {
        file_ingress_reflection(&target, bytes.len())?
    } else {
        Value::Null
    };
    Ok(
        json!({"schema":"caduceus.staff.file_ingress.v1","ok":ok,"accepted":ok,"classification":"file-ingress","mutationPerformed":mutation_performed,"execution":if ok {"staff-snake"} else {"staff-snake-refused"},"path":target,"bytes":bytes.len(),"hyalos":hyalos,"staffReceipt":staff,"firstMissingSignal":signal}),
    )
}

pub fn execute_spooled_file_ingress(
    mut metadata: Value,
    spool_path: &Path,
    target: &Path,
    bytes: u64,
) -> Result<Value, String> {
    let mode = metadata
        .get("mode")
        .and_then(Value::as_u64)
        .unwrap_or(0o664);
    let supplied_uid = metadata.get("uid").and_then(Value::as_u64);
    let supplied_gid = metadata.get("gid").and_then(Value::as_u64);
    let object = metadata
        .as_object_mut()
        .ok_or_else(|| "caduceus-file-ingress-request-invalid".to_string())?;
    object.remove("payload");
    object.insert("spoolPath".into(), json!(spool_path));
    object.insert("path".into(), json!(target));
    object.insert("targetPath".into(), json!(target));
    object.insert("mode".into(), json!(mode));
    if let Some(uid) = supplied_uid {
        object.insert("uid".into(), json!(uid));
    }
    if let Some(gid) = supplied_gid {
        object.insert("gid".into(), json!(gid));
    }
    let staff_result = staff_band_receipt("storage/upload/ingress", metadata);
    let _ = std::fs::remove_file(spool_path);
    let staff = staff_result?;
    let ok = staff.get("ok").and_then(Value::as_bool) == Some(true);
    let mutation_performed = ok && staff_mutation_performed(&staff);
    let signal = staff.get("firstMissingSignal").cloned().unwrap_or_else(|| {
        json!(if ok {
            "none"
        } else {
            "caduceus-agathodaimon-refused"
        })
    });
    let hyalos = if ok {
        let bytes = usize::try_from(bytes)
            .map_err(|_| "caduceus-file-ingress-byte-count-invalid".to_string())?;
        file_ingress_reflection(target, bytes)?
    } else {
        Value::Null
    };
    Ok(
        json!({"schema":"caduceus.staff.file_ingress.v1","ok":ok,"accepted":ok,"classification":"file-ingress","mutationPerformed":mutation_performed,"execution":if ok {"staff-snake"} else {"staff-snake-refused"},"path":target,"bytes":bytes,"hyalos":hyalos,"staffReceipt":staff,"firstMissingSignal":signal}),
    )
}

fn execute_force_permissions(metadata: Value) -> Result<Value, String> {
    let destination = admitted_destination(&metadata)?;
    if !destination.is_dir() {
        return Err("caduceus-force-permissions-directory-missing".to_string());
    }
    let mode = metadata
        .get("mode")
        .and_then(Value::as_u64)
        .unwrap_or(0o775);
    let mut request = metadata;
    let object = request
        .as_object_mut()
        .ok_or_else(|| "caduceus-force-permissions-request-invalid".to_string())?;
    object.insert("destination".into(), json!(destination));
    object.insert("directory".into(), json!(destination));
    object.insert("path".into(), json!(destination));
    object.insert("mode".into(), json!(mode));
    let staff = staff_band_receipt("storage/upload/force-permissions", request)?;
    let ok = staff.get("ok").and_then(Value::as_bool) == Some(true);
    let mutation_performed = ok && staff_mutation_performed(&staff);
    let signal = staff.get("firstMissingSignal").cloned().unwrap_or_else(|| {
        json!(if ok {
            "none"
        } else {
            "caduceus-agathodaimon-refused"
        })
    });
    Ok(
        json!({"schema":"caduceus.staff.force_permissions.v1","ok":ok,"success":ok,"message":if ok {"Permissions updated successfully"} else {"Permissions update refused"},"accepted":ok,"classification":"force-permissions","mutationPerformed":mutation_performed,"execution":if ok {"staff-snake"} else {"staff-snake-refused"},"path":destination,"staffReceipt":staff,"firstMissingSignal":signal}),
    )
}

#[cfg(test)]
fn execute_force_permissions_with(
    metadata: Value,
    _getent: &str,
    _groups: &str,
    _usermod: &str,
) -> Result<Value, String> {
    execute_force_permissions(metadata)
}

pub fn execute_registered_service(service: &str, action: &str) -> Result<Value, String> {
    crate::routes::control_service::execute_registered_service(service, action)
}

pub fn intent(method: &str, route: &str) -> i32 {
    match intent_json(method, route, None, None) {
        Ok(value) => {
            println!("{}", serde_json::to_string_pretty(&value).unwrap());
            0
        }
        Err(err) => {
            eprintln!("caduceus-staff-intent-failed: {err}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    static FILE_INGRESS_ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn file_ingress_and_force_permissions_execute_real_mutations() {
        let _guard = FILE_INGRESS_ENV_LOCK.lock().unwrap();
        let root =
            std::env::temp_dir().join(format!("caduceus-file-ingress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("CADUCEUS_ROOT", &root);
        std::env::set_var("CADUCEUS_FILE_INGRESS_ROOT", &root);
        let result = intent_json("POST", "/api/files/upload", Some("file-ingress"), Some(json!({"filename":"proof.txt","destination":"/mnt/nas/test","payload":[104,101,108,108,111]}))).unwrap();
        assert_eq!(result["mutationPerformed"], true);
        assert_eq!(
            std::fs::read(root.join("test/proof.txt")).unwrap(),
            b"hello"
        );

        let tools = root.join("tools");
        std::fs::create_dir_all(&tools).unwrap();
        let calls = root.join("usermod-calls");
        let getent = tools.join("getent");
        let groups = tools.join("groups");
        let usermod = tools.join("usermod");
        std::fs::write(
            &getent,
            "#!/bin/sh\nprintf 'fixture-group:x:%s:\\n' \"$2\"\n",
        )
        .unwrap();
        std::fs::write(&groups, "#!/bin/sh\nprintf 'www-data : www-data\\n'\n").unwrap();
        std::fs::write(
            &usermod,
            format!("#!/bin/sh\nprintf '%s\\n' \"$*\" > {}\n", calls.display()),
        )
        .unwrap();
        for tool in [&getent, &groups, &usermod] {
            let mut permissions = std::fs::metadata(tool).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(tool, permissions).unwrap();
        }

        let result = execute_force_permissions_with(
            json!({"destination":"/mnt/nas/test"}),
            getent.to_str().unwrap(),
            groups.to_str().unwrap(),
            usermod.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(result["mutationPerformed"], true);
        assert_eq!(result["success"], true);
        assert_eq!(result["message"], "Permissions updated successfully");
        assert_eq!(
            std::fs::read_to_string(&calls).unwrap().trim(),
            "-aG fixture-group www-data"
        );
        assert_eq!(
            std::fs::metadata(root.join("test"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o775
        );
        std::env::remove_var("CADUCEUS_FILE_INGRESS_ROOT");
        std::env::remove_var("CADUCEUS_ROOT");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn force_permissions_reports_group_failure_after_writable_mutation() {
        let _guard = FILE_INGRESS_ENV_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "caduceus-force-permissions-failure-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let destination = root.join("test");
        std::fs::create_dir_all(&destination).unwrap();
        let mut permissions = std::fs::metadata(&destination).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&destination, permissions).unwrap();
        std::env::set_var("CADUCEUS_ROOT", &root);
        std::env::set_var("CADUCEUS_FILE_INGRESS_ROOT", &root);

        let failed = root.join("failed-command");
        std::fs::write(
            &failed,
            "#!/bin/sh\nprintf 'fixture failure\\n' >&2\nexit 1\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&failed).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&failed, permissions).unwrap();

        let error = execute_force_permissions_with(
            json!({"destination":"/mnt/nas/test"}),
            failed.to_str().unwrap(),
            failed.to_str().unwrap(),
            failed.to_str().unwrap(),
        )
        .unwrap_err();
        assert!(error.starts_with("Group update failed: group resolution failed"));
        assert_eq!(
            std::fs::metadata(&destination)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o775
        );

        std::env::remove_var("CADUCEUS_FILE_INGRESS_ROOT");
        std::env::remove_var("CADUCEUS_ROOT");
        let _ = std::fs::remove_dir_all(root);
    }
}

pub fn write_admitted_receipt(value: &Value) -> Result<(), String> {
    let body = serde_json::to_string(value)
        .map_err(|_| "caduceus-receipt-serialize-failed".to_string())?;
    crate::shared::receipts::write_latest(&body)
}
