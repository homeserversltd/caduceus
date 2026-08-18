use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::routes::{dhcp, dns_control, linker};
use crate::shared::hyalos;

const PROFILE_PATH: &str = "/usr/local/sbin/profile.json";

pub fn profile_json() -> Result<Value, String> {
    let profile = std::fs::read_to_string(PROFILE_PATH)
        .map_err(|err| format!("caduceus-staff-actuator-profile-unavailable: {err}"))?;
    serde_json::from_str(&profile)
        .map_err(|err| format!("caduceus-staff-actuator-profile-invalid: {err}"))
}

pub fn status_json() -> Result<Value, String> {
    let profile = profile_json()?;
    let staff = profile
        .get("staff")
        .cloned()
        .ok_or_else(|| "caduceus-staff-config-missing".to_string())?;
    let count = profile
        .get("actuators")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);
    Ok(json!({
        "schema": "caduceus.staff.status.v1",
        "ok": true,
        "staff": staff,
        "actuatorCount": count,
        "firstMissingSignal": "none"
    }))
}

pub fn actuators_json() -> Result<Value, String> {
    let profile = profile_json()?;
    let actuators = profile
        .get("actuators")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "caduceus-staff-catalog-missing".to_string())?;
    Ok(json!({
        "schema": "caduceus.staff.actuators.v1",
        "ok": true,
        "count": actuators.len(),
        "actuators": actuators,
        "firstMissingSignal": "none"
    }))
}

pub fn status() -> i32 {
    match status_json() {
        Ok(value) => {
            let staff = &value["staff"];
            println!("schema=caduceus.staff.status.v1");
            println!(
                "staff_user={}",
                staff.get("user").and_then(Value::as_str).unwrap_or("")
            );
            println!(
                "staff_home={}",
                staff.get("home").and_then(Value::as_str).unwrap_or("")
            );
            println!(
                "staff_venv={}",
                staff.get("venv").and_then(Value::as_str).unwrap_or("")
            );
            println!(
                "staff_lib_root={}",
                staff.get("libRoot").and_then(Value::as_str).unwrap_or("")
            );
            println!(
                "receipt_root={}",
                staff
                    .get("receiptRoot")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            );
            println!("actuator_count={}", value["actuatorCount"]);
            println!("first_missing_signal=none");
            0
        }
        Err(err) => {
            eprintln!("caduceus-staff-status-failed: {err}");
            1
        }
    }
}

pub fn actuators() -> i32 {
    match actuators_json() {
        Ok(value) => {
            println!("schema=caduceus.staff.actuators.v1");
            println!("count={}", value["count"]);
            if let Some(actuators) = value.get("actuators").and_then(Value::as_array) {
                for actuator in actuators {
                    println!(
                        "actuator={} family={} class={} launcher={} lib={} status={}",
                        actuator.get("id").and_then(Value::as_str).unwrap_or(""),
                        actuator.get("family").and_then(Value::as_str).unwrap_or(""),
                        actuator
                            .get("actuatorClass")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                        actuator
                            .get("launcher")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                        actuator
                            .get("libraryEntry")
                            .and_then(Value::as_str)
                            .unwrap_or(""),
                        actuator
                            .get("conversionStatus")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                    );
                }
            }
            0
        }
        Err(err) => {
            eprintln!("caduceus-staff-catalog-failed: {err}");
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
    let profile = profile_json()?;
    let actuator_count = profile
        .get("actuators")
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
    if class == "portal-service" {
        return execute_portal_service(metadata.unwrap_or_else(|| json!({})));
    }
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
        "linker" => linker::intent_json(metadata),
        id @ ("backblaze-b2-recover"
        | "backblaze-forgejo-b2-push"
        | "backblaze-forgejo-migrate"
        | "backblaze-config"
        | "calibre-helper-daemon"
        | "calibre-watch"
        | "keyman-doors"
        | "service-control-doors"
        | "disk-doors"
        | "wake-on-lan"
        | "child-device"
        | "nas-sync") => execute_registered_actuator(id, metadata),
        _ => Err("caduceus-staff-actuator-unmapped".to_string()),
    }
}

pub fn execute_registered_actuator(actuator_id: &str, metadata: Value) -> Result<Value, String> {
    let profile = profile_json()?;
    let actuator = profile
        .get("actuators")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("id").and_then(Value::as_str) == Some(actuator_id))
        })
        .ok_or_else(|| "caduceus-staff-actuator-unmapped".to_string())?;
    let launcher = actuator
        .get("launcher")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with('/') && !value.contains('\0'))
        .ok_or_else(|| "caduceus-staff-launcher-invalid".to_string())?;
    let input = serde_json::to_vec(&json!({"actuator":actuator_id,"metadata":metadata}))
        .map_err(|_| "caduceus-staff-request-invalid".to_string())?;
    let mut child = Command::new(&launcher)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "caduceus-staff-unavailable".to_string())?;
    use std::io::Write;
    child
        .stdin
        .take()
        .ok_or_else(|| "caduceus-staff-unavailable".to_string())?
        .write_all(&input)
        .map_err(|_| "caduceus-staff-unavailable".to_string())?;
    let output = child
        .wait_with_output()
        .map_err(|_| "caduceus-staff-unavailable".to_string())?;
    let receipt: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "caduceus-staff-invalid-receipt".to_string())?;
    if actuator_id == "backblaze-config"
        && receipt.get("ok").and_then(Value::as_bool) == Some(false)
    {
        return Ok(receipt);
    }
    if !output.status.success() || receipt.get("ok").and_then(Value::as_bool) == Some(false) {
        return Err(receipt
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-staff-refused")
            .to_string());
    }
    Ok(
        json!({"schema":"caduceus.staff.named_actuator.v1","ok":true,"accepted":true,"actuatorId":actuator_id,"receiptFamily":actuator.get("receiptFamily"),"receipt":receipt,"mutationPerformed":receipt.get("mutationPerformed").and_then(Value::as_bool).unwrap_or(true),"firstMissingSignal":"none"}),
    )
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
        "target": crate::protocol::TARGET_DEFAULT,
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
    let spool_root = PathBuf::from("/var/lib/caduceus/spool/file-ingress");
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

fn execute_portal_service(metadata: Value) -> Result<Value, String> {
    crate::routes::control_service::execute_service(metadata)
}

pub fn restart_registered_service(service: &str) -> Result<Value, String> {
    crate::routes::control_service::restart_registered_service(service)
}

fn execute_portal_service_with(metadata: Value, systemctl: &str) -> Result<Value, String> {
    crate::routes::control_service::execute_service_with(metadata, systemctl)
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

    #[test]
    fn portal_service_classification_executes_systemctl_and_reports_active() {
        let root =
            std::env::temp_dir().join(format!("caduceus-systemctl-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let profile_dir = root.join("etc/caduceus");
        std::fs::create_dir_all(&profile_dir).unwrap();
        std::fs::write(
            profile_dir.join("profile.yaml"),
            "schema: caduceus.profile.v1\nprofile: homeserver\n",
        )
        .unwrap();
        let config_dir = root.join("etc/appliance");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::write(config_dir.join("config.json"), r#"{"tabs":{"portals":{"data":{"portals":[{"name":"Jellyfin","services":["jellyfin"]}]}}}}"#).unwrap();
        let state_dir = root.join("var/lib/caduceus");
        std::fs::create_dir_all(&state_dir).unwrap();
        std::fs::write(
            state_dir.join("state.json"),
            r#"{"services":{"household_config":{"profile":"homeserver"}}}"#,
        )
        .unwrap();
        std::env::set_var("CADUCEUS_ROOT", &root);
        let systemctl = root.join("systemctl");
        std::fs::write(&systemctl, "#!/bin/sh\nif [ \"$1\" = is-active ]; then echo active; exit 0; else printf '%s %s\\n' \"$1\" \"$2\"; fi\n").unwrap();
        let mut permissions = std::fs::metadata(&systemctl).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&systemctl, permissions).unwrap();

        let result = execute_portal_service_with(
            json!({
                "service": "jellyfin",
                "action": "restart",
                "systemdService": "jellyfin.service"
            }),
            systemctl.to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(result["execution"], "systemctl");
        assert_eq!(result["output"], "restart jellyfin.service");
        assert_eq!(result["active"], true);
        assert_eq!(result["mutationPerformed"], true);
        let refused = execute_portal_service_with(
            json!({"service":"ssh","action":"restart","systemdService":"ssh.service"}),
            systemctl.to_str().unwrap(),
        );
        assert_eq!(refused.unwrap_err(), "caduceus-portal-service-not-allowed");
        std::env::remove_var("CADUCEUS_ROOT");
        let _ = std::fs::remove_dir_all(root);
    }
}

pub fn write_admitted_receipt(value: &Value) -> Result<(), String> {
    let body = serde_json::to_string(value)
        .map_err(|_| "caduceus-receipt-serialize-failed".to_string())?;
    crate::shared::receipts::write_latest(&body)
}
