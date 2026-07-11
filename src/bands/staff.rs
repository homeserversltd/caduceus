use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::bands::dhcp;

const PROFILE: &str = include_str!("../../data/staff-actuators/profile.json");

pub fn profile_json() -> Result<Value, String> {
    serde_json::from_str(PROFILE)
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
        .ok_or_else(|| "caduceus-staff-actuators-missing".to_string())?;
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
            eprintln!("caduceus-staff-actuators-failed: {err}");
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
    std::fs::create_dir_all(&destination)
        .map_err(|err| format!("caduceus-file-ingress-create-destination-failed: {err}"))?;
    let target = destination.join(filename);
    std::fs::write(&target, &bytes)
        .map_err(|err| format!("caduceus-file-ingress-write-failed: {err}"))?;
    Ok(
        json!({"schema":"caduceus.staff.file_ingress.v1","ok":true,"accepted":true,"classification":"file-ingress","mutationPerformed":true,"execution":"native-rust-file-ingress","path":target,"bytes":bytes.len(),"firstMissingSignal":"none"}),
    )
}

fn execute_force_permissions(metadata: Value) -> Result<Value, String> {
    let destination = admitted_destination(&metadata)?;
    if !destination.is_dir() {
        return Err("caduceus-force-permissions-directory-missing".to_string());
    }
    let mut permissions = std::fs::metadata(&destination)
        .map_err(|err| err.to_string())?
        .permissions();
    permissions.set_mode(0o775);
    std::fs::set_permissions(&destination, permissions)
        .map_err(|err| format!("caduceus-force-permissions-failed: {err}"))?;
    Ok(
        json!({"schema":"caduceus.staff.force_permissions.v1","ok":true,"accepted":true,"classification":"force-permissions","mutationPerformed":true,"execution":"native-rust-force-permissions","path":destination,"firstMissingSignal":"none"}),
    )
}

fn execute_portal_service(metadata: Value) -> Result<Value, String> {
    let systemctl =
        std::env::var("CADUCEUS_SYSTEMCTL_BIN").unwrap_or_else(|_| "systemctl".to_string());
    execute_portal_service_with(metadata, &systemctl)
}

fn execute_portal_service_with(metadata: Value, systemctl: &str) -> Result<Value, String> {
    let service = metadata
        .get("service")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-portal-service-name-missing".to_string())?;
    let action = metadata
        .get("action")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-portal-service-action-missing".to_string())?;
    let systemd_service = metadata
        .get("systemdService")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-portal-systemd-service-missing".to_string())?;
    if !safe_service_name(service)
        || !safe_service_name(systemd_service)
        || !matches!(
            action,
            "start" | "stop" | "restart" | "enable" | "disable" | "status"
        )
    {
        return Err("caduceus-portal-service-intent-invalid".to_string());
    }

    let output = Command::new(systemctl)
        .args([action, systemd_service])
        .output()
        .map_err(|err| format!("caduceus-portal-systemctl-exec-failed: {err}"))?;
    let active_output = Command::new(&systemctl)
        .args(["is-active", systemd_service])
        .output()
        .map_err(|err| format!("caduceus-portal-systemctl-active-failed: {err}"))?;
    let command_output = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    };
    let active = active_output.status.success()
        && String::from_utf8_lossy(&active_output.stdout).trim() == "active";

    Ok(json!({
        "schema": "caduceus.staff.portal_service.v1",
        "ok": output.status.success(),
        "accepted": true,
        "classification": "portal-service",
        "service": service,
        "action": action,
        "systemdService": systemd_service,
        "success": output.status.success(),
        "message": if output.status.success() { format!("Service {action} completed for {service}") } else { format!("Service {action} failed for {service}") },
        "output": command_output,
        "active": active,
        "mutationPerformed": action != "status" && output.status.success(),
        "execution": "systemctl",
        "firstMissingSignal": if output.status.success() { "none" } else { "portal-systemctl-command-failed" },
        "metadata": metadata
    }))
}

fn safe_service_name(value: &str) -> bool {
    !value.is_empty()
        && !value.contains("..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
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

    #[test]
    fn file_ingress_and_force_permissions_execute_real_mutations() {
        let root =
            std::env::temp_dir().join(format!("caduceus-file-ingress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("CADUCEUS_FILE_INGRESS_ROOT", &root);
        let result = intent_json("POST", "/api/files/upload", Some("file-ingress"), Some(json!({"filename":"proof.txt","destination":"/mnt/nas/test","payload":[104,101,108,108,111]}))).unwrap();
        assert_eq!(result["mutationPerformed"], true);
        assert_eq!(
            std::fs::read(root.join("test/proof.txt")).unwrap(),
            b"hello"
        );
        let result = intent_json(
            "POST",
            "/api/upload/force-permissions",
            Some("force-permissions"),
            Some(json!({"destination":"/mnt/nas/test"})),
        )
        .unwrap();
        assert_eq!(result["mutationPerformed"], true);
        assert_eq!(
            std::fs::metadata(root.join("test"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o775
        );
        std::env::remove_var("CADUCEUS_FILE_INGRESS_ROOT");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn portal_service_classification_executes_systemctl_and_reports_active() {
        let root =
            std::env::temp_dir().join(format!("caduceus-systemctl-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
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
        let _ = std::fs::remove_dir_all(root);
    }
}
