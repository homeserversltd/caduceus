use crate::shared::config;
use serde_json::{json, Value};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

fn write_index(path: &Path, rendered: &[u8]) -> Result<(), String> {
    let failure = |step: &str| format!("caduceus-harmonia-profile-write-failed:{step}");
    let unconfirmed = |step: &str| format!("caduceus-harmonia-profile-write-unconfirmed:{step}");
    let metadata = fs::metadata(path).map_err(|_| failure("metadata"))?;
    let dir = path.parent().ok_or_else(|| failure("directory"))?;
    let directory = File::open(dir).map_err(|_| failure("directory-open"))?;
    let temp = dir.join(format!(".index.json.{}.tmp", uuid::Uuid::new_v4()));
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(&temp).map_err(|_| failure("temp-create"))?;
    let result = (|| {
        let new_meta = file.metadata().map_err(|_| failure("temp-metadata"))?;
        if (new_meta.uid(), new_meta.gid()) != (metadata.uid(), metadata.gid()) {
            let rc = unsafe { libc::fchown(file.as_raw_fd(), metadata.uid(), metadata.gid()) };
            if rc != 0 { return Err(failure("ownership")); }
        }
        file.write_all(rendered).map_err(|_| failure("write"))?;
        file.set_permissions(fs::Permissions::from_mode(metadata.mode() & 0o7777))
            .map_err(|_| failure("mode"))?;
        file.sync_all().map_err(|_| failure("file-fsync"))?;
        fs::rename(&temp, path).map_err(|_| failure("rename"))?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }
    directory.sync_all().map_err(|_| unconfirmed("directory-fsync"))?;
    let readback = fs::read(path).map_err(|_| unconfirmed("readback"))?;
    if readback != rendered { return Err(unconfirmed("compare")); }
    Ok(())
}

fn valid_module_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub fn toggle_json(module_id: &str, enabled: bool) -> Result<Value, String> {
    if !valid_module_id(module_id) {
        return Err("caduceus-profile-module-id-invalid".to_string());
    }
    let profile_path = config::harmonia_profile_index_path()?;
    let path = config::path(&profile_path);
    let text = fs::read_to_string(&path)
        .map_err(|err| format!("caduceus-harmonia-profile-unreadable:{err}"))?;
    let mut json_value: Value =
        serde_json::from_str(&text).map_err(|_| "caduceus-harmonia-profile-invalid".to_string())?;
    let modules = json_value
        .get_mut("modules")
        .and_then(|modules| modules.as_array_mut())
        .ok_or_else(|| "caduceus-harmonia-profile-modules-missing".to_string())?;
    let existing = modules.iter_mut().find(|module| {
        module.as_str() == Some(module_id)
            || module.get("id").and_then(Value::as_str) == Some(module_id)
    });
    match existing {
        Some(Value::Object(object)) => {
            object.insert("enabled".to_string(), Value::Bool(enabled));
        }
        Some(_) if !enabled => modules.retain(|module| module.as_str() != Some(module_id)),
        None if enabled => modules.push(Value::String(module_id.to_string())),
        _ => {}
    }
    let rendered = serde_json::to_string_pretty(&json_value)
        .map_err(|_| "caduceus-harmonia-profile-render-failed".to_string())?
        + "\n";
    write_index(&path, rendered.as_bytes())?;
    Ok(json!({
        "schema": "caduceus.profile.module.toggle.v1",
        "ok": true,
        "moduleId": module_id,
        "enabled": enabled,
        "profilePath": profile_path,
        "firstMissingSignal": "none",
        "message": if enabled {
            format!("{module_id} enabled for the next Harmonia run.")
        } else {
            format!("{module_id} disabled for the next Harmonia run.")
        }
    }))
}

pub fn toggle(module_id: &str, state: &str) -> i32 {
    let enabled = match state {
        "on" => true,
        "off" => false,
        _ => {
            eprintln!("caduceus-public-action-not-allowed");
            return 2;
        }
    };
    match toggle_json(module_id, enabled) {
        Ok(value) => {
            println!("schema=caduceus.profile.module.toggle.v1");
            println!("ok=true");
            println!("module_id={module_id}");
            println!("enabled={enabled}");
            println!("first_missing_signal=none");
            if let Some(message) = value.get("message").and_then(Value::as_str) {
                println!("message={message}");
            }
            0
        }
        Err(err) => {
            eprintln!("caduceus-profile-module-toggle-failed: {err}");
            1
        }
    }
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/update/status",
            axum::routing::get(crate::routes::update_support::update_status_route),
        )
}
