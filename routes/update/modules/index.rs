use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{harmonia, policy};
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};
use std::{collections::BTreeSet, fs, path::Path};

pub const NAMESPACE: &str = "update/modules";
const COMMAND: &str = "update modules list";

fn valid_module_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 96
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn modules_json() -> Result<Value, String> {
    let public = harmonia::load_profile_value()?;
    let profile_path = public
        .get("harmonia_profile")
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-harmonia-profile-missing".to_string())?;
    let text = fs::read_to_string(profile_path)
        .map_err(|_| "caduceus-harmonia-profile-unreadable".to_string())?;
    let profile: Value =
        serde_json::from_str(&text).map_err(|_| "caduceus-harmonia-profile-invalid".to_string())?;
    let enabled = profile
        .get("modules")
        .and_then(Value::as_array)
        .ok_or_else(|| "caduceus-harmonia-profile-modules-missing".to_string())?;
    let enabled_ids = enabled
        .iter()
        .filter_map(Value::as_str)
        .filter(|id| valid_module_id(id))
        .collect::<BTreeSet<_>>();
    let mut ids = enabled_ids
        .iter()
        .map(|id| (*id).to_string())
        .collect::<BTreeSet<_>>();
    let modules_dir = Path::new(profile_path)
        .parent()
        .ok_or_else(|| "caduceus-harmonia-profile-directory-missing".to_string())?
        .join("modules");
    for entry in fs::read_dir(modules_dir)
        .map_err(|_| "caduceus-harmonia-modules-directory-unreadable".to_string())?
    {
        let entry = entry.map_err(|_| "caduceus-harmonia-module-entry-unreadable".to_string())?;
        let manifest_path = entry.path().join("manifest.json");
        if !manifest_path.is_file() {
            continue;
        }
        let manifest: Value = match fs::read_to_string(manifest_path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
        {
            Some(v) => v,
            None => continue,
        };
        if let Some(id) = manifest.get("id").and_then(Value::as_str) {
            if valid_module_id(id) {
                ids.insert(id.to_string());
            }
        }
    }
    Ok(json!({
        "schema": "caduceus.update.modules.v1",
        "ok": true,
        "modules": ids
            .into_iter()
            .map(|id| json!({"id":id,"enabled":enabled_ids.contains(id.as_str())}))
            .collect::<Vec<_>>(),
        "firstMissingSignal": "none"
    }))
}

pub(crate) async fn route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(COMMAND) {
        Ok(true) => modules_json()
            .map(Json)
            .map_err(|e| api_error_signal(COMMAND, &e)),
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/update/modules", axum::routing::get(route))
}
