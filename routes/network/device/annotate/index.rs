// Durable, Caduceus-owned Stats device notes.
//
// Notes live in the Caduceus state document, never in the retired HOMESERVER
// configuration surface. The public mapping is MAC-keyed and contains only
// ordinary note text.

use crate::shared::config;
use crate::shared::config as paths;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::{Mutex, OnceLock};

const STATE_PATH: &str = "var/lib/caduceus/state.json";
const NOTES_KEY: &str = "networkNotes";
const MAX_NOTE_BYTES: usize = 4096;
const STATE_FILE_MODE: u32 = 0o640;

fn write_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn normalize_mac(mac: &str) -> Result<String, String> {
    let octets: Vec<&str> = mac.split([':', '-']).collect();
    if octets.len() != 6
        || octets
            .iter()
            .any(|octet| octet.len() != 2 || !octet.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("caduceus-network-notes-mac-invalid".to_string());
    }
    Ok(octets
        .into_iter()
        .map(|octet| octet.to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(":"))
}

fn validate_note(note: &str) -> Result<(), String> {
    if note.len() > MAX_NOTE_BYTES || note.contains('\0') {
        return Err("caduceus-network-notes-note-invalid".to_string());
    }
    Ok(())
}

fn read_state() -> Result<Value, String> {
    let path = paths::path(STATE_PATH);
    if !path.exists() {
        return Ok(Value::Object(Map::new()));
    }
    let text = fs::read_to_string(path)
        .map_err(|_| "caduceus-network-notes-state-unreadable".to_string())?;
    serde_json::from_str(&text).map_err(|_| "caduceus-network-notes-state-invalid".to_string())
}

fn notes_from(state: &Value) -> Result<BTreeMap<String, String>, String> {
    let Some(value) = state.get(NOTES_KEY) else {
        return Ok(BTreeMap::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| "caduceus-network-notes-state-invalid".to_string())?;
    object
        .iter()
        .map(|(mac, note)| {
            let mac = normalize_mac(mac)?;
            let note = note
                .as_str()
                .ok_or_else(|| "caduceus-network-notes-state-invalid".to_string())?;
            validate_note(note)?;
            Ok((mac, note.to_string()))
        })
        .collect()
}

fn envelope(notes: BTreeMap<String, String>) -> Value {
    json!({
        "schema": "caduceus.network.notes.v1",
        "ok": true,
        "notes": notes,
        "firstMissingSignal": "none",
    })
}

pub fn read_json() -> Result<Value, String> {
    Ok(envelope(notes_from(&read_state()?)?))
}

pub fn write_json(mac: &str, note: &str) -> Result<Value, String> {
    let mac = normalize_mac(mac)?;
    validate_note(note)?;
    let _guard = write_lock()
        .lock()
        .map_err(|_| "caduceus-network-notes-state-write-failed".to_string())?;
    let mut state = read_state()?;
    let mut notes = notes_from(&state)?;
    if note.is_empty() {
        notes.remove(&mac);
    } else {
        notes.insert(mac, note.to_string());
    }
    let object = state
        .as_object_mut()
        .ok_or_else(|| "caduceus-network-notes-state-invalid".to_string())?;
    object.insert(
        NOTES_KEY.to_string(),
        serde_json::to_value(&notes)
            .map_err(|_| "caduceus-network-notes-state-render-failed".to_string())?,
    );
    let bytes = serde_json::to_vec_pretty(&state)
        .map_err(|_| "caduceus-network-notes-state-render-failed".to_string())?;
    let path = paths::path(STATE_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|_| "caduceus-network-notes-state-write-failed".to_string())?;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o750))
            .map_err(|_| "caduceus-network-notes-state-write-failed".to_string())?;
    }
    config::atomic_write_owned(&path, &bytes, STATE_FILE_MODE)
        .map_err(|_| "caduceus-network-notes-state-write-failed".to_string())?;
    let readback = notes_from(&read_state()?)?;
    let mut receipt = envelope(readback);
    receipt["mutationPerformed"] = Value::Bool(true);
    receipt["completed"] = Value::Bool(true);
    receipt["cleared"] = Value::Bool(note.is_empty());
    Ok(receipt)
}


use axum::{extract::Json, http::StatusCode, Router};
use crate::gate::{gated_json, ApiErrorBody};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkNotesBody {
    mac: String,
    note: String,
}

async fn network_notes_read_route() -> Result<Json<Value>, (StatusCode, Json<ApiErrorBody>)> {
    gated_json("network notes", network_notes::read_json).await
}

fn network_notes_write_error(signal: String) -> (StatusCode, Json<ApiErrorBody>) {
    let status = if signal == "caduceus-network-notes-mac-invalid"
        || signal == "caduceus-network-notes-note-invalid"
    {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(ApiErrorBody {
            schema: "caduceus.api.error.v1",
            ok: false,
            command: "network notes write".to_string(),
            first_missing_signal: signal,
        }),
    )
}

async fn network_notes_write_route(
    headers: HeaderMap,
    Json(body): Json<NetworkNotesBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    let command = "network notes write";
    match policy::allows_command(command) {
        Ok(false) => Err(api_error(command)),
        Err(_) => Err(api_error_signal(command, "caduceus-profile-missing")),
        Ok(true) => {
            let document = headers
                .get("x-caduceus-document")
                .and_then(|value| value.to_str().ok())
                .filter(|value| !value.trim().is_empty());
            document_attendance_admits(
                document.unwrap_or(""),
                headers
                    .get("x-caduceus-attendance")
                    .and_then(|value| value.to_str().ok()),
            )
            .map_err(|signal| api_error_signal(command, &signal))?;
            network_notes::write_json(&body.mac, &body.note)
                .map(|value| (StatusCode::OK, Json(value)))
                .map_err(network_notes_write_error)
        }
    }
}

/// Canonical registration seam; legacy aliases remain hoisted to the same body.
pub fn register(router: Router) -> Router {
    router.route("/api/v1/network/notes", axum::routing::get(network_notes_read_route).put(network_notes_write_route))
}
