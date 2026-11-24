use axum::extract::Path;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path as FsPath;
use std::sync::OnceLock;
use crate::gate::door::ARPEGGIO_PARTS;

include!(concat!(env!("OUT_DIR"), "/public_schema_seats.rs"));

const SHARED_SEATS: [&str; 5] = [
    crate::protocol::SCHEMA_ID,
    "caduceus.staff.receipt.v1",
    "caduceus.chord.v1",
    "caduceus.chord.receipt.v1",
    "hestia.portal.v1",
];

struct Seat {
    bytes: String,
    declaration: Value,
}

struct Registry {
    seats: BTreeMap<&'static str, Seat>,
    // Intent seats are served as documents, not consumed by admission.
    intents: BTreeMap<String, String>,
    census: Value,
}

fn read_intent_seat(path: &FsPath, intent: &str) -> Option<String> {
    let bytes = fs::read_to_string(path).ok()?;
    let declaration: Value = serde_json::from_str(&bytes).ok()?;
    let object = declaration.as_object()?;
    let valid = object.get("schema").and_then(Value::as_str) == Some(crate::protocol::SCHEMA_ID)
        && object.get("intent").and_then(Value::as_str) == Some(intent);
    valid.then_some(bytes)
}

fn load_intent_seats(folder: &FsPath) -> (BTreeMap<String, String>, Vec<String>) {
    let root = folder.join("intents");
    let mut seats = BTreeMap::new();
    let mut invalid = Vec::new();
    if !fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.is_dir()) {
        return (seats, invalid);
    }
    let mut pending = vec![root.clone()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            // Walk regular files and real subdirectories without following links.
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                pending.push(path);
                continue;
            }
            if !kind.is_file() || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            // The document names the stop (e.g. unit/start); the door adds intents/.
            let relative = path
                .strip_prefix(&root)
                .expect("intent seat walked below the intent root")
                .with_extension("");
            let id = format!("intents/{}", relative.display());
            let Some(bytes) = relative
                .to_str()
                .and_then(|intent| read_intent_seat(&path, intent))
            else {
                invalid.push(id);
                continue;
            };
            seats.insert(id, bytes);
        }
    }
    invalid.sort_unstable();
    (seats, invalid)
}

fn arpeggio_drift(chord: Option<&Seat>) -> Value {
    let Some(chord) = chord else {
        return json!({"walker_only": [], "seat_only": []});
    };
    let names: Vec<&str> = ["required", "optional"].iter()
        .filter_map(|key| chord.declaration.get(*key).and_then(Value::as_array))
        .flatten().filter_map(Value::as_str).collect();
    let walker_only: Vec<&str> = ARPEGGIO_PARTS.iter().copied()
        .filter(|name| !names.contains(name)).collect();
    let seat_only: Vec<&str> = names.into_iter()
        .filter(|name| !ARPEGGIO_PARTS.contains(name)).collect();
    json!({"walker_only": walker_only, "seat_only": seat_only})
}

fn registry() -> Result<&'static Registry, &'static str> {
    static REGISTRY: OnceLock<Result<Registry, String>> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let mut seats: BTreeMap<_, _> = EMBEDDED_SEATS.iter().map(|(id, bytes)| {
            let declaration: Value = serde_json::from_str(bytes)
                .expect("caduceus-schema-desync: embedded seat is not JSON");
            assert_eq!(declaration["schema"].as_str(), Some(*id),
                "caduceus-schema-desync: seat identity differs from filename");
            assert!(declaration["required"].as_array()
                .is_some_and(|fields| fields.iter().all(|field| field.as_str().is_some())),
                "caduceus-schema-desync: frozen kernel absent");
            (*id, Seat { bytes: (*bytes).to_owned(), declaration })
        }).collect();
        let folder = crate::shared::config::path("opt/caduceus/source/schema");
        let mut loaded = Vec::new();
        let mut absent = Vec::new();
        for id in SHARED_SEATS {
            let parsed = std::fs::read_to_string(folder.join(format!("{id}.json")))
                .ok().and_then(|bytes| {
                    let declaration: Value = serde_json::from_str(&bytes).ok()?;
                    declaration.is_object().then_some((bytes, declaration))
                });
            let Some((bytes, declaration)) = parsed else {
                absent.push(id);
                continue;
            };
            let found = declaration.get("schema").and_then(Value::as_str);
            if found != Some(id) {
                return Err(format!("caduceus-seat-foreign: {id} found {}", found.unwrap_or("<missing-or-non-string>")));
            }
            if id == crate::protocol::SCHEMA_ID
                && !declaration["kernel"]["required"].as_array()
                    .is_some_and(|fields| fields.iter().all(|field| field.as_str().is_some()))
            {
                absent.push(id);
                continue;
            }
            loaded.push(json!({"id": id, "schema_version": declaration.get("schema_version")}));
            seats.insert(id, Seat { bytes, declaration });
        }
        let arpeggio_drift = arpeggio_drift(seats.get("caduceus.chord.v1"));
        let (intents, invalid_intents) = load_intent_seats(&folder);
        let census = json!({
            "folder": folder.to_string_lossy(),
            "loaded": loaded,
            "absent": absent,
            "arpeggio_drift": arpeggio_drift,
            "intents": {
                "loaded_count": intents.len(),
                "loaded": intents.keys().collect::<Vec<_>>(),
                "invalid": invalid_intents,
            },
        });
        Ok(Registry {
            seats,
            intents,
            census,
        })
    }).as_ref().map_err(String::as_str)
}

pub(crate) fn initialize() -> Result<&'static Value, &'static str> {
    registry().map(|registry| &registry.census)
}

fn loaded_registry() -> &'static Registry {
    registry().expect("caduceus-seat-foreign: startup initialization failed")
}

fn seats() -> &'static BTreeMap<&'static str, Seat> {
    &loaded_registry().seats
}

/// Borrow the declaration already loaded by the startup registry.
pub(crate) fn declaration(id: &str) -> Option<&'static Value> {
    seats().get(id).map(|seat| &seat.declaration)
}

/// Only a missing shared seat selects the schema-id primitive at the gate.
pub(crate) fn shared_seat_absent(id: &str) -> bool {
    SHARED_SEATS.contains(&id) && declaration(id).is_none()
}

pub(crate) fn row_schema() -> &'static str {
    schema_id("caduceus.ruyi.v1")
}

pub(crate) fn beam_schema() -> &'static str {
    schema_id("caduceus.beam.v1")
}

fn schema_id(lookup: &str) -> &'static str {
    seats()
        .get(lookup)
        .and_then(|seat| seat.declaration["schema"].as_str())
        .expect("caduceus-schema-desync: seat identity absent")
}

/// The declaration is the authority; typed projections are only readers.
/// Optional and unknown fields never participate in this kernel gate.
pub(crate) fn accepts(id: &str, value: &Value) -> bool {
    let matches = value.get("schema").and_then(Value::as_str) == Some(id);
    let Some(seat) = seats().get(id) else {
        return matches && SHARED_SEATS.contains(&id);
    };
    matches && seat.declaration["required"].as_array().is_none_or(|fields| {
        fields.iter().all(|field| field.as_str().is_none_or(|name| value.get(name).is_some()))
    })
}

/// A shared staff receipt identifies its crossing by the stamped stop.
pub(crate) fn bound(value: &Value, stop_path: &str) -> bool {
    let (noun, verb) = stop_path.rsplit_once('/').unwrap_or((stop_path, ""));
    accepts("caduceus.staff.receipt.v1", value)
        && value.pointer("/stop/noun").and_then(Value::as_str) == Some(noun)
        && value.pointer("/stop/verb").and_then(Value::as_str) == Some(verb)
}

/// Bind a peer's HTTP reply to the path sent, not its query or a name from the reply.
pub(crate) fn bound_http_reply(value: &Value, request_target: &str) -> bool {
    let path = request_target.split_once('?').map_or(request_target, |(path, _)| path);
    path.strip_prefix("/api/v1/")
        .is_some_and(|stop| !stop.is_empty() && bound(value, stop))
}

// Close 402 binds an arpeggio aggregate to the routine crossed.
pub(crate) fn aggregate_bound(value: &Value, routine: &str) -> bool {
    accepts("caduceus.chord.receipt.v1", value)
        && value.get("routine_id").and_then(Value::as_str) == Some(routine)
}

pub(crate) fn accepts_bound(_id: &str, stop_path: &str, value: &Value) -> bool {
    _id != "caduceus.chord.receipt.v1" && bound(value, stop_path)
}

pub(crate) fn accepts_form(id: &str, form: &str, value: &Value) -> bool {
    if !accepts(id, value) {
        return false;
    }
    if SHARED_SEATS.contains(&id) && !seats().contains_key(id) {
        return true;
    }
    seats()
        .get(id)
            .and_then(|seat| seat.declaration["forms"][form]["required"].as_array())
            .is_some_and(|fields| {
                fields
                    .iter()
                    .all(|field| field.as_str().is_some_and(|name| value.get(name).is_some()))
            })
}

async fn list() -> Json<Value> {
    Json(json!({"ok": true, "schemas": seats().keys().collect::<Vec<_>>()}))
}

async fn get(Path(id): Path<String>) -> Response {
    schema_response(seats().get(id.as_str()).map(|seat| seat.bytes.as_str()))
}

async fn get_intent(Path(intent): Path<String>) -> Response {
    let id = format!("intents/{intent}");
    schema_response(loaded_registry().intents.get(&id).map(String::as_str))
}

fn schema_response(bytes: Option<&'static str>) -> Response {
    match bytes {
        Some(bytes) => ([(CONTENT_TYPE, "application/json")], bytes).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(crate::gate::ApiErrorBody {
                ok: false,
                command: "schema".to_owned(),
                first_missing_signal: "caduceus-schema-absent".to_owned(),
            }),
        )
            .into_response(),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    let _ = loaded_registry();
    router
        .route("/api/v1/schema", axum::routing::get(list))
        .route("/api/v1/schema/:id", axum::routing::get(get))
        .route(
            "/api/v1/schema/intents/*intent",
            axum::routing::get(get_intent),
        )
}
