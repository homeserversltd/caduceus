use axum::extract::Path;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/public_schema_seats.rs"));

const SEAT_FOLDER: &str = "/opt/caduceus/source/schema";
const SHARED_SEATS: [&str; 4] = [
    crate::protocol::SCHEMA_ID,
    "caduceus.staff.receipt.v1",
    "caduceus.chord.v1",
    "caduceus.chord.receipt.v1",
];

struct Seat {
    bytes: String,
    declaration: Value,
}

struct Registry {
    seats: BTreeMap<&'static str, Seat>,
    census: Value,
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
        Ok(Registry { seats, census: json!({"folder": SEAT_FOLDER, "loaded": loaded, "absent": absent}) })
    }).as_ref().map_err(String::as_str)
}

pub(crate) fn initialize() -> Result<&'static Value, &'static str> {
    registry().map(|registry| &registry.census)
}

fn seats() -> &'static BTreeMap<&'static str, Seat> {
    &registry().expect("caduceus-seat-foreign: startup initialization failed").seats
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
    match seats().get(id.as_str()) {
        Some(seat) => ([(CONTENT_TYPE, "application/json")], seat.bytes.as_str()).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(crate::gate::ApiErrorBody {
                schema: "caduceus.api.error.v1",
                ok: false,
                command: "schema".to_owned(),
                first_missing_signal: "caduceus-schema-absent".to_owned(),
            }),
        )
            .into_response(),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    let _ = seats(); // Load and check every embedded seat at router startup.
    router
        .route("/api/v1/schema", axum::routing::get(list))
        .route("/api/v1/schema/:id", axum::routing::get(get))
}
