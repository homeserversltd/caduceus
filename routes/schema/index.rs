use axum::extract::Path;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/public_schema_seats.rs"));

struct Seat {
    bytes: &'static str,
    declaration: Value,
}

fn seats() -> &'static BTreeMap<&'static str, Seat> {
    static SEATS: OnceLock<BTreeMap<&'static str, Seat>> = OnceLock::new();
    SEATS.get_or_init(|| {
        EMBEDDED_SEATS
            .iter()
            .map(|(id, bytes)| {
                let declaration: Value = serde_json::from_str(bytes)
                    .expect("caduceus-schema-desync: embedded seat is not JSON");
                assert_eq!(
                    declaration["schema"].as_str(),
                    Some(*id),
                    "caduceus-schema-desync: seat identity differs from filename"
                );
                assert!(
                    declaration["required"]
                        .as_array()
                        .is_some_and(|fields| fields.iter().all(|field| field.as_str().is_some())),
                    "caduceus-schema-desync: frozen kernel absent"
                );
                (*id, Seat { bytes, declaration })
            })
            .collect()
    })
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
    let Some(seat) = seats().get(id) else {
        return false;
    };
    value.get("schema").and_then(Value::as_str) == Some(id)
        && seat.declaration["required"]
            .as_array()
            .unwrap()
            .iter()
            .all(|field| value.get(field.as_str().unwrap()).is_some())
}

pub(crate) fn accepts_form(id: &str, form: &str, value: &Value) -> bool {
    accepts(id, value)
        && seats()
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
        Some(seat) => ([(CONTENT_TYPE, "application/json")], seat.bytes).into_response(),
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
