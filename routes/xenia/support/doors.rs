use super::{observation, observe, seat, store, validation, Refusal, Result, VERDICT, XENIA};
use axum::extract::{rejection::JsonRejection, Path};
use axum::http::StatusCode;
use axum::Json;
use serde_json::{json, Map, Value};
use std::time::Duration;

type Reply = (StatusCode, Json<Value>);
type Body = std::result::Result<Json<Value>, JsonRejection>;

fn authorized() -> Result<()> {
    match crate::shared::policy::allows_command("xenia mutate") {
        Ok(true) => Ok(()),
        Ok(false) => Err(Refusal::new(
            "authorization",
            "xenia mutate",
            "xenia-mutation-not-allowed",
            "Use a Caduceus profile which grants xenia mutate.",
        )),
        Err(error) => Err(observation("authorization", "xenia mutate", error)),
    }
}

fn input(body: Body) -> Result<Value> {
    body.map(|Json(value)| value).map_err(|error| {
        Refusal::new(
            "A",
            "body",
            format!("request-json-invalid: {error}"),
            "Send a JSON object.",
        )
    })
}

fn result_value(result: Result<Value>, verb: &str) -> Value {
    match result {
        Ok(mut value) => {
            value["schema"] = json!(VERDICT);
            value["ok"] = json!(true);
            value["verdict"] = json!(verb);
            value
        }
        Err(error) => error.value(),
    }
}

/// Exactly one attempt to append the door outcome. This is also the sole
/// emission path for malformed requests, policy refusals and worker failures.
/// A ledger error cannot turn an already-written transaction into success or
/// pretend to roll it back: the prior outcome is retained in the failure.
fn finish(id: &str, door: &str, mut value: Value) -> Reply {
    let form = if value["ok"] == true && value["verdict"] == "admissible" {
        Some("admissible")
    } else if value["ok"] == true && value["verdict"] == "ran" {
        Some("ran")
    } else if value["ok"] == false {
        Some("refusal")
    } else {
        None
    };
    if let Err(error) = seat::form(VERDICT, form, &value, "schema", "verdict") {
        let prior = value;
        value = error.value();
        value["observed"] = json!({"door_outcome": prior});
    }
    let event = json!({"kind": "xenia", "organ": "caduceus", "correlation_id": id,
        "ok": value["ok"], "level": if value["ok"] == true {"info"} else {"warn"},
        "message": format!("xenia {door}: {}", value["verdict"].as_str().unwrap_or("refused")),
        "attributes_redacted": value});
    if let Err(error) = crate::shared::hyalos::reflect_json(event) {
        let mut failure = observation(
            "hyalos",
            "event",
            format!("hyalos-emission-failed: {error}"),
        )
        .value();
        failure["observed"] = json!({"door_outcome": value});
        return (StatusCode::SERVICE_UNAVAILABLE, Json(failure));
    }
    let status = if value["ok"] == true {
        StatusCode::OK
    } else if value["check"] == "authorization" {
        StatusCode::FORBIDDEN
    } else if value["check"] == "status"
        || value["check"] == "schema"
        || value["check"] == "transaction"
    {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::UNPROCESSABLE_ENTITY
    };
    (status, Json(value))
}

async fn mutation_or_validation(body: Body, mutate: bool) -> Reply {
    let body = input(body);
    let id = body
        .as_ref()
        .ok()
        .and_then(|value| value.get("manifest"))
        .and_then(|manifest| manifest["id"].as_str())
        .unwrap_or("")
        .to_string();
    let result = tokio::task::spawn_blocking(move || -> Result<Value> {
        if mutate { authorized()?; }
        let body = body?;
        let candidate = validation::validate(&body)?;
        if mutate { store::admit(&candidate.house, &candidate.entry, &candidate.row) }
        else { Ok(json!({"entry": candidate.entry, "tabs": candidate.row, "observed": candidate.observed})) }
    }).await.unwrap_or_else(|error| Err(observation("transaction", "worker", error.to_string())));
    let verb = if mutate { "admitted" } else { "admissible" };
    finish(
        &id,
        if mutate { "admit" } else { "validate" },
        result_value(result, verb),
    )
}

pub async fn validate(body: Body) -> Reply {
    mutation_or_validation(body, false).await
}
pub async fn admit(body: Body) -> Reply {
    mutation_or_validation(body, true).await
}

pub async fn observe(Path(id): Path<String>, body: Body) -> Reply {
    let parsed = input(body);
    let worker_id = id.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Value> {
        seat::startup().map_err(|e| observation("schema", "startup", e))?;
        seat::field(XENIA, "id", &json!(worker_id), "C", "id")?;
        let body = parsed?;
        let object = body.as_object().ok_or_else(|| {
            Refusal::new(
                "schema",
                "body",
                "observation-body-not-object",
                "Send exactly one installed or discovered snapshot.",
            )
        })?;
        let entry = seat::declaration(XENIA)?["forms"]["entry"]
            .as_object()
            .ok_or_else(|| observation("schema", "forms.entry", "entry-form-seat-desync"))?;
        for key in object.keys() {
            let declared = ["required", "optional"]
                .iter()
                .try_fold(false, |found, list| {
                    let fields = entry.get(*list).and_then(Value::as_array).ok_or_else(|| {
                        observation(
                            "schema",
                            &format!("forms.entry.{list}"),
                            "entry-form-seat-desync",
                        )
                    })?;
                    Ok::<_, Refusal>(
                        found
                            || fields
                                .iter()
                                .any(|field| field.as_str() == Some(key.as_str())),
                    )
                })?;
            if declared && key != "installed" && key != "discovered" {
                return Err(Refusal::new(
                    "schema",
                    &format!("body.{key}"),
                    "forgery-of-declaration",
                    "Send only one engine-owned installed or discovered snapshot.",
                ));
            }
        }
        let installed = object.contains_key("installed");
        let discovered = object.contains_key("discovered");
        if object.len() != 1 || installed == discovered {
            return Err(Refusal::new(
                "schema",
                "body",
                "observation-body-must-contain-exactly-one-snapshot",
                "Send exactly one installed or discovered snapshot and no declared entry fields.",
            ));
        }
        let field = if installed { "installed" } else { "discovered" };
        let snapshot = object
            .get(field)
            .ok_or_else(|| observation("observe", field, "snapshot-absent"))?;
        seat::field(XENIA, field, snapshot, "observe", field)?;
        store::observe(&worker_id, field, snapshot)
    })
    .await
    .unwrap_or_else(|error| Err(observation("transaction", "worker", error.to_string())));
    finish(&id, "observe", result_value(result, "admissible"))
}

pub async fn run(Path(id): Path<String>, body: Body) -> Reply {
    let parsed = input(body);
    let worker_id = id.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Value> {
        seat::startup().map_err(|e| observation("schema", "startup", e))?;
        let body = parsed?;
        let object = body.as_object().ok_or_else(|| {
            Refusal::new(
                "run",
                "body",
                "run-body-not-object",
                "Send an object containing band and envelope.",
            )
        })?;
        let requested_band = object.get("band").and_then(Value::as_str).ok_or_else(|| {
            Refusal::new(
                "run",
                "band",
                "xenos-band-unlisted",
                "Send a band listed by the admitted clone's staff index.",
            )
        })?;
        let band = crate::gate::snake::safe_band_path(requested_band).map_err(|_| {
            Refusal::new(
                "run",
                "band",
                "xenos-band-unlisted",
                "Send a band listed by the admitted clone's staff index.",
            )
        })?;
        let envelope = object
            .get("envelope")
            .ok_or_else(|| {
                Refusal::new(
                    "run",
                    "envelope",
                    "run-envelope-required",
                    "Send the caduceus staff envelope for the selected band.",
                )
            })?
            .clone();
        let house = store::snapshot()?;
        if house.register["xenoi"].get(&worker_id).is_none() {
            return Err(Refusal::new(
                "run",
                "id",
                "xenos-not-admitted",
                "Admit the xenos before invoking a guest band.",
            ));
        }
        let root = crate::shared::config::path(&format!("/var/lib/xenia/{worker_id}/staff"));
        let entries = crate::gate::snake::index_entries(&root).map_err(|_| {
            Refusal::new(
                "run",
                "band",
                "xenos-band-unlisted",
                "Declare the requested band in the clone's staff index.",
            )
        })?;
        if !entries
            .iter()
            .any(|entry| entry.get("bandPath").and_then(Value::as_str) == Some(band.as_str()))
        {
            return Err(Refusal::new(
                "run",
                "band",
                "xenos-band-unlisted",
                "Declare the requested band in the clone's staff index.",
            ));
        }
        let argv = vec![
            "/usr/local/sbin/agathodaimon/caduceus-xenos-run".to_string(),
            worker_id,
            "band".to_string(),
            band,
        ];
        let mut value = crate::gate::snake::run_launcher(&argv, &envelope, Duration::from_secs(30))
            .map_err(|error| {
                let message = match error.as_str() {
                    "xenos-run-timeout" => "xenos-run-timeout",
                    "xenos-launcher-absent" => "xenos-launcher-absent",
                    _ => "xenos-launcher-refused",
                };
                Refusal::new(
                    "run",
                    "launcher",
                    message,
                    "Restore the fixed xenos launcher and repeat the run door.",
                )
            })?;
        if value["ok"] != true {
            return Err(Refusal::new(
                "run",
                "launcher",
                "xenos-launcher-refused",
                "Restore the launcher band and repeat the run door.",
            ));
        }
        value["receipt"] = value["receiptPayload"].clone();
        Ok(value)
    })
    .await
    .unwrap_or_else(|error| Err(observation("transaction", "worker", error.to_string())));
    finish(&id, "run", result_value(result, "ran"))
}

pub async fn remove(body: Body) -> Reply {
    let body = input(body);
    let id = body
        .as_ref()
        .ok()
        .and_then(|value| value["id"].as_str())
        .unwrap_or("")
        .to_string();
    let worker_id = id.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<Value> {
        authorized()?;
        seat::startup().map_err(|e| observation("schema", "startup", e))?;
        let body = body?;
        seat::field(XENIA, "id", &body["id"], "C", "id")?;
        store::remove(&worker_id)
    })
    .await
    .unwrap_or_else(|error| Err(observation("transaction", "worker", error.to_string())));
    finish(&id, "remove", result_value(result, "removed"))
}

fn read_status(id: Option<&str>) -> Result<Value> {
    seat::startup().map_err(|e| observation("schema", "startup", e))?;
    if let Some(id) = id {
        seat::field(XENIA, "id", &json!(id), "C", "id")?;
    }
    let house = store::snapshot()?; // No config mutex across systemctl/proc observation.
    if let Some(id) = id {
        return match house.register["xenoi"].get(id) {
            Some(entry) => {
                let runtime = match observe::runtime(entry) {
                    Ok(value) => value,
                    Err(error) => {
                        json!({"state": "observation-failed", "ok": false, "error": error.value()})
                    }
                };
                let failed = runtime["state"] == "observation-failed";
                let mut outcome = json!({"entry": entry, "id": id, "runtime": runtime,
                    "observed": {"row_present": house.config["tabs"].get(id).is_some()}});
                if failed {
                    outcome["runtime_observation_failed"] = json!(true);
                }
                Ok(outcome)
            }
            None => {
                Ok(json!({"id": id, "runtime": {"state": "entry-absent", "health": "unknown"}}))
            }
        };
    }
    let entries = house.register["xenoi"]
        .as_object()
        .ok_or_else(|| observation("status", "xenoi", "register-map-absent"))?;
    let mut runtime = Map::new();
    let mut failed = false;
    for (id, entry) in entries {
        let answer = match observe::runtime(entry) {
            Ok(value) => value,
            Err(error) => {
                failed = true;
                json!({"state": "observation-failed", "ok": false, "error": error.value()})
            }
        };
        runtime.insert(id.clone(), answer);
    }
    // Whole register accompanies whole entries so top-level household extensions
    // survive readback too. Runtime is evidence alongside them, never a stamp.
    Ok(
        json!({"xenoi": entries, "register": house.register, "runtime": runtime, "runtime_observation_failed": failed}),
    )
}

async fn status_call(id: Option<String>) -> Reply {
    let correlation = id.clone().unwrap_or_default();
    let result = tokio::task::spawn_blocking(move || read_status(id.as_deref()))
        .await
        .unwrap_or_else(|error| Err(observation("status", "worker", error.to_string())));
    let mut value = result_value(result, "status");
    if value["runtime_observation_failed"] == true {
        // Retain all entries even on failed runtime observation, with a public
        // refusal rather than ok=true over a missing kernel observation.
        value["ok"] = json!(false);
        value["verdict"] = json!("refused");
        value["check"] = json!("status");
        value["field"] = json!("runtime");
        value["message"] = json!("runtime-observation-failed");
        value["suggestion"] =
            json!("Restore the named systemctl/proc observation and repeat status.");
    }
    finish(&correlation, "status", value)
}

pub async fn status() -> Reply {
    status_call(None).await
}
pub async fn status_id(Path(id): Path<String>) -> Reply {
    status_call(Some(id)).await
}
