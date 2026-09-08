//! One disk collector beside CPU telemetry; HTTP only clones held state.
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::sync::{Condvar, Mutex, Once};
use std::time::Duration;

const CADENCE: Duration = Duration::from_secs(10);
const UNAVAILABLE: &str = "caduceus-disk-census-unavailable";
struct State {
    latest: Option<Value>,
    generation: u64,
}
static STATE: Mutex<State> = Mutex::new(State {
    latest: None,
    generation: 0,
});
static WAKE: Condvar = Condvar::new();
static START: Once = Once::new();

pub(crate) fn current() -> Result<Value, String> {
    STATE
        .lock()
        .map_err(|_| UNAVAILABLE.to_owned())?
        .latest
        .clone()
        .ok_or_else(|| UNAVAILABLE.to_owned())
}

/// Called only after a dispatched disk action succeeds. No I/O or lazy startup.
pub(crate) fn request_refresh() {
    let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());
    state.generation = state.generation.wrapping_add(1);
    state.latest = None;
    WAKE.notify_one();
}

pub(super) fn start() {
    START.call_once(|| {
        if let Err(error) = std::thread::Builder::new()
            .name("caduceus-disk-census".into())
            .spawn(collect_loop)
        {
            eprintln!("{UNAVAILABLE}: {error}");
        }
    });
}

fn open() -> Result<Connection, String> {
    let connection = super::open_db()?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS disk_census_devices (
            device TEXT NOT NULL, mount TEXT NOT NULL, position INTEGER NOT NULL,
            row TEXT NOT NULL, PRIMARY KEY(device,mount));
         CREATE TABLE IF NOT EXISTS disk_census_snapshot (
            id INTEGER PRIMARY KEY CHECK(id=1), envelope TEXT NOT NULL);
         CREATE TEMP TABLE disk_census_seen (
            device TEXT NOT NULL, mount TEXT NOT NULL, PRIMARY KEY(device,mount));",
        )
        .map_err(|error| error.to_string())?;
    Ok(connection)
}

fn hydrate(connection: &mut Connection) -> Result<Option<Value>, String> {
    let tx = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    let envelope: Option<String> = tx
        .query_row(
            "SELECT envelope FROM disk_census_snapshot WHERE id=1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|error| error.to_string())?;
    let Some(envelope) = envelope else {
        return Ok(None);
    };
    let mut value: Value = serde_json::from_str(&envelope).map_err(|error| error.to_string())?;
    let devices = {
        let mut statement = tx
            .prepare("SELECT row FROM disk_census_devices ORDER BY position")
            .map_err(|error| error.to_string())?;
        let rows = statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|error| error.to_string())?;
        rows.map(|row| {
            let row = row.map_err(|error| error.to_string())?;
            serde_json::from_str::<Value>(&row).map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, String>>()?
    };
    value["devices"] = Value::Array(devices);
    tx.commit().map_err(|error| error.to_string())?;
    Ok(Some(value))
}

fn persist(connection: &mut Connection, value: &Value) -> Result<(), String> {
    let devices = value["devices"].as_array().ok_or(UNAVAILABLE)?;
    let tx = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    tx.execute("DELETE FROM disk_census_seen", [])
        .map_err(|error| error.to_string())?;
    for (position, row) in devices.iter().enumerate() {
        // JSON-encoded identity preserves null, delimiters and mount whitespace.
        let device = serde_json::json!([row["name"], row["partition"]]).to_string();
        let mount = row["mountpoint"].to_string();
        tx.execute(
            "INSERT INTO disk_census_devices(device,mount,position,row) VALUES(?1,?2,?3,?4)
             ON CONFLICT(device,mount) DO UPDATE SET position=excluded.position,row=excluded.row",
            params![device, mount, position as i64, row.to_string()],
        )
        .map_err(|error| error.to_string())?;
        tx.execute(
            "INSERT OR IGNORE INTO disk_census_seen(device,mount) VALUES(?1,?2)",
            params![device, mount],
        )
        .map_err(|error| error.to_string())?;
    }
    tx.execute(
        "DELETE FROM disk_census_devices WHERE NOT EXISTS
         (SELECT 1 FROM disk_census_seen s WHERE s.device=disk_census_devices.device
          AND s.mount=disk_census_devices.mount)",
        [],
    )
    .map_err(|error| error.to_string())?;
    let mut envelope = value.clone();
    envelope
        .as_object_mut()
        .ok_or(UNAVAILABLE)?
        .remove("devices");
    tx.execute(
        "INSERT INTO disk_census_snapshot(id,envelope) VALUES(1,?1)
         ON CONFLICT(id) DO UPDATE SET envelope=excluded.envelope",
        [envelope.to_string()],
    )
    .map_err(|error| error.to_string())?;
    tx.commit().map_err(|error| error.to_string())
}

fn collect_loop() {
    let mut connection = None;
    let mut hydrated = false;
    loop {
        let generation = STATE
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .generation;
        let result = (|| {
            if connection.is_none() {
                connection = Some(open()?);
            }
            let connection = connection.as_mut().ok_or(UNAVAILABLE)?;
            if !hydrated {
                hydrated = true;
                match hydrate(connection) {
                    Ok(snapshot) => {
                        let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());
                        // A mutation before/during startup forbids the previous snapshot.
                        if generation == 0 && state.generation == generation {
                            state.latest = snapshot;
                        }
                    }
                    Err(error) => eprintln!("{UNAVAILABLE}: hydration: {error}"),
                }
            }
            let value = crate::routes::disk::collect_json()?;
            persist(connection, &value)?;
            Ok::<_, String>(value)
        })();
        let mut state = STATE.lock().unwrap_or_else(|error| error.into_inner());
        if state.generation != generation {
            // A signal during collection/persistence survives: immediately collect again.
            continue;
        }
        match result {
            Ok(value) => state.latest = Some(value),
            Err(error) => {
                state.latest = None;
                eprintln!("{UNAVAILABLE}: {error}");
            }
        }
        // Predicate + mutex prevents a signal between completion and parking being lost.
        let _ = WAKE
            .wait_timeout_while(state, CADENCE, |state| state.generation == generation)
            .unwrap_or_else(|error| error.into_inner());
    }
}
