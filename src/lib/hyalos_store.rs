//! Best-effort SQLite projection beside the unchanged hyalos channel.
use super::{metadata_alias, ChannelEvent};
use crate::shared::config;
use rusqlite::{
    params, types::Value as SqlValue, Connection, OptionalExtension, TransactionBehavior,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/hyalos_seats.rs"));

const DB_PATH: &str = "var/lib/caduceus/hyalos.sqlite3";
type StoreResult<T> = Result<T, &'static str>;
static WRITER: Mutex<Option<Connection>> = Mutex::new(None);

#[derive(Deserialize)]
struct RowSeat {
    schema: String,
    fields: RowFields,
}

#[derive(Deserialize)]
struct RowFields {
    families: FamilyFields,
}

#[derive(Deserialize)]
struct FamilyFields {
    projected_fields: BTreeMap<String, Vec<String>>,
}

#[derive(Deserialize)]
struct KindsSeat {
    schema: String,
    kinds: Vec<String>,
    bad_outcomes: Vec<String>,
    rules: Vec<Rule>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Names {
    One(String),
    Many(Vec<String>),
}

impl Names {
    fn matches(&self, value: Option<&str>) -> bool {
        match self {
            Self::One(name) => value == Some(name.as_str()),
            Self::Many(names) => names.iter().any(|name| value == Some(name.as_str())),
        }
    }
}

#[derive(Deserialize)]
struct Rule {
    organ: Option<String>,
    kind: Option<Names>,
    verb: Option<Names>,
    outcome: Option<String>,
    signal: Option<String>,
    bad: Option<bool>,
    row: Class,
}

#[derive(Deserialize)]
struct Class {
    kind: String,
    level: i64,
}

struct Policy {
    row: RowSeat,
    table: KindsSeat,
    lowest: i64,
    highest: i64,
}

fn read_seat<T: DeserializeOwned>(id: &str) -> StoreResult<T> {
    let bytes = config::read_public_file(&format!("opt/caduceus/source/schema/{id}.json"))
        .map_err(|_| "seat-unreadable")?;
    serde_json::from_str(&bytes).map_err(|_| "seat-invalid")
}

fn load_policy() -> StoreResult<Policy> {
    let row: RowSeat = read_seat(ROW_SCHEMA)?;
    let table: KindsSeat = read_seat(KINDS_SCHEMA)?;
    if row.schema != ROW_SCHEMA || table.schema != KINDS_SCHEMA {
        return Err("seat-schema-foreign");
    }
    if table
        .rules
        .iter()
        .any(|rule| !table.kinds.contains(&rule.row.kind))
    {
        return Err("seat-kind-undeclared");
    }
    let levels = table.rules.iter().map(|rule| rule.row.level);
    let (lowest, highest) = levels.clone().min().zip(levels.max()).ok_or("seat-empty")?;
    Ok(Policy {
        row,
        table,
        lowest,
        highest,
    })
}

fn policy() -> StoreResult<&'static Policy> {
    static POLICY: OnceLock<StoreResult<Policy>> = OnceLock::new();
    POLICY
        .get_or_init(load_policy)
        .as_ref()
        .map_err(|error| *error)
}

impl Policy {
    fn classify<'a>(
        &'a self,
        event: &ChannelEvent,
        projected: &ChannelEvent,
    ) -> StoreResult<(&'a Class, bool)> {
        let fields = &projected.attributes_redacted;
        let verb = fields["verb"].as_str();
        let signal = fields["signal"].as_str();
        // The legacy run-profile projection can narrow an explicit outcome.
        // Classify the reported outcome; keep the projected words in the row.
        let outcome = event.attributes_redacted["outcome"]
            .as_str()
            .or_else(|| fields["outcome"].as_str());
        let outcome_is = |name: &str| outcome.is_some_and(|value| value.eq_ignore_ascii_case(name));
        let bad = !event.ok || self.table.bad_outcomes.iter().any(|name| outcome_is(name));
        self.table
            .rules
            .iter()
            .find(|rule| {
                rule.organ.as_deref().is_none_or(|name| name == event.organ)
                    && rule
                        .kind
                        .as_ref()
                        .is_none_or(|names| names.matches(Some(&event.kind)))
                    && rule.verb.as_ref().is_none_or(|names| names.matches(verb))
                    && rule.outcome.as_deref().is_none_or(outcome_is)
                    && rule
                        .signal
                        .as_deref()
                        .is_none_or(|name| signal == Some(name))
                    && rule.bad.is_none_or(|expected| expected == bad)
            })
            .map(|rule| (&rule.row, bad))
            .ok_or("seat-no-match")
    }

    fn body_level(&self) -> i64 {
        config::get_json("hyalos.level")
            .ok()
            .and_then(|answer| answer["value"].as_i64())
            .filter(|level| (self.lowest..=self.highest).contains(level))
            .unwrap_or(self.lowest)
    }

    fn families(&self, fields: &Value) -> Option<String> {
        let families: Map<String, Value> = self
            .row
            .fields
            .families
            .projected_fields
            .iter()
            .filter_map(|(family, keys)| {
                let values: Map<String, Value> = keys
                    .iter()
                    .filter_map(|key| {
                        fields
                            .get(key)
                            .filter(|value| !value.is_null())
                            .map(|value| (key.clone(), value.clone()))
                    })
                    .collect();
                (!values.is_empty()).then(|| (family.clone(), Value::Object(values)))
            })
            .collect();
        (!families.is_empty()).then(|| Value::Object(families).to_string())
    }
}

fn open() -> StoreResult<Connection> {
    let path = config::path(DB_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "sqlite-parent-failed")?;
    }
    let connection = Connection::open(path).map_err(|_| "sqlite-open-failed")?;
    connection
        .busy_timeout(Duration::from_secs(5))
        .map_err(|_| "sqlite-busy-timeout-failed")?;
    connection
        .execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")
        .map_err(|_| "sqlite-auto-vacuum-failed")?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .map_err(|_| "sqlite-wal-failed")?;
    if mode != "wal" {
        return Err("sqlite-wal-failed");
    }
    connection
        .execute_batch(
            "PRAGMA synchronous=NORMAL;
         PRAGMA temp_store=MEMORY;
         PRAGMA foreign_keys=ON;
         PRAGMA journal_size_limit=8388608;
         CREATE TABLE IF NOT EXISTS deeds (
             id INTEGER PRIMARY KEY,
             schema TEXT NOT NULL,
             kind TEXT NOT NULL,
             at TEXT NOT NULL,
             level INTEGER NOT NULL,
             routine TEXT,
             body TEXT,
             organ TEXT,
             target TEXT,
             who TEXT,
             verb TEXT,
             outcome TEXT,
             signal TEXT,
             duration_ms ANY,
             families TEXT
         ) STRICT;
         CREATE INDEX IF NOT EXISTS deeds_latest ON deeds (organ, kind, verb, target, id DESC);",
        )
        .map_err(|_| "sqlite-initialize-failed")?;
    Ok(connection)
}

pub(super) fn offer(
    event: &ChannelEvent,
    projected: &ChannelEvent,
    debug: bool,
) -> StoreResult<()> {
    let policy = policy()?;
    let (class, bad) = policy.classify(event, projected)?;
    let level = if debug {
        policy.highest
    } else if class.level <= policy.body_level() {
        class.level
    } else {
        return Ok(()); // No SQLite open, transaction, or query on a level drop.
    };

    let fields = &projected.attributes_redacted;
    let field = |name: &str| fields[name].as_str();
    let kind = class.kind.as_str();
    let organ = projected.organ.as_str();
    let verb = field("verb");
    let outcome = field("outcome");
    let signal = field("signal");
    let (target, routine) = if projected.kind == "generic-http-door" {
        // The legacy projection keeps this target under routine_id instead.
        (field("routine_id"), None)
    } else {
        (
            field("target"),
            field("run_id").map(str::to_owned).or_else(|| {
                metadata_alias(
                    &event.attributes_redacted,
                    &["run_id", "routine_id", "routine"],
                    64,
                )
            }),
        )
    };
    let duration_ms = fields["duration_ms"].as_u64().map(|ms| {
        i64::try_from(ms)
            .map(SqlValue::Integer)
            .unwrap_or_else(|_| SqlValue::Text(ms.to_string()))
    });
    let families = policy.families(fields);

    let mut writer = WRITER.lock().map_err(|_| "sqlite-writer-lock-failed")?;
    let connection = match writer.as_mut() {
        Some(connection) => connection,
        None => writer.insert(open()?),
    };
    // Lock the writer before reading the newest row so concurrent CLI and
    // server writers cannot both admit the same failure or state.
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "sqlite-begin-failed")?;
    if bad || kind == "state" {
        let repeated = tx
            .query_row(
                "SELECT (outcome IS ?5) AND (signal IS ?6) FROM deeds
             WHERE organ = ?1 AND kind = ?2 AND verb IS ?3 AND target IS ?4
             ORDER BY id DESC LIMIT 1",
                params![organ, kind, verb, target, outcome, signal],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(|_| "sqlite-repeat-check-failed")?;
        if repeated == Some(true) {
            return Ok(()); // The transaction drops without changing any rows.
        }
    }
    tx.execute(
        "INSERT INTO deeds (schema, kind, at, level, routine, body, organ, target,
                            who, verb, outcome, signal, duration_ms, families)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            policy.row.schema,
            kind,
            projected.timestamp,
            level,
            routine,
            projected.body_id,
            organ,
            target,
            field("who"),
            verb,
            outcome,
            signal,
            duration_ms,
            families
        ],
    )
    .map_err(|_| "sqlite-insert-failed")?;
    tx.commit().map_err(|_| "sqlite-commit-failed")
}
