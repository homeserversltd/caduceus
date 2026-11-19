//! The Hyalos store. Only the writer and upkeep open it for writing.
use super::{metadata_alias, ChannelEvent, TailFilters};
use crate::shared::config;
use rusqlite::{
    params, params_from_iter, types::Value as SqlValue, Connection, OpenFlags, OptionalExtension,
    Row, TransactionBehavior,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, HashMap};
use std::{fs, io};
use std::sync::{Condvar, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant};

include!(concat!(env!("OUT_DIR"), "/hyalos_seats.rs"));

pub(crate) const DB_PATH: &str = "/var/lib/caduceus/hyalos.sqlite3";
const STORE_WAIT: Duration = Duration::from_millis(250);
const TROUBLE_CACHE_KEYS: usize = 1024;
type StoreResult<T> = Result<T, &'static str>;
static WRITER: LazyLock<Mutex<Option<Store>>> =
    LazyLock::new(|| Mutex::new(Some(Store::default())));
static WRITER_READY: Condvar = Condvar::new();

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Disposition {
    Written,
    Dropped,
    Failed,
}

#[derive(Clone, Copy)]
pub(super) enum OfferMode {
    Normal,
    Debug,
    // A real retention deletion is always recorded, at its seated level.
    // No sender or door can request this mode.
    Upkeep,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    organ: String,
    verb: Option<String>,
    target: Option<String>,
}

#[derive(Default)]
struct Store {
    writer: Option<Connection>,
    reader: Option<Connection>,
    data_version: Option<i64>,
    troubles: HashMap<Key, bool>,
}

// Lend the connection out without holding the mutex across SQLite I/O.
// A queued deed spends the same deadline on the writer slot and SQLite locks.
struct WriterLease(Store);

impl WriterLease {
    fn acquire(deadline: Instant) -> StoreResult<Self> {
        let slot = WRITER.lock().map_err(|_| "sqlite-writer-lock-failed")?;
        let (mut slot, _) = WRITER_READY
            .wait_timeout_while(
                slot,
                deadline.saturating_duration_since(Instant::now()),
                |slot| slot.is_none(),
            )
            .map_err(|_| "sqlite-writer-lock-failed")?;
        slot.take().map(Self).ok_or("sqlite-writer-busy")
    }
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        *WRITER.lock().unwrap_or_else(|error| error.into_inner()) =
            Some(std::mem::take(&mut self.0));
        WRITER_READY.notify_one();
    }
}

impl Store {
    fn remember(&mut self, key: Key, trouble: bool) {
        if self.troubles.len() >= TROUBLE_CACHE_KEYS && !self.troubles.contains_key(&key) {
            self.troubles.clear(); // A forgotten key is read again, never guessed.
        }
        self.troubles.insert(key, trouble);
    }

    fn newest_is_trouble(&mut self, key: &Key, deadline: Instant) -> StoreResult<bool> {
        let connection = match (&self.writer, &mut self.reader) {
            (Some(connection), _) => connection,
            (None, Some(connection)) => connection,
            (None, reader) => {
                let path = config::path(DB_PATH);
                if !path.try_exists().map_err(|_| "sqlite-path-check-failed")? {
                    return Ok(false); // A cold drop never creates the database.
                }
                reader.insert(
                    Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                        .map_err(|_| "sqlite-read-open-failed")?,
                )
            }
        };
        // The daemon and native CLI can both write this file. A commit from
        // another connection invalidates the hints before they can drop a recovery.
        let version = data_version(connection, deadline)?;
        if self.data_version != Some(version) {
            self.troubles.clear();
            self.data_version = Some(version);
        }
        if let Some(&trouble) = self.troubles.get(key) {
            return Ok(trouble);
        }
        limit_busy(connection, deadline)?;
        let trouble = connection
            .query_row(
                "SELECT trouble FROM deeds WHERE organ = ?1 AND verb IS ?2 AND target IS ?3
             ORDER BY id DESC LIMIT 1",
                params![key.organ, key.verb, key.target],
                |row| row.get::<_, bool>(0),
            )
            .optional()
            .map_err(|_| "sqlite-trouble-check-failed")?
            .unwrap_or(false);
        self.remember(key.clone(), trouble);
        Ok(trouble)
    }

    fn writable(&mut self, deadline: Instant) -> StoreResult<&mut Connection> {
        if self.writer.is_none() {
            let writer = open(deadline)?;
            // Versions are connection-local. Baseline the writer before its
            // first commit warms a key; its own commits do not move the version.
            let version = data_version(&writer, deadline)?;
            self.writer = Some(writer);
            self.reader = None;
            self.data_version = Some(version);
            self.troubles.clear();
        }
        Ok(self.writer.as_mut().expect("writer opened"))
    }
}

fn limit_busy(connection: &Connection, deadline: Instant) -> StoreResult<()> {
    connection
        .busy_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| "sqlite-busy-timeout-failed")
}

fn data_version(connection: &Connection, deadline: Instant) -> StoreResult<i64> {
    limit_busy(connection, deadline)?;
    connection
        .query_row("PRAGMA data_version", [], |row| row.get(0))
        .map_err(|_| "sqlite-data-version-failed")
}

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
    static POLICY: OnceLock<Policy> = OnceLock::new();
    if let Some(policy) = POLICY.get() {
        return Ok(policy);
    }
    let loaded = load_policy()?; // Only a valid pair is published; try again on the next deed.
    Ok(POLICY.get_or_init(|| loaded))
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

pub(crate) fn body_level() -> StoreResult<i64> {
    Ok(policy()?.body_level())
}

fn has_deeds(connection: &Connection) -> StoreResult<bool> {
    connection
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'deeds' LIMIT 1)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-schema-read-failed")
}

fn indexes_installed(connection: &Connection) -> StoreResult<bool> {
    // The last index is installed in the same transaction as all the others.
    connection
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'index' AND name = 'deeds_profile_history' LIMIT 1)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-schema-read-failed")
}

// Older projected timestamps were not parsed. Only ISO date-shaped values can
// reach julianday() in the index; SQLite treats inputs such as "now" as volatile.
const AGE_KEY: &str = "julianday(CASE WHEN substr(at, 5, 1) = '-' THEN at END)";
const PROFILE_DEEDS: &str = "organ = 'harmonia' AND routine IS NOT NULL
                           AND verb IN ('harmonia.run_profile', 'harmonia.run_profile.v1')";

// The sender's ok flag is not the seated trouble predicate. March 1 rows
// lack that bit, so use inverse trouble only for those rows. This storage
// column serves the tail filter and is not part of the public row shape.
const OK_KEY: &str = "coalesce(source_ok, NOT trouble)";

fn has_source_ok(connection: &Connection) -> StoreResult<bool> {
    connection
        .query_row(
            "SELECT EXISTS (SELECT 1 FROM pragma_table_info('deeds') WHERE name = 'source_ok' LIMIT 1)",
            [],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-schema-read-failed")
}

fn install_read_indexes(connection: &mut Connection, deadline: Instant) -> StoreResult<()> {
    limit_busy(connection, deadline)?;
    if indexes_installed(connection)? {
        return Ok(());
    }
    limit_busy(connection, deadline)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "sqlite-index-begin-failed")?;
    if !has_source_ok(&tx)? {
        tx.execute(
            "ALTER TABLE deeds ADD COLUMN source_ok INTEGER CHECK (source_ok IN (0, 1))",
            [],
        )
        .map_err(|_| "sqlite-tail-filter-column-failed")?;
    }
    tx.execute_batch(&format!(
        "CREATE INDEX IF NOT EXISTS deeds_by_kind ON deeds (kind, id DESC);
         CREATE INDEX IF NOT EXISTS deeds_by_organ ON deeds (organ, id DESC);
         CREATE INDEX IF NOT EXISTS deeds_by_verb ON deeds (verb, id DESC);
         CREATE INDEX IF NOT EXISTS deeds_by_level ON deeds (level, id DESC);
         CREATE INDEX IF NOT EXISTS deeds_by_routine ON deeds (routine, id DESC) WHERE routine IS NOT NULL;
         CREATE INDEX IF NOT EXISTS deeds_by_age ON deeds ({AGE_KEY});
         CREATE INDEX IF NOT EXISTS deeds_harmonia_runs ON deeds (organ, kind, id DESC)
             WHERE organ = 'harmonia' AND kind = 'run';
         CREATE INDEX IF NOT EXISTS deeds_by_ok ON deeds ({OK_KEY}, id DESC);
         CREATE INDEX IF NOT EXISTS deeds_profile_history ON deeds (id DESC) WHERE {PROFILE_DEEDS};",
    ))
    .map_err(|_| "sqlite-index-install-failed")?;
    limit_busy(&tx, deadline)?;
    tx.commit().map_err(|_| "sqlite-index-commit-failed")
}

fn open(deadline: Instant) -> StoreResult<Connection> {
    let path = config::path(DB_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "sqlite-parent-failed")?;
    }
    let mut connection = Connection::open(path).map_err(|_| "sqlite-open-failed")?;
    limit_busy(&connection, deadline)?;
    let auto_vacuum: i64 = connection
        .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
        .map_err(|_| "sqlite-auto-vacuum-failed")?;
    if auto_vacuum != 2 {
        // Set the file's mode before the first table, not on every CLI open.
        limit_busy(&connection, deadline)?;
        connection
            .execute_batch("PRAGMA auto_vacuum=INCREMENTAL;")
            .map_err(|_| "sqlite-auto-vacuum-failed")?;
    }
    limit_busy(&connection, deadline)?;
    let mode: String = connection
        .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
        .map_err(|_| "sqlite-wal-failed")?;
    if mode != "wal" {
        return Err("sqlite-wal-failed");
    }
    limit_busy(&connection, deadline)?;
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
             families TEXT,
             trouble INTEGER NOT NULL CHECK (trouble IN (0, 1))
         ) STRICT;
         CREATE INDEX IF NOT EXISTS deeds_latest ON deeds (organ, verb, target, id DESC);",
        )
        .map_err(|_| "sqlite-initialize-failed")?;
    install_read_indexes(&mut connection, deadline)?;
    Ok(connection)
}

pub(super) fn offer(
    event: &ChannelEvent,
    projected: &ChannelEvent,
    mode: OfferMode,
) -> StoreResult<Disposition> {
    let policy = policy()?;
    let (class, trouble) = policy.classify(event, projected)?;
    let allowed = !matches!(mode, OfferMode::Normal) || class.level <= policy.body_level();
    if !allowed && trouble {
        return Ok(Disposition::Dropped); // A high-level trouble cannot be a recovery.
    }
    let level = if matches!(mode, OfferMode::Debug) { policy.highest } else { class.level };

    let fields = &projected.attributes_redacted;
    let field = |name: &str| fields[name].as_str();
    let kind = class.kind.as_str();
    let organ = projected.organ.as_str();
    let verb = field("verb");
    let outcome = field("outcome");
    let signal = field("signal");
    let target = if projected.kind == "generic-http-door" {
        // Its target is the routine name even when its correlation id is set.
        field("routine_id")
    } else {
        field("target")
    };
    let routine = field("run_id")
        .map(str::to_owned)
        .or_else(|| metadata_alias(&event.attributes_redacted, &["run_id"], 64))
        .or_else(|| projected.correlation_id.clone())
        // Retain the existing aliases when neither run nor correlation is set.
        .or_else(|| field("routine_id").map(str::to_owned))
        .or_else(|| metadata_alias(&event.attributes_redacted, &["routine_id", "routine"], 64));
    let key = Key {
        organ: organ.to_owned(),
        verb: verb.map(str::to_owned),
        target: target.map(str::to_owned),
    };
    let deadline = Instant::now() + STORE_WAIT;
    let mut lease = WriterLease::acquire(deadline)?;
    let store = &mut lease.0;
    if !allowed && !store.newest_is_trouble(&key, deadline)? {
        return Ok(Disposition::Dropped); // No write transaction or schema setup on a level drop.
    }

    let duration_ms = fields["duration_ms"].as_u64().map(|ms| {
        i64::try_from(ms)
            .map(SqlValue::Integer)
            .unwrap_or_else(|_| SqlValue::Text(ms.to_string()))
    });
    let families = policy.families(fields);

    let connection = store.writable(deadline)?;
    limit_busy(connection, deadline)?;
    // Recheck under the write lock: a different process may have changed the
    // key since the read-only lookup. Concurrent recoveries must not both write.
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "sqlite-begin-failed")?;
    if !allowed || trouble || kind == "state" {
        limit_busy(&tx, deadline)?;
        let latest = tx
            .query_row(
                "SELECT trouble, (outcome IS ?4) AND (signal IS ?5) AND (families IS ?6) FROM deeds
             WHERE organ = ?1 AND verb IS ?2 AND target IS ?3
             ORDER BY id DESC LIMIT 1",
                params![organ, verb, target, outcome, signal, families],
                |row| Ok((row.get::<_, bool>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()
            .map_err(|_| "sqlite-repeat-check-failed")?;
        if !allowed && !latest.is_some_and(|(prior_trouble, _)| prior_trouble) {
            return Ok(Disposition::Dropped); // No longer a recovery; leave the store unchanged.
        }
        // A transition into or out of trouble is not a repeat even when the
        // sender's three projected fields happen to be identical.
        if (trouble || kind == "state") && latest == Some((trouble, true)) {
            return Ok(Disposition::Dropped);
        }
    }
    limit_busy(&tx, deadline)?;
    // Use the same fixed-date predicate as AGE_KEY. 'now' and bare numbers
    // are not dates on a deed. SQLite supplies the write time in this insert.
    tx.execute(
        "INSERT INTO deeds (schema, kind, at, level, routine, body, organ, target,
                            who, verb, outcome, signal, duration_ms, families, trouble, source_ok)
         VALUES (?1, ?2, CASE
                    WHEN julianday(CASE WHEN substr(?3, 5, 1) = '-' THEN ?3 END)
                         <= julianday('now', '+1 day') THEN ?3
                    ELSE strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                END, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
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
            families,
            trouble,
            event.ok,
        ],
    )
    .map_err(|_| "sqlite-insert-failed")?;
    limit_busy(&tx, deadline)?;
    tx.commit().map_err(|_| "sqlite-commit-failed")?;
    store.remember(key, trouble);
    Ok(Disposition::Written)
}

fn open_existing(flags: OpenFlags) -> StoreResult<Option<(Connection, u64)>> {
    let path = config::path(DB_PATH);
    let size = match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => metadata.len(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        _ => return Err("sqlite-path-unavailable"),
    };
    let connection = Connection::open_with_flags(path, flags).map_err(|_| "sqlite-open-failed")?;
    connection.busy_timeout(STORE_WAIT).map_err(|_| "sqlite-busy-timeout-failed")?;
    Ok(Some((connection, size)))
}

fn existing_writer() -> StoreResult<Option<Connection>> {
    let Some((connection, _)) = open_existing(OpenFlags::SQLITE_OPEN_READ_WRITE)? else {
        return Ok(None);
    };
    connection
        .execute_batch("PRAGMA synchronous=NORMAL; PRAGMA temp_store=MEMORY;")
        .map_err(|_| "sqlite-upkeep-open-failed")?;
    Ok(Some(connection))
}

// At service start, upgrade the March 1 database without waiting for a deed.
// This is not part of the periodic pass, and neither path creates a store.
pub(crate) fn prepare_existing() -> StoreResult<()> {
    let deadline = Instant::now() + STORE_WAIT;
    let Some((reader, _)) = open_existing(OpenFlags::SQLITE_OPEN_READ_ONLY)? else {
        return Ok(());
    };
    if !has_deeds(&reader)? || indexes_installed(&reader)? {
        return Ok(());
    }
    drop(reader);
    if let Some(mut writer) = existing_writer()? {
        install_read_indexes(&mut writer, deadline)?;
    }
    Ok(())
}

const PRUNE_BATCH: usize = 200;
const PRUNE_GAP: Duration = Duration::from_millis(5);
// Match the repeat/recovery key, including nullable verb and target. The
// existing deeds_latest index makes this a seek rather than a second scan.
const NOT_OPEN_TROUBLE: &str = "(trouble = 0 OR EXISTS (
    SELECT 1 FROM deeds AS newer
    WHERE newer.organ IS deeds.organ AND newer.verb IS deeds.verb
      AND newer.target IS deeds.target AND newer.id > deeds.id
    LIMIT 1
))";

fn prune_batch(
    connection: &mut Connection,
    prunable: &str,
    cutoff: f64,
    ids: &[i64],
) -> StoreResult<usize> {
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| "sqlite-prune-begin-failed")?;
    let mut deleted = 0;
    {
        // Fence each delete against writers. Consume IDs oldest-first so an
        // expired recovery cannot expose an expired predecessor mid-pass.
        let mut delete = tx
            .prepare(&format!("DELETE FROM deeds WHERE id = ?2 AND {prunable}"))
            .map_err(|_| "sqlite-prune-delete-failed")?;
        for id in ids {
            deleted += delete
                .execute(params![cutoff, id])
                .map_err(|_| "sqlite-prune-delete-failed")?;
        }
    }
    if deleted == 0 {
        return Ok(0);
    }
    {
        // Bound reclamation as well as the delete work done under this lock.
        let mut stmt = tx
            .prepare("PRAGMA incremental_vacuum(64)")
            .map_err(|_| "sqlite-prune-vacuum-failed")?;
        let mut pages = stmt.query([]).map_err(|_| "sqlite-prune-vacuum-failed")?;
        while pages.next().map_err(|_| "sqlite-prune-vacuum-failed")?.is_some() {}
    }
    // A separate connection's commit invalidates the writer's trouble hints.
    tx.commit().map_err(|_| "sqlite-prune-commit-failed")?;
    Ok(deleted)
}

pub(crate) fn prune_expired() -> StoreResult<usize> {
    // Even opening a write connection on a quiet pass can checkpoint its WAL.
    let Some((reader, _)) = open_existing(OpenFlags::SQLITE_OPEN_READ_ONLY)? else {
        return Ok(0);
    };
    if !has_deeds(&reader)? {
        return Ok(0);
    }
    let cutoff: f64 = reader
        .query_row("SELECT julianday('now', '-90 days')", [], |row| row.get(0))
        .map_err(|_| "sqlite-prune-read-failed")?;
    let prunable = format!("{AGE_KEY} < ?1 AND {NOT_OPEN_TROUBLE}");
    let has_expired: bool = reader
        .query_row(
            &format!("SELECT EXISTS (SELECT 1 FROM deeds WHERE {prunable} LIMIT 1)"),
            [cutoff],
            |row| row.get(0),
        )
        .map_err(|_| "sqlite-prune-read-failed")?;
    if !has_expired {
        return Ok(0);
    }
    let end: Option<i64> = reader
        .query_row("SELECT MAX(id) FROM deeds", [], |row| row.get(0))
        .map_err(|_| "sqlite-prune-read-failed")?;
    let Some(end) = end else { return Ok(0); };
    // Once there is work, advance a rowid cursor instead of sorting the age
    // index again for every batch. No scan or snapshot spans a write lock.
    let mut select = reader
        .prepare(&format!(
            "SELECT id FROM deeds NOT INDEXED WHERE id >= ?2 AND id <= ?3 AND {prunable}
             ORDER BY id LIMIT ?4"
        ))
        .map_err(|_| "sqlite-prune-read-failed")?;
    let mut first = i64::MIN;
    let mut writer = None;
    let mut deleted = 0;
    let result = (|| {
        loop {
            let ids = select
                .query_map(params![cutoff, first, end, PRUNE_BATCH], |row| row.get::<_, i64>(0))
                .and_then(Iterator::collect::<Result<Vec<_>, _>>)
                .map_err(|_| "sqlite-prune-read-failed")?;
            let Some(&last) = ids.last() else { return Ok(()); };
            if writer.is_none() {
                writer = existing_writer()?;
            }
            let Some(writer) = writer.as_mut() else { return Ok(()); };
            deleted += prune_batch(writer, &prunable, cutoff, &ids)?;
            if ids.len() < PRUNE_BATCH || last == end {
                return Ok(());
            }
            first = last + 1;
            // Give waiting native CLI writers a turn as well as daemon writers.
            std::thread::sleep(PRUNE_GAP);
        }
    })();
    if let Err(error) = result {
        if deleted == 0 {
            return Err(error);
        }
        // Earlier transactions are durable. Report the interruption and let
        // the existing caller record their total once, not lose it on error.
        eprintln!("caduceus-hyalos-prune-incomplete: {error}");
    }
    Ok(deleted)
}

#[derive(Default)]
pub(crate) struct LogFilters {
    pub kind: Option<String>,
    pub organ: Option<String>,
    pub verb: Option<String>,
    pub level: Option<i64>,
    pub since: Option<String>,
}

#[derive(Default)]
pub(crate) struct DeedPage {
    pub rows: Vec<Value>,
    pub total: i64,
    pub file_size: u64,
}

const ROW_COLUMNS: &str = "id, schema, kind, at, level, routine, body, organ, target, who, verb,
                           outcome, signal, duration_ms, families, trouble";

fn row_json(row: &Row<'_>) -> StoreResult<Value> {
    let invalid = |_| "sqlite-deed-row-invalid";
    let text = |name| row.get::<_, Option<String>>(name).map_err(invalid);
    let integer = |name| row.get::<_, i64>(name).map_err(invalid);
    let duration = match row.get::<_, SqlValue>("duration_ms").map_err(invalid)? {
        SqlValue::Null => None,
        SqlValue::Integer(ms) if ms >= 0 => Some(ms as u64),
        SqlValue::Text(ms) => Some(ms.parse::<u64>().map_err(|_| "sqlite-deed-row-invalid")?),
        _ => return Err("sqlite-deed-row-invalid"),
    };
    let families = text("families")?
        .as_deref()
        .map(serde_json::from_str::<Map<String, Value>>)
        .transpose()
        .map_err(|_| "sqlite-deed-row-invalid")?;
    Ok(json!({
        "id": integer("id")?, "schema": text("schema")?, "kind": text("kind")?,
        "at": text("at")?, "level": integer("level")?, "routine": text("routine")?,
        "body": text("body")?, "organ": text("organ")?, "target": text("target")?,
        "who": text("who")?, "verb": text("verb")?, "outcome": text("outcome")?,
        "signal": text("signal")?, "duration_ms": duration, "families": families,
        "trouble": row.get::<_, bool>("trouble").map_err(invalid)?,
    }))
}

#[derive(Default)]
struct Selection {
    terms: Vec<String>,
    args: Vec<SqlValue>,
}

impl Selection {
    fn filter(&mut self, term: impl Into<String>, value: Option<impl Into<SqlValue>>) {
        if let Some(value) = value {
            self.terms.push(term.into());
            self.args.push(value.into());
        }
    }

    fn clause(&self) -> String {
        if self.terms.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.terms.join(" AND "))
        }
    }

    fn total(&self, connection: &Connection) -> StoreResult<i64> {
        connection
            .query_row(
                &format!("SELECT COUNT(*) FROM deeds{} LIMIT 1", self.clause()),
                params_from_iter(&self.args),
                |row| row.get(0),
            )
            .map_err(|_| "sqlite-deed-count-failed")
    }

    fn rows(&self, connection: &Connection, offset: usize, limit: usize) -> StoreResult<Vec<Value>> {
        let pagination = [limit as i64, i64::try_from(offset).unwrap_or(i64::MAX)];
        let mut stmt = connection
            .prepare(&format!("SELECT {ROW_COLUMNS} FROM deeds{} ORDER BY id DESC LIMIT ? OFFSET ?", self.clause()))
            .map_err(|_| "sqlite-deed-select-failed")?;
        let mut rows = stmt
            .query(params_from_iter(self.args.iter().cloned().chain(pagination.map(SqlValue::Integer))))
            .map_err(|_| "sqlite-deed-select-failed")?;
        let mut page = Vec::new();
        while let Some(row) = rows.next().map_err(|_| "sqlite-deed-select-failed")? {
            page.push(row_json(row)?);
        }
        Ok(page)
    }
}

fn read<T: Default>(query: impl FnOnce(&Connection) -> StoreResult<T>) -> StoreResult<(T, u64)> {
    let Some((mut connection, file_size)) = open_existing(OpenFlags::SQLITE_OPEN_READ_ONLY)? else {
        return Ok((T::default(), 0));
    };
    connection.execute_batch("PRAGMA temp_store=MEMORY;").map_err(|_| "sqlite-read-open-failed")?;
    // The filtered total and the page describe the same WAL snapshot.
    let tx = connection.transaction().map_err(|_| "sqlite-read-begin-failed")?;
    let result = if has_deeds(&tx)? { query(&tx)? } else { T::default() };
    Ok((result, file_size))
}

pub(crate) fn read_page(offset: usize, limit: usize, filters: LogFilters) -> StoreResult<DeedPage> {
    let mut selection = Selection::default();
    selection.filter("kind = ?", filters.kind);
    selection.filter("organ = ?", filters.organ);
    selection.filter("verb = ?", filters.verb);
    selection.filter("level <= ?", filters.level);
    selection.filter(format!("{AGE_KEY} >= julianday(?)"), filters.since);
    let ((rows, total), file_size) = read(|connection| {
        let total = selection.total(connection)?;
        if limit == 0 || i64::try_from(offset).unwrap_or(i64::MAX) >= total {
            return Ok((Vec::new(), total));
        }
        Ok((selection.rows(connection, offset, limit)?, total))
    })?;
    Ok(DeedPage { rows, total, file_size })
}

pub(super) fn read_tail(filters: &TailFilters, limit: usize) -> StoreResult<(Vec<Value>, u64)> {
    let level = filters.level.as_deref().map(str::parse::<i64>).transpose()
        .map_err(|_| "hyalos-tail-level-invalid")?;
    let mut selection = Selection::default();
    selection.filter("(kind = :kind OR verb = :kind)", filters.kind.clone());
    selection.filter("organ = ?", filters.organ.clone());
    selection.filter("routine = ?", filters.correlation_id.clone());
    selection.filter("level = ?", level);
    read(|connection| {
        if let Some(ok) = filters.ok {
            // A read-only CLI may run before the writer upgrades an old store.
            let key = if has_source_ok(connection)? { OK_KEY } else { "NOT trouble" };
            selection.filter(format!("({key}) = ?"), Some(i64::from(ok)));
        }
        selection.rows(connection, 0, limit)
    })
}

pub(crate) fn read_harmonia_runs() -> StoreResult<Vec<Value>> {
    let selection = Selection {
        // Filter on the sender's verb even for versioned rows from before the
        // kinds-seat change. Only the newest profile deed per run uses a slot.
        terms: vec![PROFILE_DEEDS.into(), format!(
            "NOT EXISTS (SELECT 1 FROM deeds AS newer WHERE {PROFILE_DEEDS}
             AND newer.routine = deeds.routine AND newer.id > deeds.id LIMIT 1)"
        )],
        args: Vec::new(),
    };
    read(|connection| selection.rows(connection, 0, 10)).map(|(rows, _)| rows)
}
