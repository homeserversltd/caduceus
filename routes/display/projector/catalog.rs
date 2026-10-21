//! Product state shares Caduceus's existing database; replies are never stored.
use super::KnownProductEntry;
use crate::{
    routes::leaf_schema,
    shared::{config, hyalos},
    stats,
};
use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Value};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader, Read},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::PathBuf,
    time::Instant,
};

const SCHEMA: &str = "caduceus.pjlink.known_product.v1";

pub(super) fn schema() -> Result<String, String> {
    leaf_schema::declaration(SCHEMA)
        .and_then(|seat| seat.get("schema"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| "caduceus-pjlink-catalog-schema-desync".into())
}

fn initialize(connection: &Connection) -> Result<(), String> {
    schema()?;
    connection
        .execute_batch(
            "CREATE TABLE IF NOT EXISTS pjlink_known_products (
        id TEXT PRIMARY KEY, device_id TEXT, host TEXT, port INTEGER,
        manufacturer TEXT, product_name TEXT, other_info TEXT, class TEXT,
        source TEXT, first_seen_epoch INTEGER, last_seen_epoch INTEGER
    );",
        )
        .map_err(|error| error.to_string())
}

fn put(connection: &Connection, entry: &KnownProductEntry, importing: bool) -> Result<(), String> {
    let sql = if importing {
        // A committed import retried after failed unlink never overwrites current rows.
        "INSERT OR IGNORE INTO pjlink_known_products VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
    } else {
        "INSERT INTO pjlink_known_products VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
         ON CONFLICT(id) DO UPDATE SET device_id=excluded.device_id, host=excluded.host,
         port=excluded.port, manufacturer=excluded.manufacturer, product_name=excluded.product_name,
         other_info=excluded.other_info, class=excluded.class, source=excluded.source,
         first_seen_epoch=excluded.first_seen_epoch, last_seen_epoch=excluded.last_seen_epoch"
    };
    connection
        .execute(
            sql,
            params![
                entry.id,
                entry.device_id,
                entry.host,
                entry.port,
                entry.manufacturer,
                entry.product_name,
                entry.other_info,
                entry.class,
                entry.source,
                entry.first_seen_epoch,
                entry.last_seen_epoch
            ],
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn legacy_path() -> Result<PathBuf, String> {
    let profile = config::read_public_profile_value()?;
    if let Some(path) = profile
        .pointer("/pjlink/catalog_path")
        .and_then(Value::as_str)
    {
        return Ok(config::path(path));
    }
    // The retired suffix is recognized only for the one-time import, never a writer.
    Ok(config::path("var/lib/caduceus/pjlink-known-products")
        .with_extension(["json", "l"].concat()))
}

fn deed(verb: &str, target: &str, started: Instant, ok: bool, signal: &str) -> Result<(), String> {
    hyalos::reflect_json(json!({
        "organ": "caduceus", "kind": "pjlink-catalog", "message": "catalog deed", "ok": ok,
        "attributes_redacted": {"who": "caduceus", "verb": verb, "target": target,
            "outcome": if ok { "success" } else { "failure" },
            "duration_ms": started.elapsed().as_millis() as u64, "signal": signal,
            "first_missing_field": if ok { Value::Null } else { json!("catalog") }}
    }))
    .map(|_| ())
}

pub(super) fn import_legacy() -> Result<(), String> {
    let path = legacy_path()?;
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("caduceus-pjlink-catalog-unreadable".into()),
    };
    let started = Instant::now();
    // Serialize concurrent processes, including a reader that opened before unlink.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err("caduceus-pjlink-catalog-lock-failed".into());
    }
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err("caduceus-pjlink-catalog-unreadable".into()),
    };
    let opened = file.metadata().map_err(|error| error.to_string())?;
    if opened.dev() != metadata.dev() || opened.ino() != metadata.ino() {
        return Err("caduceus-pjlink-catalog-changed".into());
    }
    let result = (|| {
        let mut connection = stats::open_db()?
            .lock()
            .map_err(|_| "caduceus-pjlink-catalog-lock-poisoned")?;
        initialize(&connection)?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        let mut reader = BufReader::new(&file);
        let mut line_number = 0;
        loop {
            let mut line = String::new();
            let length = reader
                .by_ref()
                .take(65_537)
                .read_line(&mut line)
                .map_err(|_| "caduceus-pjlink-catalog-unreadable")?;
            if length == 0 {
                break;
            }
            line_number += 1;
            if length > 65_536 {
                return Err("caduceus-pjlink-catalog-line-too-large".into());
            }
            if line.trim().is_empty() {
                continue;
            }
            let mut value: Value = serde_json::from_str(&line)
                .map_err(|_| format!("caduceus-pjlink-catalog-line-{line_number}-invalid"))?;
            if value.get("schema").and_then(Value::as_str)
                == Some("caduceus.pjlink.known-product.v1")
            {
                value["schema"] = json!(schema()?);
            }
            if !leaf_schema::accepts(SCHEMA, &value) {
                return Err("caduceus-pjlink-catalog-schema-desync".into());
            }
            let entry: KnownProductEntry = serde_json::from_value(value)
                .map_err(|_| format!("caduceus-pjlink-catalog-line-{line_number}-invalid"))?;
            if entry.id.is_empty() {
                return Err("caduceus-pjlink-catalog-identity-missing".into());
            }
            // First occurrence wins for duplicate legacy identities, matching keyed import.
            put(&transaction, &entry, true)?;
        }
        transaction.commit().map_err(|error| error.to_string())?;
        fs::remove_file(&path).map_err(|_| "caduceus-pjlink-catalog-unlink-failed".to_owned())?;
        Ok(())
    })();
    let signal = if result.is_ok() {
        "none"
    } else {
        "caduceus-pjlink-catalog-import-failed"
    };
    deed(
        "pjlink-catalog-import",
        "pjlink_known_products",
        started,
        result.is_ok(),
        signal,
    )?;
    result
}

pub(super) fn list() -> Result<Vec<KnownProductEntry>, String> {
    import_legacy()?;
    // A query on an uninitialized body creates no database, directory or log.
    if !stats::db_path()
        .try_exists()
        .map_err(|error| error.to_string())?
    {
        return Ok(Vec::new());
    }
    let connection =
        Connection::open_with_flags(stats::db_path(), OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|error| error.to_string())?;
    let exists: bool = connection.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='pjlink_known_products')", [], |row| row.get(0))
        .map_err(|error| error.to_string())?;
    if !exists {
        return Ok(Vec::new());
    }
    let schema = schema()?;
    let mut statement = connection.prepare("SELECT id,device_id,host,port,manufacturer,product_name,other_info,class,source,first_seen_epoch,last_seen_epoch FROM pjlink_known_products ORDER BY id")
        .map_err(|error| error.to_string())?;
    let rows = statement
        .query_map([], |row| {
            Ok(KnownProductEntry {
                schema: schema.clone(),
                id: row.get(0)?,
                device_id: row.get(1)?,
                host: row.get(2)?,
                port: row.get(3)?,
                manufacturer: row.get(4)?,
                product_name: row.get(5)?,
                other_info: row.get(6)?,
                class: row.get(7)?,
                source: row.get(8)?,
                first_seen_epoch: row.get(9)?,
                last_seen_epoch: row.get(10)?,
            })
        })
        .map_err(|error| error.to_string())?;
    rows.map(|row| row.map_err(|error| error.to_string()))
        .collect()
}

pub(super) fn add(entry: &KnownProductEntry) -> Result<usize, String> {
    import_legacy()?;
    let started = Instant::now();
    let result = (|| {
        let mut connection = stats::open_db()?
            .lock()
            .map_err(|_| "caduceus-pjlink-catalog-lock-poisoned")?;
        initialize(&connection)?;
        let transaction = connection
            .transaction()
            .map_err(|error| error.to_string())?;
        put(&transaction, entry, false)?;
        let count = transaction
            .query_row("SELECT count(*) FROM pjlink_known_products", [], |row| {
                row.get(0)
            })
            .map_err(|error| error.to_string())?;
        transaction.commit().map_err(|error| error.to_string())?;
        Ok(count)
    })();
    deed(
        "pjlink-known-add",
        &entry.id,
        started,
        result.is_ok(),
        if result.is_ok() {
            "none"
        } else {
            "caduceus-pjlink-catalog-write-failed"
        },
    )?;
    result
}

pub(super) fn remove(id: &str) -> Result<(usize, usize), String> {
    import_legacy()?;
    if !stats::db_path()
        .try_exists()
        .map_err(|error| error.to_string())?
    {
        return Ok((0, 0));
    }
    let started = Instant::now();
    let mut connection = stats::open_db()?
        .lock()
        .map_err(|_| "caduceus-pjlink-catalog-lock-poisoned")?;
    initialize(&connection)?;
    let transaction = connection
        .transaction()
        .map_err(|error| error.to_string())?;
    let removed = transaction
        .execute("DELETE FROM pjlink_known_products WHERE id=?1", [id])
        .map_err(|error| error.to_string())?;
    let count = transaction
        .query_row("SELECT count(*) FROM pjlink_known_products", [], |row| {
            row.get(0)
        })
        .map_err(|error| error.to_string())?;
    transaction.commit().map_err(|error| error.to_string())?;
    if removed > 0 {
        deed("pjlink-known-remove", id, started, true, "none")?;
    }
    Ok((removed, count))
}
