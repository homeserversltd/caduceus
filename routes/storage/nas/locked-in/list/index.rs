use axum::{http::StatusCode, routing::post, Json, Router};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use serde_json::{json, Value};
use std::{sync::Mutex, time::{Duration, Instant}};

const STOP: &str = "storage/nas/setup/prefire";
const UNAVAILABLE: &str = "nas-lock-in-unavailable";
static ADOPTION: Mutex<()> = Mutex::new(());

#[derive(Clone, Serialize)]
pub(crate) struct LockedInDrive {
    pub part_uuid: String,
    pub role: String,
    pub holder: String,
    pub size_bytes: i64,
    pub locked_in_at: String,
}

fn initialize(db: &Connection) -> Result<(), String> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS nas_drives_locked_in (part_uuid TEXT PRIMARY KEY, role TEXT, holder TEXT, size_bytes INTEGER, locked_in_at TEXT)").map_err(|_| UNAVAILABLE)?;
    let mut stmt = db.prepare("PRAGMA table_info(nas_drives_locked_in)").map_err(|_| UNAVAILABLE)?;
    let columns = stmt.query_map([], |r| r.get::<_, String>(1)).map_err(|_| UNAVAILABLE)?
        .collect::<Result<Vec<_>, _>>().map_err(|_| UNAVAILABLE)?;
    for (name, ty) in [("role", "TEXT"), ("holder", "TEXT"), ("size_bytes", "INTEGER"), ("locked_in_at", "TEXT")] {
        if !columns.iter().any(|c| c == name) {
            db.execute_batch(&format!("ALTER TABLE nas_drives_locked_in ADD COLUMN {name} {ty}")).map_err(|_| UNAVAILABLE)?;
        }
    }
    Ok(())
}

fn with_db<T>(f: impl FnOnce(&mut Connection) -> Result<T, String>) -> Result<T, String> {
    let shared = crate::stats::open_db().map_err(|_| UNAVAILABLE)?;
    let mut db = shared.lock().map_err(|_| UNAVAILABLE)?;
    initialize(&db)?;
    f(&mut db)
}

fn row(r: &rusqlite::Row<'_>) -> rusqlite::Result<LockedInDrive> {
    Ok(LockedInDrive { part_uuid: r.get(0)?, role: r.get(1)?, holder: r.get(2)?, size_bytes: r.get(3)?, locked_in_at: r.get(4)? })
}

pub(crate) fn read_all() -> Result<Vec<LockedInDrive>, String> {
    with_db(|db| {
        let mut q = db.prepare("SELECT part_uuid,role,holder,size_bytes,locked_in_at FROM nas_drives_locked_in ORDER BY role,part_uuid").map_err(|_| UNAVAILABLE)?;
        let rows = q.query_map([], row).map_err(|_| UNAVAILABLE)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|_| UNAVAILABLE.into())
    })
}

pub(crate) fn read_by_uuid(uuid: &str) -> Result<Option<LockedInDrive>, String> {
    with_db(|db| db.query_row("SELECT part_uuid,role,holder,size_bytes,locked_in_at FROM nas_drives_locked_in WHERE part_uuid=?1", [uuid], row).optional().map_err(|_| UNAVAILABLE.into()))
}

fn read_role(role: &str) -> Result<Option<LockedInDrive>, String> {
    with_db(|db| db.query_row("SELECT part_uuid,role,holder,size_bytes,locked_in_at FROM nas_drives_locked_in WHERE role=?1 ORDER BY locked_in_at,part_uuid LIMIT 1", [role], row).optional().map_err(|_| UNAVAILABLE.into()))
}

pub(crate) fn primary_row() -> Result<Option<LockedInDrive>, String> { read_role("primary") }

pub(crate) fn insert_row(drive: &LockedInDrive) -> Result<bool, String> {
    with_db(|db| db.execute("INSERT OR IGNORE INTO nas_drives_locked_in(part_uuid,role,holder,size_bytes,locked_in_at) VALUES(?1,?2,?3,?4,?5)", params![drive.part_uuid,drive.role,drive.holder,drive.size_bytes,drive.locked_in_at]).map(|n| n == 1).map_err(|_| UNAVAILABLE.into()))
}

pub(crate) fn delete_by_holder(holder: &str) -> Result<usize, String> {
    with_db(|db| db.execute("DELETE FROM nas_drives_locked_in WHERE holder=?1", [holder]).map_err(|_| UNAVAILABLE.into()))
}

pub(crate) fn adopt(role: &str) -> Result<(), String> {
    let _guard = ADOPTION.lock().map_err(|_| UNAVAILABLE)?;
    if !matches!(role, "primary" | "backup") { return Err("nas-lock-in-role-invalid".into()); }
    if read_role(role)?.is_some() { return Ok(()); }
    let started = Instant::now();
    let label = format!("homeserver-{role}-nas");
    let Some(device) = crate::routes::leaf_storage_disk_census::mounted_role_disk(&label)? else { return Ok(()); };
    let crossed = crate::gate::snake::crossing_path_with_timeout(STOP, &json!({"device": device, "role": role}), Duration::from_secs(60))?;
    if crossed["ok"] != true { return Err("nas-lock-in-prefire-failed".into()); }
    let receipt = crossed.get("receiptPayload").ok_or("nas-lock-in-prefire-failed")?;
    if receipt["ok"] != true || !crate::routes::leaf_schema::bound(receipt, STOP) { return Err("nas-lock-in-prefire-failed".into()); }
    let Some(uuid) = receipt.get("partUuid").and_then(Value::as_str).filter(|v| !v.is_empty()) else { return Ok(()); };
    let size = receipt.get("sizeBytes").and_then(Value::as_i64).filter(|n| *n > 0).ok_or("nas-lock-in-prefire-failed")?;
    let drive = LockedInDrive { part_uuid: uuid.to_owned(), role: role.to_owned(), holder: "this".into(), size_bytes: size, locked_in_at: chrono::Utc::now().to_rfc3339() };
    if insert_row(&drive)? {
        let _ = crate::shared::hyalos::reflect_json_with_stderr_fallback(json!({"organ":"nas-lock-in","kind":"deed","ok":true,"message":"nas lock-in deed","attributes_redacted":{"who":role,"verb":"adopt","target":uuid,"outcome":"complete","signal":"none","duration_ms":started.elapsed().as_millis().min(u64::MAX as u128) as u64}}));
    }
    Ok(())
}

async fn list() -> (StatusCode, Json<Value>) {
    let result = crate::gate::blocking_task("storage nas locked-in list", || {
        let _ = adopt("primary");
        let _ = adopt("backup");
        read_all()
    }).await;
    match result {
        Ok(Ok(drives)) => (StatusCode::OK, Json(json!({"ok":true,"firstMissingSignal":"none","drives":drives}))),
        _ => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"ok":false,"firstMissingSignal":UNAVAILABLE,"drives":[]}))),
    }
}

pub fn register(router: Router) -> Router {
    router.route(LEAF_STORAGE_NAS_LOCKED_IN_LIST_CANONICAL, post(list))
}
