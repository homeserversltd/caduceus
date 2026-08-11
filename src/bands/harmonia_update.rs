//! Bounded asynchronous press of Harmonia's own update front door.
//!
//! This band starts exactly `harmonia update --apply` through Caduceus's
//! non-interactive privilege membrane. Harmonia remains the sole writer of its
//! completion receipt; Caduceus retains only an in-process single-flight guard.

use serde_json::{json, Value};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

const HARMONIA_BIN: &str = "/usr/local/bin/harmonia";
const RUN_LOCK: &str = "harmonia-update-in-flight";

fn run_active() -> &'static Mutex<bool> {
    static RUN_ACTIVE: OnceLock<Mutex<bool>> = OnceLock::new();
    RUN_ACTIVE.get_or_init(|| Mutex::new(false))
}

pub fn start_json() -> Result<Value, &'static str> {
    let mut active = run_active()
        .lock()
        .map_err(|_| "caduceus-harmonia-update-lock-unavailable")?;
    if *active {
        return Err(RUN_LOCK);
    }

    let mut child = Command::new("sudo")
        .args(["-n", HARMONIA_BIN, "update", "--apply"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "caduceus-harmonia-update-unavailable")?;

    *active = true;
    std::thread::spawn(move || {
        let _ = child.wait();
        if let Ok(mut active) = run_active().lock() {
            *active = false;
        }
    });

    Ok(json!({
        "ok": true,
        "action": "harmonia-update",
        "state": "started",
        "runLock": RUN_LOCK
    }))
}
