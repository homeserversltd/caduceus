//! Bounded asynchronous press of Harmonia's update invocation membrane.
//!
//! The background thread shares the synchronous `update now` path, including
//! Harmonia invocation and receipt publication. Caduceus retains only an
//! in-process single-flight guard.

use crate::bands::update;
use serde_json::{json, Value};
use std::sync::{Mutex, OnceLock};

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

    *active = true;
    std::thread::spawn(move || {
        let _ = update::invoke_now_json(&[]);
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
