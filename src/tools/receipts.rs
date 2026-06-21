use crate::tools::config;
use std::fs;

pub fn write_latest(body: &str) -> Result<(), String> {
    let path = config::path("var/lib/caduceus/receipts/latest/run.txt");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("{}: {err}", parent.display()))?;
    }
    fs::write(&path, body).map_err(|err| format!("{}: {err}", path.display()))
}
