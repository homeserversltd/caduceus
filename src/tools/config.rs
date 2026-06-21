use std::fs;
use std::path::PathBuf;

pub fn root() -> PathBuf {
    std::env::var_os("CADUCEUS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn path(relative: &str) -> PathBuf {
    root().join(relative.trim_start_matches('/'))
}

pub fn read_public_file(relative: &str) -> Result<String, String> {
    let path = path(relative);
    fs::read_to_string(&path).map_err(|err| format!("{}: {err}", path.display()))
}
