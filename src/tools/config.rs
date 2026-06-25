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

pub fn read_public_profile_text() -> Result<String, String> {
    let mut errors = Vec::new();
    for candidate in [
        "etc/caduceus/profile.yaml",
        "etc/caduceus/profile.yml",
        "etc/caduceus/profile.json",
    ] {
        match read_public_file(candidate) {
            Ok(text) => return Ok(text),
            Err(err) => errors.push(err),
        }
    }
    Err(format!("caduceus-profile-missing: {}", errors.join("; ")))
}

pub fn read_public_profile_value() -> Result<serde_json::Value, String> {
    let text = read_public_profile_text()?;
    serde_yaml::from_str(&text).map_err(|err| format!("caduceus-profile-invalid: {err}"))
}

pub fn public_profile_present() -> bool {
    read_public_profile_text().is_ok()
}

pub fn read_file_at(absolute: &str) -> Result<String, String> {
    fs::read_to_string(absolute).map_err(|err| format!("{absolute}: {err}"))
}
