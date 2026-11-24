use std::{fs, net::Ipv4Addr};

pub(crate) struct NameRecord {
    pub name: String,
    pub ip: String,
    pub alias: bool,
}

/// Read only the configured root file and the immediate .conf directory.
pub(crate) fn read() -> Result<Vec<NameRecord>, String> {
    let root = crate::shared::config::path("etc/unbound");
    let mut paths = vec![root.join("unbound.conf")];
    let directory = root.join("unbound.conf.d");
    let mut entries = fs::read_dir(directory).map_err(|e| e.to_string())?
        .map(|entry| entry.map(|e| e.path()).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort();
    for path in entries {
        if path.extension().is_some_and(|ext| ext == "conf")
            && fs::symlink_metadata(&path).map_err(|e| e.to_string())?.file_type().is_file() {
            paths.push(path);
        }
    }
    let mut result = Vec::new();
    for path in paths {
        let is_owned_file = path.file_name().is_some_and(|name| name == "agathodaimon-local-names.conf");
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        let mut owned = false;
        for line in text.lines() {
            if is_owned_file && line.trim() == "# BEGIN CADUCEUS OWNED DEVICE RECORDS" { owned = true; continue; }
            if is_owned_file && line.trim() == "# END CADUCEUS OWNED DEVICE RECORDS" { owned = false; continue; }
            let Some(rest) = line.trim().strip_prefix("local-data:") else { continue };
            let Some(rest) = rest.trim_start().strip_prefix('"') else { continue };
            let Some((content, tail)) = rest.split_once('"') else { continue };
            let mut fields = content.split_whitespace();
            let Some(name) = fields.next() else { continue };
            let Some(mut kind) = fields.next() else { continue };
            if kind.eq_ignore_ascii_case("IN") {
                let Some(next) = fields.next() else { continue }; kind = next;
            }
            if !kind.eq_ignore_ascii_case("A") { continue; }
            let Some(ip) = fields.next().and_then(|s| s.parse::<Ipv4Addr>().ok()) else { continue };
            let name = name.trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() { continue; }
            let alias = owned && tail.trim_start().strip_prefix("# agathodaimon-alias ")
                .is_some_and(|canonical| !canonical.trim().is_empty());
            result.push(NameRecord { name, ip: ip.to_string(), alias });
        }
    }
    Ok(result)
}
