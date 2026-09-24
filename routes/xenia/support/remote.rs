use super::{observation, seat, Result};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const LIMIT: usize = 1024 * 1024;
const FORGEJO_CREDENTIAL: &str = "/home/owner/.ssh/forgejo-token";

fn token_from_contents(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let value = line.trim();
        if value.is_empty() {
            return None;
        }
        value
            .strip_prefix("FORGEJO_TOKEN=")
            .map(str::trim)
            .or((!value.contains('=')).then_some(value))
            .filter(|token| !token.is_empty())
            .map(str::to_owned)
    })
}

fn resolve_path(path: &Path) -> Result<String> {
    let metadata = std::fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            observation("F", "forge.credential", "forge-credential-absent")
        } else {
            observation("F", "forge.credential", "forge-credential-unreadable")
        }
    })?;
    if !metadata.is_file() {
        return Err(observation(
            "F",
            "forge.credential",
            "forge-credential-not-regular-file",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(observation(
            "F",
            "forge.credential",
            "forge-credential-permissive",
        ));
    }
    let contents = std::fs::read_to_string(path)
        .map_err(|_| observation("F", "forge.credential", "forge-credential-unreadable"))?;
    token_from_contents(&contents)
        .ok_or_else(|| observation("F", "forge.credential", "forge-credential-invalid"))
}

fn forgejo_token() -> Result<String> {
    resolve_path(Path::new(FORGEJO_CREDENTIAL))
}

/// Only release metadata and the two evidence assets enter this HTTPS reader.
/// curl's own total deadline covers DNS, connect and response transfer. Reading
/// at most LIMIT+3 bounds the body plus its three-byte HTTP status trailer.
struct HttpsResponse {
    status: u16,
    body: Vec<u8>,
}

/// Normalize only full commit references; return the lookup tag and the
/// underlying commit identity without letting the tag become that identity.
fn commit_reference(reference: &str) -> Option<(String, String)> {
    let (sha, bare) = match reference.strip_prefix("sha-") {
        Some(sha)
            if sha.len() == 40
                && sha
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            (sha, false)
        }
        Some(_) => return None,
        None
            if reference.len() == 40
                && reference
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            (reference, true)
        }
        None => return None,
    };
    let lookup_tag = if bare {
        format!("sha-{sha}")
    } else {
        reference.to_owned()
    };
    Some((lookup_tag, sha.to_owned()))
}

fn https(url: &str, token: &str) -> Result<HttpsResponse> {
    if !std::path::Path::new("/usr/bin/curl").is_file() {
        return Err(observation("F", "source", "curl-absent"));
    }
    let parsed = url::Url::parse(url).map_err(|e| observation("F", "source", e.to_string()))?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(observation("F", "source", "release-https-required"));
    }
    let escaped = token.replace('\\', "\\\\").replace('"', "\\\"");
    let mut child = Command::new("/usr/bin/curl")
        .args([
            "--disable",
            "--silent",
            "--fail",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "15",
            "--connect-timeout",
            "5",
            "--max-filesize",
            "1048576",
            "--write-out",
            "%{http_code}",
            "--cacert",
            "/etc/ssl/certs/ca-certificates.crt",
            "--config",
            "-",
            "--url",
            url,
        ])
        .env_remove("CURL_CA_BUNDLE")
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| observation("F", "source", format!("curl-launch: {e}")))?;
    child
        .stdin
        .take()
        .ok_or_else(|| observation("F", "forge.credential", "curl-auth-config-absent"))?
        .write_all(format!("header = \"Authorization: token {escaped}\"\n").as_bytes())
        .map_err(|_| observation("F", "forge.credential", "curl-auth-config-failed"))?;
    let mut bytes = Vec::new();
    let read = child
        .stdout
        .take()
        .ok_or_else(|| observation("F", "source", "curl-pipe-absent"))?
        .take((LIMIT + 4) as u64)
        .read_to_end(&mut bytes);
    if read.is_err() || bytes.len() > LIMIT + 3 {
        let _ = child.kill();
        let _ = child.wait();
        return Err(observation(
            "F",
            "source",
            "release-response-size-or-read-failed",
        ));
    }
    // Drain the bounded output and reap curl before interpreting its trailer;
    // malformed or missing status text must not leave the child unreaped.
    let exit = child
        .wait()
        .map_err(|e| observation("F", "source", e.to_string()))?;
    if bytes.len() < 3 {
        return Err(observation("F", "source", "release-http-status-absent"));
    }
    let status_start = bytes.len() - 3;
    let status = std::str::from_utf8(&bytes[status_start..])
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| observation("F", "source", "release-http-status-absent"))?;
    bytes.truncate(status_start);
    if bytes.len() > LIMIT {
        return Err(observation(
            "F",
            "source",
            "release-response-size-or-read-failed",
        ));
    }
    if !exit.success() && !(exit.code() == Some(22) && status == 404) {
        return Err(observation("F", "source", format!("curl-failed: {exit}")));
    }
    Ok(HttpsResponse {
        status,
        body: bytes,
    })
}

/// Local HTTP observations never use the release transport or carry credentials.
pub fn local(port: u16, path: &str, check: &str) -> Result<Vec<u8>> {
    if !path.starts_with('/') || path.contains(['\r', '\n']) {
        return Err(observation(check, path, "local-observation-path-invalid"));
    }
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(3))
        .map_err(|e| observation(check, path, format!("observation-failed: {e}")))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| observation(check, path, e.to_string()))?;
    stream.write_all(format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nAccept: application/json\r\n\r\n").as_bytes())
        .map_err(|e| observation(check, path, e.to_string()))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut bytes = Vec::new();
    loop {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| observation(check, path, "observation-timeout"))?;
        stream
            .set_read_timeout(Some(left))
            .map_err(|e| observation(check, path, e.to_string()))?;
        let mut block = [0u8; 4096];
        let count = stream
            .read(&mut block)
            .map_err(|e| observation(check, path, e.to_string()))?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&block[..count]);
        if bytes.len() > LIMIT {
            return Err(observation(check, path, "observation-size-exceeded"));
        }
    }
    let split = bytes
        .windows(4)
        .position(|b| b == b"\r\n\r\n")
        .ok_or_else(|| observation(check, path, "http-header-absent"))?;
    let head = std::str::from_utf8(&bytes[..split])
        .map_err(|e| observation(check, path, e.to_string()))?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1));
    if status != Some("200") {
        return Err(observation(
            check,
            path,
            format!("http-observation-status: {status:?}"),
        ));
    }
    let body = &bytes[split + 4..];
    if head.lines().any(|line| {
        line.to_ascii_lowercase()
            .starts_with("transfer-encoding: chunked")
    }) {
        let mut remaining = body;
        let mut out = Vec::new();
        loop {
            let end = remaining
                .windows(2)
                .position(|b| b == b"\r\n")
                .ok_or_else(|| observation(check, path, "chunk-size-absent"))?;
            let size = std::str::from_utf8(&remaining[..end])
                .ok()
                .and_then(|s| usize::from_str_radix(s.split(';').next().unwrap_or(""), 16).ok())
                .ok_or_else(|| observation(check, path, "chunk-size-invalid"))?;
            remaining = &remaining[end + 2..];
            if size == 0 {
                return Ok(out);
            }
            if size > remaining.len().saturating_sub(2) || &remaining[size..size + 2] != b"\r\n" {
                return Err(observation(check, path, "chunk-body-truncated"));
            }
            out.extend_from_slice(&remaining[..size]);
            remaining = &remaining[size + 2..];
        }
    }
    if let Some(length) = head.lines().find_map(|line| {
        line.to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::trim)
            .and_then(|s| s.parse::<usize>().ok())
    }) {
        if length != body.len() {
            return Err(observation(check, path, "http-body-truncated"));
        }
    }
    Ok(body.to_vec())
}

pub fn crown_port() -> Result<u16> {
    crate::shared::config::get_json("coronatio.bind")
        .ok()
        .and_then(|value| {
            value
                .get("value")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .and_then(|bind| bind.parse::<SocketAddr>().ok())
        .map(|bind| bind.port())
        .ok_or_else(|| observation("A", "coronatio.bind", "crown-bind-undeclared"))
}

pub fn crown(path: &str, check: &str) -> Result<Value> {
    let bytes = local(crown_port()?, path, check)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| observation(check, path, format!("observation-json-invalid: {e}")))
}

pub fn health() -> Result<Value> {
    // Fetch both answers before judging either; a failed read is not absent data.
    let crown = crown("/health", "A");
    let staff = crate::shared::config::declared_bind()
        .map_err(|e| observation("A", "staff.health", e))
        .and_then(|bind| local(bind.port(), "/health", "A"))
        .and_then(|bytes| {
            serde_json::from_slice::<Value>(&bytes)
                .map_err(|e| observation("A", "staff.health", e.to_string()))
        });
    let crown = crown?;
    let staff = staff?;
    for (name, answer) in [("crown.health", &crown), ("staff.health", &staff)] {
        match answer.get("ok").and_then(Value::as_bool) {
            Some(true) => {}
            Some(false) => return Err(observation("A", name, "house-unhealthy")),
            None => return Err(observation("A", name, "health-answer-absent")),
        }
    }
    Ok(json!({"crown": crown, "staff": staff}))
}

pub fn release(manifest: &Value) -> Result<Value> {
    if !std::path::Path::new("/usr/bin/curl").is_file() {
        return Err(observation("F", "source", "curl-absent"));
    }
    let token = forgejo_token()?;
    let source = &manifest["source"];
    let repo = source["release_repo"]
        .as_str()
        .ok_or_else(|| observation("F", "source.release_repo", "release-repo-absent"))?;
    let reference = source["ref"]
        .as_str()
        .ok_or_else(|| observation("F", "source.ref", "release-ref-absent"))?;
    let api = url::Url::parse("https://git.home.arpa/api/v1/repos/")
        .map_err(|e| observation("F", "source", e.to_string()))?;
    let release_url = |tag: &str| -> Result<url::Url> {
        let mut url = api.clone();
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| observation("F", "source", "forge-path-invalid"))?;
        segments.pop_if_empty();
        for part in repo.split('/') {
            segments.push(part);
        }
        segments.extend(["releases", "tags", tag]);
        drop(segments);
        Ok(url)
    };
    let commit = commit_reference(reference);
    let lookup_tag = commit
        .as_ref()
        .map(|(tag, _)| tag.as_str())
        .unwrap_or(reference);
    let mut release_response = https(release_url(lookup_tag)?.as_str(), &token)?;
    if commit.as_ref().is_some_and(|(_, _)| reference.len() == 40) && release_response.status == 404
    {
        release_response = https(release_url(reference)?.as_str(), &token)?;
    }
    if release_response.status != 200 {
        return Err(observation(
            "F",
            "release",
            format!("release-http-status: {}", release_response.status),
        ));
    }
    let release: Value = serde_json::from_slice(&release_response.body)
        .map_err(|e| observation("F", "release", e.to_string()))?;
    let tag_name = release["tag_name"].as_str();
    let tag_matches = match commit.as_ref().filter(|_| reference.len() == 40) {
        Some((tag, sha)) => {
            tag_name == Some(reference) || tag_name == Some(tag.as_str()) || tag_name == Some(sha)
        }
        None => tag_name == Some(reference),
    };
    if !tag_matches {
        return Err(observation("F", "release.tag_name", "release-ref-mismatch"));
    }
    let assets = release["assets"]
        .as_array()
        .ok_or_else(|| observation("F", "release.assets", "release-assets-absent"))?;
    let component = repo.split('/').nth(1).unwrap_or("");
    let sidecar_name = format!("{component}-{}.sha256", std::env::consts::ARCH);
    let asset_url = |name: &str| -> Result<String> {
        let found: Vec<_> = assets
            .iter()
            .filter(|a| a["name"].as_str() == Some(name))
            .collect();
        if found.len() != 1 {
            return Err(observation(
                "F",
                name,
                "release-evidence-absent-or-ambiguous",
            ));
        }
        let value = found[0]["browser_download_url"]
            .as_str()
            .ok_or_else(|| observation("F", name, "release-evidence-url-absent"))?;
        let url = url::Url::parse(value).map_err(|e| observation("F", name, e.to_string()))?;
        if url.origin() != api.origin() {
            return Err(observation("F", name, "release-evidence-foreign-origin"));
        }
        Ok(value.into())
    };
    let sidecar_response = https(&asset_url(&sidecar_name)?, &token)?;
    if sidecar_response.status != 200 {
        return Err(observation("F", "sidecar", "release-evidence-http-failed"));
    }
    let sidecar = std::str::from_utf8(&sidecar_response.body)
        .map_err(|e| observation("F", "sidecar", e.to_string()))?;
    let lines: Vec<_> = sidecar
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    if lines.len() != 1 {
        return Err(observation("F", "sidecar", "sidecar-ambiguous"));
    }
    let parts: Vec<_> = lines[0].split_whitespace().collect();
    let digest = parts
        .first()
        .copied()
        .ok_or_else(|| observation("F", "sidecar", "sidecar-digest-absent"))?;
    seat::field(
        super::XENIA,
        "content_inventory_digest",
        &json!(digest),
        "F",
        "sidecar.digest",
    )?;
    if parts.len() > 2
        || (parts.len() == 2
            && parts[1].trim_start_matches('*') != sidecar_name.trim_end_matches(".sha256"))
    {
        return Err(observation("F", "sidecar", "sidecar-asset-mismatch"));
    }
    let flag_response = https(&asset_url("release.flag")?, &token)?;
    if flag_response.status != 200 {
        return Err(observation(
            "F",
            "release.flag",
            "release-evidence-http-failed",
        ));
    }
    let flag: Value = serde_json::from_slice(&flag_response.body)
        .map_err(|e| observation("F", "release.flag", e.to_string()))?;
    seat::form("estate.release-flag.v1", None, &flag, "F", "release.flag")?;
    let revision_matches = match &commit {
        Some((_, sha)) => {
            flag["source_sha"].as_str() == Some(sha.as_str())
                && release.get("target_commitish").and_then(Value::as_str) == Some(sha.as_str())
        }
        None => {
            flag["source_sha"].as_str() == Some(reference)
                || release
                    .get("target_commitish")
                    .is_some_and(|target| target == &flag["source_sha"])
        }
    };
    if flag["component"].as_str() != Some(component) || !revision_matches {
        return Err(observation(
            "F",
            "release.flag",
            "release-flag-source-mismatch",
        ));
    }
    if digest != manifest["content_inventory_digest"].as_str().unwrap_or("") {
        return Err(observation(
            "F",
            "content_inventory_digest",
            "release-digest-mismatch",
        ));
    }
    if let Some(flag_digest) = flag.get("sha256") {
        if flag_digest.as_str() != Some(digest) {
            return Err(observation(
                "F",
                "release.flag.sha256",
                "release-flag-digest-mismatch",
            ));
        }
    }
    Ok(
        json!({"release": release, "sidecar": sidecar, "flag": flag, "digest": digest, "binary_fetched": false}),
    )
}
