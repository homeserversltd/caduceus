//! Hestia Anchor certificate control band: typed public membrane over house_ca.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const LEGACY_CERT_REFRESH_SCRIPT: &str = "/usr/local/sbin/sslKey.sh";

pub fn invoke_json(args: &[String]) -> Result<Value, String> {
    let input = json!({"args": args});
    crate::shared::agathodaimon::crossing_value("cert", "house-ca", &input).map_err(|value| {
        if value.get("firstMissingSignal").and_then(Value::as_str)
            == Some("caduceus-pin-not-yet-provisioned")
        {
            "caduceus-house-ca-refused".to_string()
        } else {
            value
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .unwrap_or("caduceus-house-ca-refused")
                .to_string()
        }
    })
}

fn invoke_receipt(args: &[String]) -> Result<Value, String> {
    invoke_json(args)
}

fn invoke_json_with_stdin(args: &[String], stdin: Option<&[u8]>) -> Result<Value, String> {
    let mut input: Value = stdin
        .map(|bytes| {
            serde_json::from_slice(bytes).map_err(|_| "caduceus-cert-invalid-request".to_string())
        })
        .transpose()?
        .unwrap_or_else(|| json!({}));
    input["args"] = json!(args);
    crate::shared::agathodaimon::crossing_value("cert", "house-ca", &input).map_err(|value| {
        value
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or(if value.get("firstMissingSignal").is_some() {
                "caduceus-cert-house-ca-failed"
            } else {
                "caduceus-house-ca-refused"
            })
            .to_string()
    })
}

pub fn sign_csr_json(csr_pem: &str) -> Result<Value, String> {
    let request = json!({ "csrPem": csr_pem });
    let body = request.to_string();
    let private = invoke_json_with_stdin(&["sign-csr".into()], Some(body.as_bytes()))?;
    let text = |field: &str| {
        private
            .get(field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "caduceus-cert-csr-sign-invalid-receipt".to_string())
    };
    let leaf_pem = text("leaf_pem")?;
    if leaf_pem.contains("PRIVATE KEY") {
        return Err("caduceus-cert-private-key-leaked".to_string());
    }
    Ok(json!({
        "schema": "caduceus.cert.csr_sign.v1",
        "ok": true,
        "primitive": "csr_sign",
        "changed": private.get("changed").and_then(Value::as_bool).unwrap_or(false),
        "identity": text("identity")?,
        "sans": private.get("sans").cloned().unwrap_or(Value::Array(Vec::new())),
        "leaf_pem": leaf_pem,
        "leaf_fingerprint": text("leaf_fingerprint")?,
        "ca_fingerprint": text("ca_fingerprint")?,
        "leaf_expiry": text("leaf_expiry")?,
        "proof": text("proof")?,
    }))
}

fn print(value: Result<Value, String>) -> i32 {
    match value {
        Ok(value) => {
            println!("{}", serde_json::to_string(&value).unwrap());
            0
        }
        Err(signal) => {
            eprintln!("{signal}");
            1
        }
    }
}

pub fn status_json() -> Result<Value, String> {
    invoke_receipt(&["status".into()])
}
pub fn status() -> i32 {
    print(status_json())
}

pub fn ensure_root_json(dry_run: bool, renewal_authority: Option<&str>) -> Result<Value, String> {
    let mut args = vec!["ensure-root".into()];
    if dry_run {
        args.push("--dry-run".into());
    }
    if let Some(authority) = renewal_authority.filter(|value| !value.is_empty()) {
        args.extend(["--renewal-authority".into(), authority.into()]);
    }
    invoke_json(&args)
}

pub fn issue_leaf_json(
    identity: &str,
    sans: &[String],
    ips: &[String],
    dry_run: bool,
) -> Result<Value, String> {
    let mut args = vec!["issue-leaf".into(), identity.into()];
    if !sans.is_empty() {
        args.extend(["--sans".into(), sans.join(",")]);
    }
    if !ips.is_empty() {
        args.extend(["--ips".into(), ips.join(",")]);
    }
    if dry_run {
        args.push("--dry-run".into());
    }
    invoke_json(&args)
}
pub fn issue_leaf(sans: &[String], dry_run: bool) -> i32 {
    print(issue_leaf_json("home.arpa", sans, &[], dry_run))
}

pub fn bundle_create_json(platform: &str, dry_run: bool) -> Result<Value, String> {
    if !["windows", "android", "chromeos", "linux", "macos"].contains(&platform) {
        return Err("caduceus-cert-platform-invalid".into());
    }
    let mut args = vec!["bundle-export".into(), platform.into()];
    if dry_run {
        args.push("--dry-run".into());
    }
    invoke_json(&args)
}
pub fn bundle_create(platform: &str, dry_run: bool) -> i32 {
    print(bundle_create_json(platform, dry_run))
}

#[derive(Debug, PartialEq, Eq)]
pub struct BundleDownload {
    pub bytes: Vec<u8>,
    pub filename: String,
    pub mime_type: String,
    pub fingerprint: String,
    pub client_reinstall_required: bool,
}

#[derive(Deserialize)]
struct BundleReadReceipt {
    schema: String,
    ok: bool,
    platform: String,
    filename: String,
    mime_type: String,
    fingerprint: String,
    content_base64: String,
    client_reinstall_required: bool,
}

fn bundle_metadata(platform: &str) -> Result<(String, &'static str), String> {
    if !["windows", "android", "chromeos", "linux", "macos"].contains(&platform) {
        return Err("caduceus-cert-platform-invalid".into());
    }
    let suffix = if platform == "windows" {
        ".cer"
    } else {
        ".crt"
    };
    Ok((
        format!("homeserver-house-ca-{platform}{suffix}"),
        "application/x-x509-ca-cert",
    ))
}

pub fn bundle_download_json(platform: &str) -> Result<BundleDownload, String> {
    let (expected_filename, expected_mime) = bundle_metadata(platform)?;
    let value = invoke_json(&["bundle-read".into(), platform.into()])?;
    let receipt: BundleReadReceipt = serde_json::from_value(value)
        .map_err(|_| "caduceus-cert-bundle-read-invalid-receipt".to_string())?;
    if receipt.schema != "caduceus.staff.house_ca.bundle_read.v1"
        || !receipt.ok
        || receipt.platform != platform
        || receipt.filename != expected_filename
        || receipt.mime_type != expected_mime
        || receipt.fingerprint.trim().is_empty()
    {
        return Err("caduceus-cert-bundle-read-invalid-receipt".into());
    }
    let bytes = STANDARD
        .decode(receipt.content_base64)
        .map_err(|_| "caduceus-cert-bundle-read-invalid-base64".to_string())?;
    if bytes.is_empty() {
        return Err("caduceus-cert-bundle-empty".into());
    }
    if bytes
        .windows(b"PRIVATE KEY".len())
        .any(|window| window == b"PRIVATE KEY")
    {
        return Err("caduceus-cert-private-key-leaked".into());
    }
    Ok(BundleDownload {
        bytes,
        filename: receipt.filename,
        mime_type: receipt.mime_type,
        fingerprint: receipt.fingerprint,
        client_reinstall_required: receipt.client_reinstall_required,
    })
}

/// Exports and then reads a CA-only platform bundle through the house-CA staff
/// launcher. The reader reasserts the no-private-key invariant before bytes
/// cross the public HTTP membrane.
pub fn bundle_export_download_json(platform: &str) -> Result<BundleDownload, String> {
    bundle_create_json(platform, false)?;
    bundle_download_json(platform)
}

/// Executes the preserved root-refresh script. Its successful renewal always
/// requires clients to reinstall the refreshed certificate bundle.
pub fn legacy_refresh_root_json() -> Result<Value, String> {
    let output = Command::new("/usr/bin/sudo")
        .args(["/bin/bash", LEGACY_CERT_REFRESH_SCRIPT])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| "caduceus-cert-refresh-script-unavailable".to_string())?;
    if !output.status.success() {
        return Err("caduceus-cert-refresh-script-failed".into());
    }
    Ok(json!({
        "schema": "caduceus.cert.refresh_root.v1",
        "ok": true,
        "primitive": "refresh_root",
        "changed": true,
        "requiresReinstall": true,
    }))
}

pub fn apply_json(
    portal: &str,
    upstream: &str,
    certificate: &str,
    key: &str,
    dry_run: bool,
) -> Result<Value, String> {
    let mut args = vec![
        "apply-nginx".into(),
        portal.into(),
        upstream.into(),
        certificate.into(),
        key.into(),
    ];
    if dry_run {
        args.push("--dry-run".into());
    }
    invoke_json(&args)
}
pub fn constituent_lock_json(portal: &str, lan_ip: &str, dry_run: bool) -> Result<Value, String> {
    let mut args = vec!["constituent-lock".into(), portal.into(), lan_ip.into()];
    if dry_run {
        args.push("--dry-run".into());
    }
    invoke_json(&args)
}
pub fn trust_install_json(bundle: &str, platform: &str, dry_run: bool) -> Result<Value, String> {
    let mut args = vec![
        "trust-install".into(),
        bundle.into(),
        "--platform".into(),
        platform.into(),
    ];
    if dry_run {
        args.push("--dry-run".into());
    }
    invoke_json(&args)
}

fn trust_fetch_target(server: &str) -> Result<(String, SocketAddr), String> {
    if server.is_empty() || server.len() > 255 || server.contains(['/', '\\', '\r', '\n', '\0']) {
        return Err("caduceus-cert-trust-fetch-server-invalid".into());
    }
    let address = if server.starts_with('[') {
        server.to_string()
    } else if server
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok())
    {
        server.to_string()
    } else {
        format!("{server}:8787")
    };
    let socket = address
        .to_socket_addrs()
        .map_err(|_| "caduceus-cert-trust-fetch-server-unreachable".to_string())?
        .next()
        .ok_or_else(|| "caduceus-cert-trust-fetch-server-unreachable".to_string())?;
    Ok((address, socket))
}

fn fetch_bundle_http(server: &str) -> Result<(Vec<u8>, String), String> {
    let (address, socket) = trust_fetch_target(server)?;
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(5))
        .map_err(|_| "caduceus-cert-trust-fetch-server-unreachable".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| "caduceus-cert-trust-fetch-server-unreachable".to_string())?;
    stream
        .write_all(
            format!(
                "GET /api/v1/cert/bundle HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .map_err(|_| "caduceus-cert-trust-fetch-server-unreachable".to_string())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|_| "caduceus-cert-trust-fetch-server-unreachable".to_string())?;
    let separator = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "caduceus-cert-trust-fetch-response-invalid".to_string())?;
    let headers = std::str::from_utf8(&response[..separator])
        .map_err(|_| "caduceus-cert-trust-fetch-response-invalid".to_string())?;
    if !headers.starts_with("HTTP/1.1 200 ") && !headers.starts_with("HTTP/1.0 200 ") {
        return Err("caduceus-cert-trust-fetch-server-refused".into());
    }
    let fingerprint = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("x-caduceus-ca-fingerprint"))
        .map(|(_, value)| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "caduceus-cert-trust-fetch-fingerprint-missing".to_string())?;
    let bytes = response[separator + 4..].to_vec();
    if bytes.is_empty()
        || bytes
            .windows(b"PRIVATE KEY".len())
            .any(|window| window == b"PRIVATE KEY")
    {
        return Err("caduceus-cert-trust-fetch-bundle-invalid".into());
    }
    Ok((bytes, fingerprint))
}

fn fetched_bundle_path() -> Result<PathBuf, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "caduceus-cert-trust-fetch-tempfile-failed".to_string())?
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "caduceus-trust-fetch-{}-{nonce}.crt",
        std::process::id()
    ));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| "caduceus-cert-trust-fetch-tempfile-failed".to_string())?;
    Ok(path)
}

/// Fetches a public house bundle and delegates all CA/fingerprint/store validation
/// to the existing trust-install primitive. The fetched bytes are never retained.
pub fn trust_fetch_json(server: &str, platform: &str) -> Result<Value, String> {
    let (bytes, fingerprint) = fetch_bundle_http(server)?;
    let path = fetched_bundle_path()?;
    let write_result = fs::write(&path, &bytes);
    let result = match write_result {
        Ok(()) => trust_install_json(path.to_str().unwrap_or(""), platform, false),
        Err(_) => Err("caduceus-cert-trust-fetch-tempfile-failed".into()),
    };
    let _ = fs::remove_file(&path);
    match result {
        Ok(receipt) => {
            let installed = receipt
                .get("bundle_installed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let actual = receipt
                .get("ca_fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !installed || actual != fingerprint {
                Ok(json!({
                    "schema": "caduceus.cert.trust_fetch.v1",
                    "ok": false,
                    "server": server,
                    "fingerprint": fingerprint,
                    "state": "bundle_refused",
                    "firstMissingSignal": "bundle_refused",
                }))
            } else {
                let changed = receipt
                    .get("changed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                Ok(json!({
                    "schema": "caduceus.cert.trust_fetch.v1",
                    "ok": true,
                    "server": server,
                    "fingerprint": fingerprint,
                    "state": "installed",
                    "convergence": if changed { "installed" } else { "already_current" },
                    "changed": changed,
                    "proof": receipt.get("proof").cloned().unwrap_or(json!("trust-store-readback")),
                }))
            }
        }
        Err(_) => Ok(json!({
            "schema": "caduceus.cert.trust_fetch.v1",
            "ok": false,
            "server": server,
            "fingerprint": fingerprint,
            "state": "bundle_refused",
            "firstMissingSignal": "bundle_refused",
        })),
    }
}
pub fn portal_admit_json(
    portal: &str,
    ip: &str,
    upstream: &str,
    aliases: &[String],
    dry_run: bool,
) -> Result<Value, String> {
    let mut args = vec![
        "portal-admit".into(),
        portal.into(),
        ip.into(),
        upstream.into(),
    ];
    if !aliases.is_empty() {
        args.extend(["--aliases".into(), aliases.join(",")]);
    }
    if dry_run {
        args.push("--dry-run".into());
    }
    invoke_json(&args)
}
pub fn rotate_ca(_dry_run: bool, _understood: bool) -> i32 {
    eprintln!("caduceus-cert-rotate-ca-not-v1");
    2
}
