//! Hestia Anchor certificate control band: typed public membrane over house_ca.
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::env;
use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

const LEGACY_CERT_BUNDLE_SCRIPT: &str = "/usr/local/sbin/createCertBundle.sh";
const LEGACY_CERT_REFRESH_SCRIPT: &str = "/usr/local/sbin/sslKey.sh";

fn command() -> (String, Vec<String>) {
    if let Ok(value) = env::var("CADUCEUS_HOUSE_CA_CMD") {
        let mut parts = value.split_whitespace().map(str::to_owned);
        return (
            parts.next().unwrap_or_else(|| "caduceus-house-ca".into()),
            parts.collect(),
        );
    }
    ("caduceus-house-ca".into(), Vec::new())
}

pub fn invoke_json(args: &[String]) -> Result<Value, String> {
    invoke_json_with_stdin(args, None)
}

fn invoke_receipt(args: &[String]) -> Result<Value, String> {
    let (program, prefix) = command();
    let output = Command::new(program)
        .args(prefix)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .output()
        .map_err(|e| format!("caduceus-cert-house-ca-unavailable: {e}"))?;
    serde_json::from_slice(&output.stdout)
        .map_err(|_| "caduceus-cert-house-ca-invalid-receipt".to_string())
}

fn invoke_json_with_stdin(args: &[String], stdin: Option<&[u8]>) -> Result<Value, String> {
    let (program, prefix) = command();
    let mut child = Command::new(program)
        .args(prefix)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| format!("caduceus-cert-house-ca-unavailable: {e}"))?;
    if let Some(input) = stdin {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(input)
            .map_err(|e| format!("caduceus-cert-house-ca-stdin-failed: {e}"))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|e| format!("caduceus-cert-house-ca-unavailable: {e}"))?;
    // stderr is deliberately suppressed at the public membrane.
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "caduceus-cert-house-ca-invalid-receipt".to_string())?;
    if output.status.success() && value.get("ok") == Some(&json!(true)) {
        Ok(value)
    } else {
        Err(value
            .get("firstMissingSignal")
            .and_then(Value::as_str)
            .unwrap_or("caduceus-cert-house-ca-failed")
            .to_string())
    }
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

fn legacy_bundle_metadata(
    platform: &str,
) -> Result<(&'static str, &'static str, &'static str), String> {
    match platform {
        "windows" => Ok((
            "/tmp/homeserver_certs/homeserver_ca.cer",
            "homeserver_ca.cer",
            "application/x-x509-ca-cert",
        )),
        "android" | "chromeos" => Ok((
            "/tmp/homeserver_certs/homeserver_ca.crt",
            "homeserver_ca.crt",
            "application/x-x509-ca-cert",
        )),
        "linux" | "macos" => Ok((
            "/tmp/homeserver_certs/homeserver_ca.p12",
            "homeserver_ca.p12",
            "application/x-pkcs12",
        )),
        _ => Err("caduceus-cert-platform-invalid".into()),
    }
}

/// Executes the preserved legacy bundle maker for the Crown compatibility door.
/// The script owns conversion; Rust only validates the platform and carries bytes.
pub fn legacy_bundle_download(platform: &str) -> Result<BundleDownload, String> {
    let (path, filename, mime_type) = legacy_bundle_metadata(platform)?;
    let output = Command::new("/usr/bin/sudo")
        .args(["/bin/bash", LEGACY_CERT_BUNDLE_SCRIPT, platform])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|_| "caduceus-cert-bundle-script-unavailable".to_string())?;
    if !output.status.success() {
        return Err("caduceus-cert-bundle-script-failed".into());
    }
    let bytes = fs::read(path).map_err(|_| "caduceus-cert-bundle-artifact-missing".to_string())?;
    if bytes.is_empty() {
        return Err("caduceus-cert-bundle-empty".into());
    }
    let _ = fs::remove_file(path);
    Ok(BundleDownload {
        bytes,
        filename: filename.to_string(),
        mime_type: mime_type.to_string(),
        fingerprint: String::new(),
        client_reinstall_required: true,
    })
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
