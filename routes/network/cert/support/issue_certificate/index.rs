// Hestia Anchor certificate control band: typed public membrane over house_ca.
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

fn house_ca_stop(verb: &str) -> Option<&'static str> {
    match verb {
        "status" => Some("network/cert/house-ca/status"),
        "ensure-root" => Some("network/cert/house-ca/ensure-root"),
        "issue-leaf" => Some("network/cert/house-ca/issue-leaf"),
        "sign-csr" => Some("network/cert/house-ca/sign-csr"),
        "bundle-export" => Some("network/cert/house-ca/bundle-export"),
        "bundle-read" => Some("network/cert/house-ca/bundle-read"),
        "trust-install" => Some("network/cert/house-ca/trust-install"),
        "apply-nginx" => Some("network/cert/house-ca/apply-nginx"),
        "constituent-lock" => Some("network/cert/house-ca/constituent-lock"),
        "portal-admit" => Some("network/cert/house-ca/portal-admit"),
        "portal-retire" => Some("network/cert/house-ca/portal-retire"),
        _ => None,
    }
}

fn house_ca_crossing(verb: &str, payload: Value, seconds: u64) -> Result<Value, Value> {
    house_ca_crossing_with_timeout(verb, payload, Duration::from_secs(seconds))
}

fn house_ca_crossing_with_timeout(verb: &str, payload: Value, timeout: Duration) -> Result<Value, Value> {
    let path = house_ca_stop(verb).ok_or_else(|| json!({"ok":false,"firstMissingSignal":"agathodaimon-house-ca-refused"}))?;
    let wrapper = crate::gate::snake::crossing_path_with_timeout(path, &payload, timeout)
        .map_err(|signal| json!({"ok":false,"firstMissingSignal":signal}))?;
    let receipt = wrapper.get("receiptPayload").filter(|v| v.is_object()).cloned()
        .unwrap_or_else(|| json!({"ok":false,"firstMissingSignal":"caduceus-house-ca-refused"}));
    if receipt.get("ok").and_then(Value::as_bool) == Some(true) { Ok(receipt) } else { Err(receipt) }
}

fn invoke_stop_json(verb: &str, payload: Value, seconds: u64) -> Result<Value, Value> {
    invoke_stop_json_with_timeout(verb, payload, Duration::from_secs(seconds))
}

fn invoke_stop_json_with_timeout(verb: &str, payload: Value, timeout: Duration) -> Result<Value, Value> {
    house_ca_crossing_with_timeout(verb, payload, timeout)
}

fn stop_signal(value: Value) -> String {
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
}

pub fn invoke_json(args: &[String]) -> Result<Value, String> {
    let verb = args.first().map(String::as_str).unwrap_or("");
    let keys: &[&str] = match verb {
        "status" | "ensure-root" => &[],
        "issue-leaf" => &["identity"],
        "sign-csr" => &["csrPem"],
        "bundle-export" | "bundle-read" => &["platform"],
        "trust-install" => &["bundle"],
        "apply-nginx" => &["portal", "upstream", "certificate", "key-path"],
        "constituent-lock" => &["portal", "lan-ip"],
        "portal-admit" => &["portal", "lan-ip", "upstream"],
        "portal-retire" => &["portal", "owner-mac"],
        _ => return Err("agathodaimon-house-ca-refused".into()),
    };
    let seconds = match verb { "status" | "bundle-read" => 60, "sign-csr" | "bundle-export" | "constituent-lock" => 120, "portal-admit" | "portal-retire" => 600, _ => 300 };
    let mut payload = json!({});
    let mut i = 1;
    for key in keys {
        if let Some(value) = args.get(i).filter(|v| !v.starts_with("--")) {
            payload[*key] = json!(value); i += 1;
        }
    }
    while let Some(flag) = args.get(i) {
        let key = flag.strip_prefix("--").unwrap_or("");
        let allowed = match verb {
            "ensure-root" => &["dry-run", "renewal-authority"][..],
            "issue-leaf" => &["dry-run", "sans", "ips"],
            "bundle-export" => &["dry-run"],
            "trust-install" => &["dry-run", "platform", "fingerprint", "renew-ring"],
            "apply-nginx" | "constituent-lock" => &["dry-run", "aliases"],
            "portal-admit" => &["dry-run", "aliases", "owner-mac", "origin", "claim-tiles"],
            "portal-retire" => &["dry-run"],
            _ => &[],
        };
        if !allowed.contains(&key) { return Err("agathodaimon-house-ca-refused".into()); }
        if key == "dry-run" || key == "renew-ring" { payload[key] = json!(true); i += 1; }
        else if let Some(value) = args.get(i + 1) { payload[key] = json!(value); i += 2; }
        else { return Err("agathodaimon-house-ca-refused".into()); }
    }
    invoke_stop_json(verb, payload, seconds).map_err(stop_signal)
}

fn invoke_json_with_stdin(verb: &str, input: Value) -> Result<Value, String> {
    house_ca_crossing(verb, input, 120).map_err(|value| {
        value.get("firstMissingSignal").and_then(Value::as_str)
            .unwrap_or(if value.get("firstMissingSignal").is_some() { "caduceus-cert-house-ca-failed" } else { "caduceus-house-ca-refused" })
            .to_string()
    })
}

pub fn sign_csr_json(csr_pem: &str) -> Result<Value, String> {
    let request = json!({ "csrPem": csr_pem });
    let private = invoke_json_with_stdin("sign-csr", request)?;
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
    status_json_with_timeout(Duration::from_secs(60))
}
pub(crate) fn status_json_with_timeout(timeout: Duration) -> Result<Value, String> {
    status_receipt(timeout).map_err(stop_signal)
}
pub(crate) fn status_receipt(timeout: Duration) -> Result<Value, Value> {
    invoke_stop_json_with_timeout("status", json!({}), timeout)
}
pub fn status() -> i32 {
    match status_receipt(Duration::from_secs(60)) {
        Ok(value) => {
            println!("{}", serde_json::to_string(&value).unwrap());
            0
        }
        Err(receipt) => {
            println!("{}", serde_json::to_string(&receipt).unwrap());
            1
        }
    }
}

pub fn ensure_root_json(dry_run: bool, renewal_authority: Option<&str>) -> Result<Value, String> {
    let mut payload = json!({});
    if dry_run { payload["dry-run"] = json!(true); }
    if let Some(authority) = renewal_authority.filter(|value| !value.is_empty()) {
        payload["renewal-authority"] = json!(authority);
    }
    invoke_stop_json("ensure-root", payload, 300).map_err(stop_signal).and_then(|receipt| {
        let changed = receipt
            .get("changed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        crate::routes::cert_dependent_reload::after_material_lands(
            receipt,
            json!({"material": "root", "scope": "household-root", "changed": changed}),
        )
    })
}

pub fn issue_leaf_json(
    identity: &str,
    sans: &[String],
    ips: &[String],
    dry_run: bool,
) -> Result<Value, String> {
    let mut payload = json!({"identity": identity});
    if !sans.is_empty() { payload["sans"] = json!(sans.join(",")); }
    if !ips.is_empty() { payload["ips"] = json!(ips.join(",")); }
    if dry_run { payload["dry-run"] = json!(true); }
    invoke_stop_json("issue-leaf", payload, 300).map_err(stop_signal).and_then(|receipt| {
        let changed = receipt
            .get("changed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        crate::routes::cert_dependent_reload::after_material_lands(
            receipt,
            json!({"material": "leaf", "identity": identity, "sans": sans, "changed": changed}),
        )
    })
}
pub fn issue_leaf(sans: &[String], dry_run: bool) -> i32 {
    print(issue_leaf_json("home.arpa", sans, &[], dry_run))
}

pub fn bundle_create_json(platform: &str, dry_run: bool) -> Result<Value, String> {
    if !["windows", "android", "chromeos", "linux", "macos"].contains(&platform) {
        return Err("caduceus-cert-platform-invalid".into());
    }
    let mut payload = json!({"platform": platform});
    if dry_run { payload["dry-run"] = json!(true); }
    invoke_stop_json("bundle-export", payload, 120).map_err(stop_signal)
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
    content_base64: String,
    client_reinstall_required: bool,
}

fn openssl_x509_sha256_fingerprint(bytes: &[u8], der: bool) -> Result<String, String> {
    let mut command = Command::new("openssl");
    command.arg("x509");
    if der {
        command.args(["-inform", "DER"]);
    }
    let mut child = command
        .args(["-noout", "-fingerprint", "-sha256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "caduceus-cert-bundle-fingerprint-invalid".to_string())?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "caduceus-cert-bundle-fingerprint-invalid".to_string())?;
    if stdin.write_all(bytes).is_err() {
        drop(stdin);
        let _ = child.kill();
        let _ = child.wait();
        return Err("caduceus-cert-bundle-fingerprint-invalid".into());
    }
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|_| "caduceus-cert-bundle-fingerprint-invalid".to_string())?;
    if !output.status.success() {
        return Err("caduceus-cert-bundle-fingerprint-invalid".into());
    }
    let output = String::from_utf8(output.stdout)
        .map_err(|_| "caduceus-cert-bundle-fingerprint-invalid".to_string())?;
    let fingerprint = output
        .trim()
        .rsplit_once('=')
        .map(|(_, fingerprint)| fingerprint.trim())
        .ok_or_else(|| "caduceus-cert-bundle-fingerprint-invalid".to_string())?;
    let octets: Vec<&str> = fingerprint.split(':').collect();
    if octets.len() != 32
        || octets
            .iter()
            .any(|octet| octet.len() != 2 || !octet.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("caduceus-cert-bundle-fingerprint-invalid".into());
    }
    Ok(octets
        .iter()
        .map(|octet| octet.to_ascii_uppercase())
        .collect::<Vec<_>>()
        .join(":"))
}

fn x509_sha256_fingerprint(bytes: &[u8]) -> Result<String, String> {
    openssl_x509_sha256_fingerprint(bytes, false)
        .or_else(|_| openssl_x509_sha256_fingerprint(bytes, true))
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
    let value = invoke_stop_json("bundle-read", json!({"platform":platform}), 60).map_err(stop_signal)?;
    let bound = crate::routes::leaf_schema::bound(&value, "network/cert/house-ca/bundle-read");
    let receipt: BundleReadReceipt = serde_json::from_value(value)
        .map_err(|_| "caduceus-cert-bundle-read-invalid-receipt".to_string())?;
    if (receipt.schema != "caduceus.network.cert.house-ca.bundle-read.v1" && !bound)
        || !receipt.ok
        || receipt.platform != platform
        || receipt.filename != expected_filename
        || receipt.mime_type != expected_mime
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
    let fingerprint = x509_sha256_fingerprint(&bytes)?;
    Ok(BundleDownload {
        bytes,
        filename: receipt.filename,
        mime_type: receipt.mime_type,
        fingerprint,
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
    let walked = crate::gate::snake::crossing_path_with_timeout(
        "network/cert/refresh",
        &json!({}),
        Duration::from_secs(600),
    )
    .map_err(|signal| {
        if matches!(
            signal.as_str(),
            "caduceus-agathodaimon-cli-missing" | "caduceus-agathodaimon-cli-unavailable"
        ) {
            "caduceus-cert-refresh-script-unavailable".to_string()
        } else {
            "caduceus-cert-refresh-script-failed".to_string()
        }
    })?;
    if walked.get("ok").and_then(Value::as_bool) != Some(true) {
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
    let mut payload = json!({"portal":portal,"upstream":upstream,"certificate":certificate,"key-path":key});
    if dry_run { payload["dry-run"] = json!(true); }
    invoke_stop_json("apply-nginx", payload, 300).map_err(stop_signal).and_then(|receipt| {
        let changed = receipt
            .get("changed")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        crate::routes::cert_dependent_reload::after_material_lands(
            receipt,
            json!({"material": "applied", "portal": portal, "certificate": certificate, "changed": changed}),
        )
    })
}
pub fn constituent_lock_json(portal: &str, lan_ip: &str, dry_run: bool) -> Result<Value, String> {
    let mut payload = json!({"portal":portal,"lan-ip":lan_ip});
    if dry_run { payload["dry-run"] = json!(true); }
    invoke_stop_json("constituent-lock", payload, 120).map_err(stop_signal)
}
pub fn trust_install_json(bundle: &str, platform: &str, dry_run: bool) -> Result<Value, String> {
    let mut payload = json!({"bundle":bundle,"platform":platform});
    if dry_run { payload["dry-run"] = json!(true); }
    invoke_stop_json("trust-install", payload, 300).map_err(stop_signal)
}

fn trust_install_with_renew_receipt(
    bundle: &str,
    platform: &str,
    fingerprint: &str,
    dry_run: bool,
    renew: bool,
) -> Result<Value, Value> {
    let mut payload = json!({"bundle":bundle,"platform":platform,"fingerprint":fingerprint});
    if dry_run { payload["dry-run"] = json!(true); }
    if renew { payload["renew-ring"] = json!(true); }
    house_ca_crossing("trust-install", payload, 300)
}

fn staff_receipt_reason(receipt: &Value) -> Value {
    receipt
        .get("reason")
        .filter(|reason| reason.is_string())
        .cloned()
        .unwrap_or(Value::Null)
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

fn fetch_bundle_http(server: &str, platform: &str) -> Result<(Vec<u8>, String), String> {
    bundle_metadata(platform)?;
    let (address, socket) = trust_fetch_target(server)?;
    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(5))
        .map_err(|_| "caduceus-cert-trust-fetch-server-unreachable".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| "caduceus-cert-trust-fetch-server-unreachable".to_string())?;
    stream
        .write_all(
            format!(
                "GET /api/v1/cert/bundle/download?platform={platform} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
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
pub fn trust_fetch_json(server: &str, platform: &str, renew: bool) -> Result<Value, String> {
    let (bytes, fingerprint) = fetch_bundle_http(server, platform)?;
    let path = fetched_bundle_path()?;
    let write_result = fs::write(&path, &bytes);
    let result = match write_result {
        Ok(()) => trust_install_with_renew_receipt(
            path.to_str().unwrap_or(""),
            platform,
            &fingerprint,
            false,
            renew,
        ),
        Err(_) => Err(Value::Null),
    };
    let _ = fs::remove_file(&path);
    match result {
        Ok(receipt) => {
            let reason = staff_receipt_reason(&receipt);
            let successful = receipt.get("ok").and_then(Value::as_bool) == Some(true);
            let installed = receipt
                .get("bundle_installed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let actual = receipt
                .get("ca_fingerprint")
                .and_then(Value::as_str)
                .unwrap_or("");
            if !successful || !installed || actual != fingerprint {
                Ok(json!({
                    "schema": "caduceus.cert.trust_fetch.v1",
                    "ok": false,
                    "server": server,
                    "fingerprint": fingerprint,
                    "state": "bundle_refused",
                    "firstMissingSignal": "bundle_refused",
                    "reason": reason,
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
                    "reason": reason,
                }))
            }
        }
        Err(receipt) => Ok(json!({
            "schema": "caduceus.cert.trust_fetch.v1",
            "ok": false,
            "server": server,
            "fingerprint": fingerprint,
            "state": "bundle_refused",
            "firstMissingSignal": "bundle_refused",
            "reason": staff_receipt_reason(&receipt),
        })),
    }
}
pub(crate) fn portal_admit_receipt(portal: &str, ip: &str, upstream: &str, aliases: &[String], dry_run: bool, timeout: Option<Duration>) -> Result<Value, Value> {
    let mut payload = json!({"portal":portal,"lan-ip":ip,"upstream":upstream});
    if !aliases.is_empty() { payload["aliases"] = json!(aliases.join(",")); }
    if dry_run { payload["dry-run"] = json!(true); }
    house_ca_crossing_with_timeout("portal-admit", payload, timeout.unwrap_or(Duration::from_secs(600)))
}

pub(crate) fn portal_owned_admit_receipt(portal: &str, ip: &str, upstream: &str, aliases: &[String], mac: &str, origin: &str, claim_tiles: &[String], dry_run: bool, timeout: Option<Duration>) -> Result<Value, Value> {
    let mut payload = json!({"portal":portal,"lan-ip":ip,"upstream":upstream,"owner-mac":mac,"origin":origin});
    if !aliases.is_empty() { payload["aliases"] = json!(aliases.join(",")); }
    if !claim_tiles.is_empty() { payload["claim-tiles"] = json!(claim_tiles.join(",")); }
    if dry_run { payload["dry-run"] = json!(true); }
    house_ca_crossing_with_timeout("portal-admit", payload, timeout.unwrap_or(Duration::from_secs(600)))
}

/// The CLI door preserves the staff receipt and binds it to this stop.
pub(crate) fn portal_admit_cli_receipt(
    portal: &str, ip: &str, upstream: Option<&str>, aliases: &[String],
    owner: Option<(&str, &str)>, claim_tiles: &[String], dry_run: bool,
    tailnet_port: Option<&str>, locations: Option<&str>,
    max_body_size: Option<&str>, read_timeout: Option<&str>,
    forwarded: serde_json::Map<String, Value>,
) -> Result<Value, Value> {
    let mut payload = json!({"portal":portal,"lan-ip":ip});
    if let Some(value) = upstream { payload["upstream"] = json!(value); }
    if !aliases.is_empty() { payload["aliases"] = json!(aliases.join(",")); }
    if let Some((mac, origin)) = owner {
        payload["owner-mac"] = json!(mac);
        payload["origin"] = json!(origin);
        if !claim_tiles.is_empty() { payload["claim-tiles"] = json!(claim_tiles.join(",")); }
    }
    if dry_run { payload["dry-run"] = json!(true); }
    if let Some(value) = tailnet_port { payload["tailnet-port"] = json!(value); }
    if let Some(value) = locations { payload["locations"] = json!(value); }
    if let Some(value) = max_body_size { payload["max-body-size"] = json!(value); }
    if let Some(value) = read_timeout { payload["read-timeout"] = json!(value); }
    payload.as_object_mut().expect("payload is an object").extend(forwarded);

    let result = house_ca_crossing_with_timeout("portal-admit", payload, Duration::from_secs(600));
    let receipt = match &result { Ok(value) | Err(value) => value };
    // The shared crossing constructs a two-field error when no staff receipt exists.
    if result.is_err() && receipt.as_object().is_some_and(|object|
        object.len() == 2 && object.contains_key("ok") && object.contains_key("firstMissingSignal")) {
        return result;
    }
    let former = receipt.get("schema").and_then(Value::as_str)
        == Some("caduceus.network.cert.house-ca.portal-admit.v1");
    let bound = crate::routes::leaf_schema::bound(receipt, "network/cert/house-ca/portal-admit");
    if former || bound {
        result
    } else {
        let mut answer = receipt.clone();
        answer.as_object_mut().expect("receipt is an object")
            .entry("caduceus_door_verdict").or_insert_with(|| json!({"signal":"caduceus-schema-desync",
                "expected_stop":{"noun":"network/cert/house-ca","verb":"portal-admit"},
                "received_schema":receipt.get("schema"),"received_stop":receipt.get("stop")}));
        Err(answer)
    }
}

pub(crate) fn portal_retire_receipt(portal: &str, mac: &str, dry_run: bool, timeout: Option<Duration>) -> Result<Value, Value> {
    let mut payload = json!({"portal":portal,"owner-mac":mac});
    if dry_run { payload["dry-run"] = json!(true); }
    house_ca_crossing_with_timeout("portal-retire", payload, timeout.unwrap_or(Duration::from_secs(600)))
}

pub fn portal_admit_json(
    portal: &str,
    ip: &str,
    upstream: &str,
    aliases: &[String],
    dry_run: bool,
) -> Result<Value, String> {
    portal_admit_receipt(portal, ip, upstream, aliases, dry_run, None).map_err(|value| {
        if value.get("firstMissingSignal").and_then(Value::as_str) == Some("caduceus-pin-not-yet-provisioned") {
            "caduceus-house-ca-refused".to_string()
        } else {
            value.get("firstMissingSignal").and_then(Value::as_str).unwrap_or("caduceus-house-ca-refused").to_string()
        }
    })
}
pub fn rotate_ca(_dry_run: bool, _understood: bool) -> i32 {
    eprintln!("caduceus-cert-rotate-ca-not-v1");
    2
}
