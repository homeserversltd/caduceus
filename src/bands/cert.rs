//! Hestia Anchor certificate control band: typed public membrane over house_ca.
use serde_json::{json, Value};
use std::env;
use std::process::{Command, Stdio};

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
    let (program, prefix) = command();
    let output = Command::new(program)
        .args(prefix)
        .args(args)
        .stdin(Stdio::null())
        .output()
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

fn call(parts: &[&str]) -> Result<Value, String> {
    invoke_json(&parts.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}

pub fn status_json() -> Result<Value, String> {
    call(&["status"])
}
pub fn status() -> i32 {
    print(status_json())
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
