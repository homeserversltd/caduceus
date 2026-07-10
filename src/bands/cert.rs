//! Caduceus cert band — public face (snake 1) over caduceus_staff house_ca (snake 2).
//! Does not invoke sslKey.sh / createCertBundle.sh.

use serde_json::{json, Value};
use std::env;
 
use std::process::Command;

fn house_ca_cmd() -> (String, Vec<String>) {
    if let Ok(cmd) = env::var("CADUCEUS_HOUSE_CA_CMD") {
        // space-separated override for tests, e.g. "python3 -m caduceus_staff.house_ca"
        let parts: Vec<String> = cmd.split_whitespace().map(str::to_string).collect();
        if parts.is_empty() {
            return ("caduceus-house-ca".into(), vec![]);
        }
        return (parts[0].clone(), parts[1..].to_vec());
    }
    if which("caduceus-house-ca") {
        return ("caduceus-house-ca".into(), vec![]);
    }
    ("python3".into(), vec!["-m".into(), "caduceus_staff.house_ca".into()])
}

fn which(bin: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn invoke(args: &[&str]) -> Result<Value, String> {
    let (prog, prefix) = house_ca_cmd();
    let mut cmd = Command::new(&prog);
    for p in &prefix {
        cmd.arg(p);
    }
    for a in args {
        cmd.arg(a);
    }
    if let Ok(dir) = env::var("CADUCEUS_CERT_DIR") {
        cmd.env("CADUCEUS_CERT_DIR", dir);
    }
    if let Ok(dir) = env::var("CADUCEUS_CERT_BUNDLE_DIR") {
        cmd.env("CADUCEUS_CERT_BUNDLE_DIR", dir);
    }
    if let Ok(pp) = env::var("PYTHONPATH") {
        cmd.env("PYTHONPATH", pp);
    }
    let output = cmd
        .output()
        .map_err(|e| format!("caduceus-cert-house-ca-unavailable: {e}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stdout.is_empty() {
        return Err(format!(
            "caduceus-cert-house-ca-empty: status={} stderr={stderr}",
            output.status
        ));
    }
    let value: Value = serde_json::from_str(&stdout)
        .map_err(|e| format!("caduceus-cert-house-ca-invalid-json: {e}; stdout={stdout}"))?;
    if !output.status.success() && value.get("ok") != Some(&json!(true)) {
        return Err(format!(
            "caduceus-cert-house-ca-failed: {}",
            value
                .get("firstMissingSignal")
                .and_then(Value::as_str)
                .unwrap_or("nonzero-exit")
        ));
    }
    Ok(value)
}

fn print_receipt(value: &Value) {
    if let Some(schema) = value.get("schema").and_then(Value::as_str) {
        println!("schema={schema}");
    } else {
        println!("schema=caduceus.cert.v1");
    }
    println!("ok={}", value.get("ok").and_then(Value::as_bool).unwrap_or(false));
    for key in [
        "ca_fingerprint",
        "leaf_fingerprint",
        "ca_not_after",
        "leaf_not_after",
        "client_reinstall_required",
        "path",
        "platform",
        "firstMissingSignal",
    ] {
        if let Some(v) = value.get(key) {
            if let Some(s) = v.as_str() {
                println!("{key}={s}");
            } else if let Some(b) = v.as_bool() {
                println!("{key}={b}");
            }
        }
    }
    // never print private keys
}

pub fn status() -> i32 {
    match invoke(&["status"]) {
        Ok(v) => {
            print_receipt(&v);
            if v.get("ok") == Some(&json!(true)) {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

pub fn issue_leaf(sans: &[String], dry_run: bool) -> i32 {
    if dry_run {
        println!("schema=caduceus.cert.issue_leaf.v1");
        println!("ok=true");
        println!("dry_run=true");
        println!("client_reinstall_required=false");
        println!("firstMissingSignal=none");
        return 0;
    }
    let mut args = vec!["issue-leaf".to_string()];
    if !sans.is_empty() {
        args.push("--sans".into());
        args.push(sans.join(","));
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match invoke(&arg_refs) {
        Ok(v) => {
            print_receipt(&v);
            if v.get("ok") == Some(&json!(true)) {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

pub fn rotate_ca(dry_run: bool, understood: bool) -> i32 {
    if !understood {
        eprintln!("caduceus-cert-rotate-ca-confirmation-required: pass --i-understand-clients-reinstall");
        return 2;
    }
    if dry_run {
        println!("schema=caduceus.cert.rotate_ca.v1");
        println!("ok=true");
        println!("dry_run=true");
        println!("client_reinstall_required=true");
        return 0;
    }
    match invoke(&["rotate-ca", "--i-understand-clients-reinstall"]) {
        Ok(v) => {
            print_receipt(&v);
            if v.get("ok") == Some(&json!(true)) {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

pub fn bundle_create(platform: &str, dry_run: bool) -> i32 {
    if dry_run {
        println!("schema=caduceus.cert.bundle.v1");
        println!("ok=true");
        println!("dry_run=true");
        println!("platform={platform}");
        println!("client_reinstall_required=false");
        return 0;
    }
    match invoke(&["bundle", platform]) {
        Ok(v) => {
            print_receipt(&v);
            if v.get("ok") == Some(&json!(true)) {
                0
            } else {
                1
            }
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

pub fn status_json() -> Result<Value, String> {
    invoke(&["status"])
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use super::*;
     
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture_pythonpath() -> String {
        let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        root.push("tests/fixtures/staff");
        root.display().to_string()
    }

    #[test]
    fn issue_leaf_keeps_ca_stable() {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = env::temp_dir().join(format!("caduceus-house-ca-test-{n}"));
        let cert_dir = base.join("certs");
        let bundle_dir = base.join("bundles");
        std::fs::create_dir_all(&cert_dir).unwrap();
        std::fs::create_dir_all(&bundle_dir).unwrap();
        env::set_var("CADUCEUS_CERT_DIR", &cert_dir);
        env::set_var("CADUCEUS_CERT_BUNDLE_DIR", &bundle_dir);
        env::set_var("PYTHONPATH", fixture_pythonpath());
        env::set_var(
            "CADUCEUS_HOUSE_CA_CMD",
            "python3 -m caduceus_staff.house_ca",
        );
        let a = invoke(&["issue-leaf", "--sans", "alpha.home.arpa"]).expect("issue a");
        let b = invoke(&["issue-leaf", "--sans", "beta.home.arpa"]).expect("issue b");
        assert_eq!(a["ca_fingerprint"], b["ca_fingerprint"]);
        assert_ne!(a["leaf_fingerprint"], b["leaf_fingerprint"]);
        assert_eq!(a["client_reinstall_required"], json!(false));
        let bundle = invoke(&["bundle", "linux"]).expect("bundle");
        assert_eq!(bundle["ok"], json!(true));
        let _ = std::fs::remove_dir_all(base);
    }
}
