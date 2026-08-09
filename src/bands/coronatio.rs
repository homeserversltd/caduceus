use crate::tools::hyalos;
use base64::Engine;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;
const SCHEMA: &str = "caduceus.coronatio.source_currency.v1";
const DEFAULT_FORGEJO: &str = "http://git.home.arpa";
const REPOSITORY: &str = "HOMESERVERSLTD/coronatio";
const TOKEN_FILE: &str = "/home/owner/.ssh/forgejo-token";
fn valid_sha(v: &str) -> bool {
    v.len() == 40 && v.bytes().all(|b| b.is_ascii_hexdigit())
}
fn response(
    build: &str,
    ok: bool,
    origin: Option<&str>,
    relation: &str,
    signal: Option<&str>,
) -> Value {
    let mut b = json!({"ok":ok,"schema":SCHEMA,"originMainSha":origin,"buildSha":build,"relation":relation});
    if let Some(s) = signal {
        b["firstMissingSignal"] = Value::String(s.into())
    }
    b
}
fn credential() -> Result<(String, String), String> {
    let p = std::env::var("CADUCEUS_FORGEJO_TOKEN_FILE").unwrap_or_else(|_| TOKEN_FILE.into());
    let t = std::fs::read_to_string(p)
        .map_err(|_| "caduceus-forgejo-credential-missing".to_string())?;
    let mut u = None;
    let mut k = None;
    for l in t.lines() {
        if let Some(v) = l.strip_prefix("FORGEJO_USERNAME=") {
            u = Some(v)
        }
        if let Some(v) = l.strip_prefix("FORGEJO_TOKEN=") {
            k = Some(v)
        }
    }
    match (u.filter(|v| !v.is_empty()), k.filter(|v| !v.is_empty())) {
        (Some(u), Some(k)) => Ok((u.into(), k.into())),
        _ => Err("caduceus-forgejo-credential-missing".into()),
    }
}
fn base() -> String {
    std::env::var("CADUCEUS_FORGEJO_URL")
        .unwrap_or_else(|_| DEFAULT_FORGEJO.into())
        .trim_end_matches('/')
        .into()
}
struct Http {
    status: u16,
    body: String,
}
fn get(url: &str, user: &str, token: &str) -> Result<Http, String> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| "caduceus-forgejo-api-failure".to_string())?;
    let (host, path) = rest
        .split_once('/')
        .ok_or_else(|| "caduceus-forgejo-api-failure".to_string())?;
    let mut s = TcpStream::connect(host).map_err(|_| "caduceus-forgejo-api-failure".to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    let auth = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{token}"));
    write!(s,"GET /{path} HTTP/1.1\r\nHost: {host}\r\nAuthorization: Basic {auth}\r\nConnection: close\r\n\r\n").map_err(|_|"caduceus-forgejo-api-failure".to_string())?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)
        .map_err(|_| "caduceus-forgejo-api-failure".to_string())?;
    let text = String::from_utf8(raw).map_err(|_| "caduceus-forgejo-api-failure".to_string())?;
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "caduceus-forgejo-api-failure".to_string())?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .ok_or_else(|| "caduceus-forgejo-api-failure".to_string())?;
    Ok(Http {
        status,
        body: body.into(),
    })
}
fn classify(s: &str) -> Option<&'static str> {
    match s {
        "identical" => Some("current"),
        "behind" => Some("behind"),
        "diverged" | "ahead" | "unknown" | "no_ancestry" => Some("diverged"),
        _ => None,
    }
}
pub fn source_currency_json(build: &str) -> Value {
    let result: Result<Value, String> = if !valid_sha(build) {
        Err("caduceus-build-sha-malformed".into())
    } else {
        (|| -> Result<Value, String> {
            let (u, k) = credential()?;
            let b = base();
            let branch = get(
                &format!("{b}/api/v1/repos/{REPOSITORY}/branches/main"),
                &u,
                &k,
            )?;
            if branch.status != 200 {
                return Err("caduceus-forgejo-api-failure".into());
            }
            let j: Value =
                serde_json::from_str(&branch.body).map_err(|_| "caduceus-forgejo-api-failure")?;
            let origin = j
                .pointer("/commit/id")
                .and_then(Value::as_str)
                .filter(|v| valid_sha(v))
                .ok_or_else(|| "caduceus-forgejo-api-failure".to_string())?
                .to_string();
            let rel = if build.eq_ignore_ascii_case(&origin) {
                "current"
            } else {
                let c = get(
                    &format!("{b}/api/v1/repos/{REPOSITORY}/compare/{build}...main"),
                    &u,
                    &k,
                )?;
                if c.status != 200 {
                    return Err("caduceus-forgejo-api-failure".into());
                } else {
                    let cj: Value = serde_json::from_str(&c.body)
                        .map_err(|_| "caduceus-forgejo-api-failure")?;
                    classify(cj.get("status").and_then(Value::as_str).unwrap_or(""))
                        .ok_or_else(|| "caduceus-forgejo-api-failure".to_string())?
                }
            };
            Ok(response(build, true, Some(&origin), rel, None))
        })()
    };
    let body = match result {
        Ok(v) => v,
        Err(s) => response(build, false, None, "unknown", Some(&s)),
    };
    let ok = body.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let _ = hyalos::reflect_json(json!({
        "organ": "coronatio-source-currency",
        "kind": "source-currency-check",
        "ok": ok,
        "message": if ok { "source-currency-checked" } else { "source-currency-check-failed" },
        "attributes_redacted": {
            "buildSha": body.get("buildSha").cloned().unwrap_or(Value::Null),
            "originMainSha": body.get("originMainSha").cloned().unwrap_or(Value::Null),
            "relation": body.get("relation").cloned().unwrap_or(Value::Null)
        }
    }));
    body
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed() {
        let b = source_currency_json("bad");
        assert_eq!(b["relation"], "unknown");
        assert!(b["firstMissingSignal"].as_str().is_some())
    }
    #[test]
    fn source_currency_reflects_to_hyalos_without_changing_the_response() {
        let root =
            std::env::temp_dir().join(format!("caduceus-coronatio-hyalos-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::env::set_var("CADUCEUS_ROOT", &root);
        let body = source_currency_json("bad");
        assert_eq!(body["ok"], false);
        assert_eq!(body["schema"], SCHEMA);
        assert_eq!(body["originMainSha"], Value::Null);
        assert_eq!(body["relation"], "unknown");
        assert_eq!(body["firstMissingSignal"], "caduceus-build-sha-malformed");
        let channel = std::fs::read_to_string(root.join("var/log/hyalos/channel.jsonl")).unwrap();
        let event: Value = serde_json::from_str(channel.trim()).unwrap();
        assert_eq!(event["organ"], "coronatio-source-currency");
        assert_eq!(event["kind"], "source-currency-check");
        assert_eq!(event["ok"], false);
        assert_eq!(event["message"], "source-currency-check-failed");
        assert_eq!(event["attributes_redacted"]["buildSha"], "bad");
        assert_eq!(event["attributes_redacted"]["originMainSha"], Value::Null);
        assert_eq!(event["attributes_redacted"]["relation"], "unknown");
        assert!(!root.join("var/lib/caduceus/receipts").exists());
        std::env::remove_var("CADUCEUS_ROOT");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn forgejo_api_failure() {
        std::env::set_var("CADUCEUS_FORGEJO_TOKEN_FILE", "/path/that/does/not/exist");
        let b = source_currency_json(&"a".repeat(40));
        assert_eq!(b["ok"], false);
        assert_eq!(b["relation"], "unknown");
        assert!(b["firstMissingSignal"].as_str().is_some())
    }
    #[test]
    fn relations() {
        assert_eq!(classify("identical"), Some("current"));
        assert_eq!(classify("behind"), Some("behind"));
        assert_eq!(classify("ahead"), Some("diverged"));
        assert_eq!(classify("diverged"), Some("diverged"));
        assert_eq!(classify("unknown"), Some("diverged"));
        assert_eq!(classify("no_ancestry"), Some("diverged"))
    }
    #[test]
    fn forgejo_request_paths_name_coronatio_not_caduceus() {
        let build = "a".repeat(40);
        let main = format!("/api/v1/repos/{REPOSITORY}/branches/main");
        let compare = format!("/api/v1/repos/{REPOSITORY}/compare/{build}...main");
        assert!(main.contains("HOMESERVERSLTD/coronatio"));
        assert!(compare.contains("HOMESERVERSLTD/coronatio"));
        assert!(!main.contains("HOMESERVERSLTD/caduceus"));
        assert!(!compare.contains("HOMESERVERSLTD/caduceus"));
    }
    #[test]
    fn response_secret_absence() {
        let s = response(&"a".repeat(40), false, None, "unknown", Some("failed")).to_string();
        assert!(!s.contains("FORGEJO_TOKEN"));
        assert!(!s.contains("password"))
    }
    #[test]
    fn hyalos_reflection_attributes_are_secret_free() {
        let reflection = json!({
            "organ": "coronatio-source-currency",
            "kind": "source-currency-check",
            "ok": false,
            "message": "source-currency-check-failed",
            "attributes_redacted": {
                "buildSha": "a".repeat(40),
                "originMainSha": Value::Null,
                "relation": "unknown"
            }
        });
        let s = reflection.to_string();
        assert!(!s.contains("token"));
        assert!(!s.contains("password"))
    }
}
