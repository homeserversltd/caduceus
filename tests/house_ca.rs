use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn root() -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "caduceus-house-ca-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}
fn run(root: &std::path::Path, args: &[&str]) -> serde_json::Value {
    let out = Command::new("python3")
        .args(["-m", "caduceus_staff.house_ca"])
        .args(args)
        .env("PYTHONPATH", "tests/fixtures/staff")
        .env("CADUCEUS_ROOT", root)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[test]
fn house_ca_integration() {
    let root = root();
    let a = run(&root, &["issue-leaf", "alpha.home.arpa"]);
    let b = run(
        &root,
        &["issue-leaf", "beta.home.arpa", "--ips", "192.168.123.22"],
    );
    assert_eq!(a["ca_fingerprint"], b["ca_fingerprint"]);
    assert_ne!(a["leaf_fingerprint"], b["leaf_fingerprint"]);
    let bundle = run(&root, &["bundle-export", "linux"]);
    let bytes = std::fs::read(bundle["path"].as_str().unwrap()).unwrap();
    assert!(!bytes.windows(11).any(|w| w == b"PRIVATE KEY"));
    let before = walk(&root);
    let dry = run(
        &root,
        &[
            "portal-admit",
            "portal.home.arpa",
            "192.168.123.20",
            "http://127.0.0.1:8080",
            "--dry-run",
        ],
    );
    assert_eq!(dry["children"][0]["primitive"], "constituent_lock");
    assert_eq!(dry["children"][1]["primitive"], "issue_leaf");
    assert_eq!(dry["children"][2]["primitive"], "apply_nginx");
    assert_eq!(dry["children"][3]["primitive"], "state_commit");
    assert_eq!(before, walk(&root));
    let admitted = run(
        &root,
        &[
            "portal-admit",
            "portal.home.arpa",
            "192.168.123.20",
            "http://127.0.0.1:8080",
        ],
    );
    assert_eq!(admitted["generation"], 1);
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("var/lib/caduceus/state.json")).unwrap())
            .unwrap();
    assert_eq!(state["caduceus.household.tls.v1"]["profile"], "homeserver");
    let _ = std::fs::remove_dir_all(root);
}
fn walk(root: &std::path::Path) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    fn visit(p: &std::path::Path, r: &std::path::Path, o: &mut Vec<(String, u64)>) {
        if let Ok(es) = std::fs::read_dir(p) {
            for e in es.flatten() {
                let p = e.path();
                if p.is_dir() {
                    visit(&p, r, o)
                } else {
                    o.push((
                        p.strip_prefix(r).unwrap().display().to_string(),
                        e.metadata().unwrap().len(),
                    ))
                }
            }
        }
    }
    visit(root, root, &mut out);
    out.sort();
    out
}
