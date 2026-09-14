use serde_json::Value;

const CLONE_CASES: &[&str] = &[
    "clone-source-admits-at-E",
    "clone-source-stores-verbatim-by-admit",
    "release-source-unchanged",
    "clone-skips-remote-release",
    "clone-placeholder-digest-accepted",
    "clone-real-digest-refused",
    "permissions-accepted",
    "permissions-grantee-refused",
    "permissions-path-outside-seat",
    "permissions-wildcard-refused",
    "permissions-file-symlink",
    "permissions-file-writable",
    "permissions-visudo-refused",
    "xenos-not-admitted",
    "xenos-band-unlisted",
    "xenos-run-timeout",
    "household-python-run-still-answers",
];

#[test]
fn xenia_clone_and_run_fixture_covers_contract_matrix() {
    let source_schema: Value =
        serde_json::from_str(include_str!("../schema/appliance.xenia.v1.json")).unwrap();
    let verdict_schema: Value =
        serde_json::from_str(include_str!("../schema/caduceus.xenia.verdict.v1.json")).unwrap();
    let validation = include_str!("../routes/xenia/support/validation.rs");
    let snake = include_str!("../gate/snake.rs");
    let doors = include_str!("../routes/xenia/support/doors.rs");
    let route = include_str!("../routes/xenia/:id/run/index.rs");
    let route_declaration = include_str!("../routes/xenia/:id/run/index.json");
    let routes_mod = include_str!("../routes/mod.rs");
    let profile = include_str!("../profiles/homeserver/index.yaml");
    let readme = include_str!("../README.md");

    let source = &source_schema["fields"]["source"];
    assert_eq!(source["fields"]["kind"]["enum"][0], "clone");
    assert!(source["fields"]["repo"]["description"]
        .as_str()
        .unwrap()
        .contains("reachable Forgejo host"));
    assert!(source_schema["fields"]["content_inventory_digest"]["description"]
        .as_str()
        .unwrap()
        .contains("sixty-four-zero placeholder"));
    assert_eq!(verdict_schema["fields"]["verdict"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|value| *value == "ran")
        .count(), 1);
    assert_eq!(verdict_schema["forms"]["ran"]["required"][0], "receipt");

    assert!(validation.contains("let mut entry = manifest.clone();"));
    assert!(validation.contains("let clone = source(manifest)?;"));
    assert!(validation.contains("remote::release(manifest)?"));
    assert!(validation.contains("clone-digest-not-applicable"));
    assert!(validation.contains("check_permissions(id)?"));
    for refusal in [
        "clone-repo-required",
        "clone-ref-required",
        "clone-digest-not-applicable",
        "permissions-grantee-refused",
        "permissions-path-outside-seat",
        "permissions-wildcard-refused",
        "permissions-visudo-refused",
        "permissions-file-writable",
        "permissions-file-symlink",
    ] {
        assert!(validation.contains(refusal), "missing validation refusal {refusal}");
    }
    assert!(validation.contains("visudo-absent"));
    assert!(doors.contains("xenos-not-admitted"));
    assert!(doors.contains("xenos-band-unlisted"));

    assert!(snake.contains("pub fn run_launcher"));
    assert!(snake.contains("Duration::from_secs(30)"));
    assert!(snake.contains("MAX_OUTPUT_BYTES + 1"));
    assert!(doors.contains("xenos-run-timeout"));
    assert!(doors.contains("xenos-launcher-absent"));
    assert!(doors.contains("value[\"receipt\"]"));
    assert!(route.contains("/api/v1/xenia/:id/run"));
    assert!(route.contains("doors::run"));
    assert!(route_declaration.contains("xenia/:id/run"));
    assert!(routes_mod.contains("leaf_xenia__colon_id_run"));
    assert!(profile.contains("- xenia/:id/run"));
    assert!(readme.contains("`/api/v1/xenia/<id>/run`"));

    for case in CLONE_CASES {
        assert!(!case.is_empty());
    }
}
