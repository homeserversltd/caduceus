use serde_json::Value;
use std::{fs, path::Path};

#[test]
fn input_route_has_exact_snake_seat_and_no_doors_index() {
    let value: Value =
        serde_json::from_str(&fs::read_to_string("routes/settings/input/index.json").unwrap())
            .unwrap();
    assert_eq!(
        value,
        serde_json::json!({"namespace":"settings/input","admittance":"open","flags":{},"serve":[{"snake":"settings/input"}]})
    );
    assert!(!Path::new("doors/index.json").exists());
}

#[test]
fn tv_lits_input_route_with_exact_set_command() {
    let profile = fs::read_to_string("profiles/tv/index.yaml").unwrap();
    assert!(profile
        .lines()
        .any(|line| line.trim() == "- settings/input"));
    assert!(profile
        .lines()
        .any(|line| line.trim() == "- settings input read"));
    assert!(profile
        .lines()
        .any(|line| line.trim() == "- settings input set"));
    assert!(!profile
        .lines()
        .any(|line| line.trim() == "- settings input mutate"));

    let console = fs::read_to_string("profiles/console/index.yaml").unwrap();
    assert!(console
        .lines()
        .any(|line| line.trim() == "- settings/input"));
    assert!(console
        .lines()
        .any(|line| line.trim() == "- settings input read"));
    assert!(console
        .lines()
        .any(|line| line.trim() == "- settings input set"));
    assert!(!console
        .lines()
        .any(|line| line.trim() == "- settings input mutate"));
}

#[test]
fn input_leaf_registers_read_set_methods_and_snake_band() {
    let source = fs::read_to_string("routes/settings/input/index.rs").unwrap();
    assert!(source.contains("settings input read"));
    assert!(source.contains("settings input set"));
    assert!(!source.contains("settings input mutate"));
    assert!(source.contains("/api/v1/settings/input"));
    assert!(source.contains("axum::routing::get(read_http)"));
    assert!(source.contains(".post(set_http)"));
    assert!(source.contains(".put(set_http)"));
    assert!(source.contains(".patch(set_http)"));
    assert!(source.contains("crate::gate::snake::run"));
    assert!(source.contains("const BAND: &str = \"settings/input\""));
    assert!(source.contains("\"transition\":transition"));
    assert!(source.contains("envelope[\"payload\"] = payload"));
}
