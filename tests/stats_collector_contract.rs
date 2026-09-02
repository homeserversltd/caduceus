use std::{collections::BTreeSet, fs};
#[test]
fn stats_contract_keeps_subprocesses_bounded_and_sample_keys_stable() {
    let source = fs::read_to_string("src/stats.rs").expect("stats source");
    let marker = r#"Command::new("nvidia-smi")"#;
    assert_eq!(source.matches(marker).count(), 1);
    let refresh = source.find("fn refresh_nvidia_gpu_cache").unwrap();
    let next = source[refresh..].find("fn nvidia_gpu_output").unwrap() + refresh;
    assert!(source[refresh..next].contains(marker));
    assert!(source[refresh..next].contains("Duration::from_millis(900)"));
    assert!(source.contains("Duration::from_secs(60)"));
    assert!(!source.contains(r#"Command::new("df")"#));
    assert!(!source.contains(r#"Command::new("ps")"#));
    assert!(source.contains("fn has_nvidia_gpu"));
    assert!(source.contains("process_sample_at"));
    let sample = caduceus::stats::snapshot();
    let object = sample.as_object().unwrap();
    assert_eq!(
        object.get("schema").and_then(|v| v.as_str()),
        Some("caduceus.appliance.stats.sample.v1")
    );
    let expected = BTreeSet::from([
        "ts",
        "collectedAt",
        "load",
        "temperature",
        "fans",
        "gpu",
        "memory",
        "network",
        "tcp",
        "disk",
        "processes",
    ]);
    let actual = object
        .keys()
        .filter(|k| k.as_str() != "schema")
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
}
