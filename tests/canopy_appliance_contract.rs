use serde_json::Value;
use std::{fs, path::Path};

#[path = "../build.rs"]
mod build_profile;

const LEAVES: &[&str] = &[
    "appliance/restart",
    "appliance/reboot",
    "appliance/poweroff",
    "appliance/gamescope/restart",
];

#[test]
fn appliance_leaves_are_discoverable_and_have_admittance_seats() {
    for namespace in LEAVES {
        let path = format!("routes/{namespace}/index.json");
        let value: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(value["namespace"], *namespace);
        assert!(matches!(
            value["admittance"].as_str(),
            Some("open" | "admitted")
        ));
        assert!(!value["serve"].as_array().unwrap().is_empty());
        assert_eq!(value["flags"]["receiptSchema"], "caduceus.staff.v1");
        assert!(Path::new(&format!("routes/{namespace}/index.rs")).is_file());
    }
}

#[test]
fn appliance_profile_lits_canonical_canopy() {
    let profile = fs::read_to_string("profiles/console/index.yaml").unwrap();
    for namespace in LEAVES {
        assert!(profile
            .lines()
            .any(|line| line.trim() == format!("- {namespace}")));
    }
}

#[test]
fn appliance_leaves_use_only_the_common_cold_seat_helper() {
    for namespace in LEAVES {
        let source = fs::read_to_string(format!("routes/{namespace}/index.rs")).unwrap();
        assert!(source.contains("crate::routes::canopy::staff_route"));
        for stale in [
            "allows_command",
            "crossing_path",
            "ApiErrorBody",
            "ProviderKeysBody",
            "STEAMGRIDDB_API_KEY",
        ] {
            assert!(!source.contains(stale), "{namespace} retains stale {stale}");
        }
    }
}

#[test]
fn appliance_canopy_debt_signals_are_non_placeholder_unique_and_namespace_mapped() {
    let mut signals = Vec::new();
    for namespace in LEAVES {
        let path = format!("routes/{namespace}/index.json");
        let value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        let signal = value["flags"]["firstMissingSignal"]
            .as_str()
            .expect("each canopy seat must declare a debt signal")
            .to_owned();
        let expected = format!("agathodaimon-sbin-{}", namespace.replace('/', "-"));
        assert_ne!(
            signal, "exact-staff-door-debt",
            "{namespace} retains placeholder debt"
        );
        assert_eq!(
            signal, expected,
            "{namespace} debt must map exactly to its namespace"
        );
        signals.push(signal);
    }
    signals.sort_unstable();
    signals.dedup();
    assert_eq!(
        signals.len(),
        LEAVES.len(),
        "appliance debt signals must be unique"
    );
}

#[test]
fn build_profile_resolution_uses_explicit_profile_then_birth_certificate() {
    let console = Path::new("tests/fixtures/console");
    let tv = Path::new("tests/fixtures/tv");
    let missing = Path::new("tests/fixtures/missing");

    assert_eq!(
        build_profile::resolve_build_profile(None, console),
        "console"
    );
    assert_eq!(build_profile::resolve_build_profile(None, tv), "probe");
    assert_eq!(build_profile::resolve_build_profile(None, missing), "probe");
    assert_eq!(
        build_profile::resolve_build_profile(Some("everything-lit"), console),
        "everything-lit"
    );
}
