use serde_json::Value;
use std::{fs, path::Path};

const LEAVES: &[&str] = &[
    "settings/ssh/config",
    "settings/ssh/authorized-keys",
    "settings/ssh/service/enable",
    "settings/ssh/service/disable",
];

#[test]
fn settings_ssh_leaves_are_discoverable_and_have_admittance_seats() {
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
fn settings_ssh_profile_lits_canonical_canopy() {
    let profile = fs::read_to_string("profiles/console/index.yaml").unwrap();
    for namespace in LEAVES {
        assert!(profile
            .lines()
            .any(|line| line.trim() == format!("- {namespace}")));
    }
}

#[test]
fn settings_ssh_leaves_use_only_the_common_cold_seat_helper() {
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
fn settings_ssh_canopy_debt_signals_are_non_placeholder_unique_and_namespace_mapped() {
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
        "settings_ssh debt signals must be unique"
    );
}
