use serde_json::Value;
use std::{fs, path::Path};

const LEAVES: &[&str] = &[
    "gaming/input/profile/write",
    "gaming/input/profile/apply",
    "gaming/input/profile/bind",
    "gaming/sync",
    "gaming/provider-keys",
];

#[test]
fn gaming_leaves_are_discoverable_and_have_admittance_seats() {
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
fn gaming_profile_lits_canonical_routes_and_required_aliases() {
    let profile = fs::read_to_string("profiles/console/index.yaml").unwrap();
    for namespace in LEAVES {
        assert!(profile
            .lines()
            .any(|line| line.trim() == format!("- {namespace}")));
    }
    let sync = fs::read_to_string("routes/gaming/sync/index.rs").unwrap();
    let keys = fs::read_to_string("routes/gaming/provider-keys/index.rs").unwrap();
    for path in ["/api/v1/gaming/sync", "/api/v1/games/sync"] {
        assert!(sync.contains(path));
    }
    for path in [
        "/api/v1/gaming/provider-keys",
        "/api/v1/games/provider-keys",
    ] {
        assert!(keys.contains(path));
    }
}

#[test]
fn gaming_crossing_leaves_preserve_live_policy_and_band_paths() {
    let sync = fs::read_to_string("routes/gaming/sync/index.rs").unwrap();
    assert!(sync.contains("allows_command(\"gaming sync\")"));
    assert!(sync.contains("crossing_path(\"games/sync\""));
    let keys = fs::read_to_string("routes/gaming/provider-keys/index.rs").unwrap();
    for command in ["gaming provider-keys read", "gaming provider-keys save"] {
        assert!(keys.contains(&format!("allows_command(\"{command}\")")));
    }
    assert!(keys.contains("crossing_path(\"games/provider-keys\""));
    assert!(keys.contains("ProviderKeysBody"));
    assert!(keys.contains("caduceus-games-provider-keys-empty"));
    for stale in ["crate::routes::canopy::staff_route", "mutationPerformed"] {
        assert!(!sync.contains(stale));
        assert!(!keys.contains(stale));
    }
}

#[test]
fn gaming_input_leaves_still_use_the_cold_staff_seat() {
    for namespace in &LEAVES[..3] {
        let source = fs::read_to_string(format!("routes/{namespace}/index.rs")).unwrap();
        assert!(source.contains("crate::routes::canopy::staff_route"));
    }
}

#[test]
fn stale_games_owner_is_absent() {
    assert!(!Path::new("routes/games").exists());
    assert!(!Path::new("routes/games/sync/index.rs").exists());
    assert!(!Path::new("routes/games/provider-keys/index.rs").exists());
}

#[test]
fn gaming_canopy_debt_signals_are_non_placeholder_unique_and_namespace_mapped() {
    let mut signals = Vec::new();
    for namespace in LEAVES {
        let path = format!("routes/{namespace}/index.json");
        let value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        let signal = value["flags"]["firstMissingSignal"]
            .as_str()
            .unwrap()
            .to_owned();
        let expected = format!(
            "agathodaimon-sbin-{}",
            namespace.replace(char::from(47), "-")
        );
        assert_ne!(signal, "exact-staff-door-debt");
        assert_eq!(signal, expected);
        signals.push(signal);
    }
    signals.sort_unstable();
    signals.dedup();
    assert_eq!(signals.len(), LEAVES.len());
}
