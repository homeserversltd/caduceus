use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_caduceus")
}

#[test]
fn help_names_public_commands() {
    let out = Command::new(bin()).arg("--help").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("caduceus update now"));
    assert!(text.contains("caduceus sync now"));
    assert!(text.contains("caduceus legacy-sbin list"));
    assert!(text.contains("caduceus homeserver-sbin list"));
    assert!(text.contains("caduceus staff status"));
    assert!(text.contains("caduceus network status"));
    assert!(text.contains("caduceus network dhcp"));
    assert!(text.contains("caduceus pjlink devices"));
    assert!(text.contains("caduceus pjlink scan <device-id> [--dry-run]"));
    assert!(text.contains("caduceus pjlink known-products"));
    assert!(text.contains("caduceus pjlink known add <device-id> [--dry-run] [--from-profile]"));
    assert!(text.contains("caduceus pjlink known remove <entry-id>"));
    assert!(text.contains("caduceus pjlink power set <device-id> <on|off> [--dry-run]"));
    assert!(text.contains("caduceus identity show"));
    assert!(text.contains("caduceus hyalos reflect"));
    assert!(text.contains("caduceus hyalos tail"));
    assert!(!text.contains("caduceus hyalos project upload"));
}

#[test]
fn legacy_sbin_list_exposes_ingested_script_manifest() {
    let out = Command::new(bin())
        .args(["legacy-sbin", "list"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("schema=caduceus.legacy_sbin.list.v1"));
    assert!(text.contains("script=openvpnup-sh"));
    assert!(text.contains("execution=not-executed-by-caduceus"));
}

#[test]
fn legacy_sbin_show_preserves_whole_script_body_without_execution() {
    let out = Command::new(bin())
        .args(["legacy-sbin", "show", "openvpnup-sh"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("schema=caduceus.legacy_sbin.show.v1"));
    assert!(text.contains("execution=not-executed-by-caduceus"));
    assert!(text.contains("NAMESPACE=\"vpn\""));
    assert!(text.contains("pgrep -f 'port_forwarding.sh'"));
}

#[test]
fn fixture_identity_is_read() {
    let out = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/tv")
        .args(["identity", "show"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("arch-tv"));
    assert!(!text.contains("Azoth"));
    assert!(!text.contains("Kether"));
    assert!(!text.contains("Cibation"));
}

#[test]
fn update_toggle_dry_run_is_public_safe() {
    let out = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/tv")
        .args(["update", "service", "toggle", "off", "--dry-run"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("schema=caduceus.update.service.toggle.v1"));
    assert!(text.contains("mutation=false"));
    assert!(!text.contains("Fulcrum"));
    assert!(!text.contains("Azoth"));
    assert!(!text.contains("Kether"));
}

#[test]
fn tv_pjlink_devices_and_power_dry_run_are_native() {
    let list = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/tv")
        .args(["pjlink", "devices"])
        .output()
        .unwrap();
    assert!(list.status.success());
    let text = String::from_utf8(list.stdout).unwrap();
    assert!(text.contains("schema=caduceus.pjlink.devices.v1"));
    assert!(text.contains("device=living-room-tv"));

    let power = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/tv")
        .args([
            "pjlink",
            "power",
            "set",
            "living-room-tv",
            "on",
            "--dry-run",
        ])
        .output()
        .unwrap();
    assert!(power.status.success());
    let text = String::from_utf8(power.stdout).unwrap();
    assert!(text.contains("schema=caduceus.pjlink.power.v1"));
    assert!(text.contains("requested_state=on"));
    assert!(text.contains("mutation=false"));
    assert!(text.contains("dry_run=true"));
}

#[test]
fn tv_pjlink_known_product_catalog_is_jsonl_backed() {
    let known = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/tv")
        .args(["pjlink", "known-products"])
        .output()
        .unwrap();
    assert!(known.status.success());
    let text = String::from_utf8(known.stdout).unwrap();
    assert!(text.contains("schema=caduceus.pjlink.known-products.v1"));
    assert!(text.contains("entry=living-room-tv:homeserver:living-room-tv"));

    let scan = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/tv")
        .args(["pjlink", "scan", "living-room-tv", "--dry-run"])
        .output()
        .unwrap();
    assert!(scan.status.success());
    let text = String::from_utf8(scan.stdout).unwrap();
    assert!(text.contains("schema=caduceus.pjlink.product-scan.v1"));
    assert!(text.contains("manufacturer=HOMESERVER"));
    assert!(text.contains("product=Living Room TV"));

    let add = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/tv")
        .args([
            "pjlink",
            "known",
            "add",
            "living-room-tv",
            "--dry-run",
            "--from-profile",
        ])
        .output()
        .unwrap();
    assert!(add.status.success());
    let text = String::from_utf8(add.stdout).unwrap();
    assert!(text.contains("schema=caduceus.pjlink.known-product.add.v1"));
    assert!(text.contains("mutation=false"));
    assert!(text.contains("entry=living-room-tv:homeserver:living-room-tv"));
}

#[test]
fn console_sync_route_dry_run_is_public_safe() {
    let out = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/console")
        .args(["sync", "now", "--dry-run"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("schema=caduceus.harmonia.invoke.v1"));
    assert!(text.contains("route=sync_now"));
    assert!(text.contains("mutation=false"));
}

#[test]
fn console_sync_status_reads_route() {
    let out = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/console")
        .args(["sync", "status"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("route_present=true"));
}

#[test]
fn legacy_sbin_list_includes_conversion_metadata() {
    let out = Command::new(bin())
        .args(["legacy-sbin", "list"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("script=openvpnup-sh"));
    assert!(text.contains("intent=network-vpn-status"));
    assert!(text.contains("status=converted"));
}

#[test]
fn network_status_cli_reads_typed_fixture() {
    let out = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/console")
        .args(["network", "status"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("schema=caduceus.network.status.v1"));
    assert!(text.contains("openvpn_interface=tun0"));
    assert!(text.contains("port_forwarding_process_present=true"));
    assert!(text.contains("tailscale_has_address=true"));
    assert!(text.contains("ok=true"));
}

#[test]
fn homeserver_sbin_list_exposes_actual_homeserver_quarry() {
    let out = Command::new(bin())
        .args(["homeserver-sbin", "list"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("schema=caduceus.homeserver_sbin.list.v1"));
    assert!(text.contains("script=calibrehelperdaemon-sh"));
    assert!(text.contains("script=createcertbundle-sh"));
    assert!(text.contains("script=mountvault-sh"));
    assert!(text.contains("script=update-kea-dhcp-sh"));
    assert!(text.contains("execution=not-executed-by-caduceus"));
}

#[test]
fn homeserver_sbin_show_preserves_quarry_without_execution() {
    let out = Command::new(bin())
        .args(["homeserver-sbin", "show", "createcertbundle-sh"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("schema=caduceus.homeserver_sbin.show.v1"));
    assert!(text.contains("execution=not-executed-by-caduceus"));
    assert!(text.contains("createCertBundle"));
}

#[test]
fn staff_actuators_list_backblaze_and_calibre_python_lanes() {
    let out = Command::new(bin())
        .args(["staff", "actuators"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("schema=caduceus.staff.actuators.v1"));
    let profile: serde_json::Value =
        serde_json::from_str(include_str!("../data/staff-actuators/profile.json")).unwrap();
    for actuator in profile["actuators"].as_array().unwrap() {
        let id = actuator["id"].as_str().unwrap();
        let library_entry = actuator["libraryEntry"].as_str().unwrap();
        let receipt_family = actuator["receiptFamily"].as_str().unwrap();
        assert!(!library_entry.is_empty(), "{id} has no libraryEntry");
        assert!(
            receipt_family.ends_with(".v1"),
            "{id} has no receipt schema"
        );
        assert!(text.contains(&format!("actuator={id} ")));
        assert!(text.contains(&format!("lib={library_entry} ")));
    }
}

#[test]
fn homeserver_sbin_marks_backblaze_and_calibre_staff_profiled() {
    let out = Command::new(bin())
        .args(["homeserver-sbin", "list"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("script=calibrehelperdaemon-sh"));
    assert!(text.contains("script=homeserver-backblaze-tab-b2-disaster-recovery-py"));
    assert!(text.contains("band=staff-python"));
    assert!(text.contains("status=staff-profiled"));
    assert!(!text.contains("fdwebsite"));
    assert!(!text.to_lowercase().contains("thermaltest"));
}

#[test]
fn staff_intent_cli_accepts_coronatio_route_intent() {
    let output = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/homeserver")
        .args(["staff", "intent", "POST", "/api/admin/system/restart"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("caduceus.staff.intent.v1"));
    assert!(stdout.contains("queued-behind-typed-actuator"));
}

#[test]
fn staff_intent_cli_marks_upload_route() {
    let output = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/homeserver")
        .args(["staff", "intent", "POST", "/api/files/upload"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("caduceus.staff.upload_intent.v1"));
    assert!(stdout.contains("upload-queued-behind-typed-actuator"));
}

#[test]
fn network_dhcp_cli_routes_reads_to_pinned_actuator_and_legacy_verbs_to_dhcp() {
    let read = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/homeserver")
        .env("PYTHONPATH", "tests/fixtures/staff")
        .env(
            "CADUCEUS_NETWORK_READ_CMD",
            "python3 -m caduceus_staff.network.dhcp",
        )
        .args(["network", "dhcp", "status"])
        .output()
        .unwrap();
    assert!(read.status.success());
    let stdout = String::from_utf8(read.stdout).unwrap();
    assert!(stdout.contains("\"actuatorId\":\"network.dhcp.status\""));
    assert!(stdout.contains("caduceus.network.dhcp.status.v1"));
    assert!(stdout.contains("caduceus_staff.network.dhcp"));

    let reload = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/homeserver")
        .env("PYTHONPATH", "tests/fixtures/staff")
        .env(
            "CADUCEUS_DHCP_CMD",
            "python3 -m caduceus_staff.network.dhcp",
        )
        .args(["network", "dhcp", "reload"])
        .output()
        .unwrap();
    assert!(reload.status.success());
    let stdout = String::from_utf8(reload.stdout).unwrap();
    assert!(stdout.contains("caduceus.network.dhcp.reload.v1"));
    assert!(!stdout.contains("caduceus-public-action-not-allowed"));

    let refusal = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/homeserver")
        .args(["network", "device", "remove"])
        .output()
        .unwrap();
    assert!(!refusal.status.success());
    assert!(String::from_utf8(refusal.stderr)
        .unwrap()
        .contains("caduceus-public-action-not-allowed"));
}

#[test]
fn hyalos_cli_reflects_redacts_tails_with_filters_and_no_projection() {
    let root = std::env::temp_dir().join(format!("caduceus-hyalos-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::copy(
        "tests/fixtures/homeserver/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    let reflected = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args([
            "hyalos",
            "reflect",
            "file-ingress",
            "upload",
            "proof.txt",
            "--level",
            "info",
            "--payload",
            r#"{"token":"not-on-wall"}"#,
        ])
        .output()
        .unwrap();
    assert!(
        reflected.status.success(),
        "{}",
        String::from_utf8_lossy(&reflected.stderr)
    );
    let channel = std::fs::read_to_string(root.join("var/log/appliance/appliance.log")).unwrap();
    assert!(channel.contains("hyalos.channel.event.v2"));
    assert!(channel.contains("attributes_redacted"));
    assert!(channel.contains(r#""level":"info""#));
    assert!(channel.contains('T'));
    assert!(channel.contains("[REDACTED]"));
    assert!(!channel.contains("not-on-wall"));

    let other = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args(["hyalos", "reflect", "caduceus", "receipt", "other-event"])
        .output()
        .unwrap();
    assert!(other.status.success());

    let tail = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args(["hyalos", "tail", "5", "--kind", "upload"])
        .output()
        .unwrap();
    assert!(tail.status.success());
    let tail_text = String::from_utf8_lossy(&tail.stdout);
    assert!(tail_text.contains("caduceus.hyalos.tail.v1"));
    assert!(tail_text.contains("upload"));
    assert!(!tail_text.contains("other-event"));

    let project = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args(["hyalos", "project", "upload"])
        .output()
        .unwrap();
    assert!(!project.status.success());
    assert!(!root.join("var/log/hyalos/projections/upload.log").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn hyalos_cli_migrates_legacy_channel_before_append() {
    let root =
        std::env::temp_dir().join(format!("caduceus-hyalos-migration-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::copy(
        "tests/fixtures/homeserver/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    let legacy = root.join("var/log/hyalos/channel.jsonl");
    std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
    std::fs::write(&legacy, "known legacy line\n").unwrap();

    let reflected = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args([
            "hyalos",
            "reflect",
            "caduceus",
            "receipt",
            "new-channel-event",
        ])
        .output()
        .unwrap();
    assert!(
        reflected.status.success(),
        "{}",
        String::from_utf8_lossy(&reflected.stderr)
    );

    let channel = std::fs::read_to_string(root.join("var/log/appliance/appliance.log")).unwrap();
    assert!(channel.contains("known legacy line"));
    assert!(channel.contains("new-channel-event"));
    assert!(!legacy.exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn hyalos_source_has_no_projection_upload_paths() {
    let src = std::fs::read_to_string("src/tools/hyalos.rs").unwrap();
    assert!(!src.contains("PROJECTIONS_PATH"));
    assert!(!src.contains("project_upload_json"));
    assert!(!src.contains("upload.log"));
}

fn config_temp_root(tag: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("caduceus-config-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::create_dir_all(root.join("etc/appliance")).unwrap();
    std::fs::copy(
        "tests/fixtures/tv/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    std::fs::copy(
        "tests/fixtures/tv/etc/appliance/config.json",
        root.join("etc/appliance/config.json"),
    )
    .unwrap();
    root
}

#[test]
fn config_path_show_get_resolve_each_profile() {
    for (profile, device_path) in [
        ("tv", "/etc/appliance/config.json"),
        ("console", "/etc/appliance/config.json"),
        ("homeserver", "/etc/appliance/config.json"),
    ] {
        let fixture = format!("tests/fixtures/{profile}");
        let path = Command::new(bin())
            .env("CADUCEUS_ROOT", &fixture)
            .args(["config", "path"])
            .output()
            .unwrap();
        assert!(path.status.success());
        let text = String::from_utf8(path.stdout).unwrap();
        assert!(text.contains("caduceus.household-config.path.v1"));
        assert!(text.contains(&format!("\"profile\":\"{profile}\"")));
        assert!(text.contains(&format!("\"path\":\"{device_path}\"")));
        assert!(!text.contains("tests/fixtures"));

        let show = Command::new(bin())
            .env("CADUCEUS_ROOT", &fixture)
            .args(["config", "show"])
            .output()
            .unwrap();
        assert!(show.status.success());
        let text = String::from_utf8(show.stdout).unwrap();
        assert!(text.contains("caduceus.household-config.show.v1"));
        assert!(text.contains("household.config.v1"));
        assert!(!text.contains("tests/fixtures"));

        let get = Command::new(bin())
            .env("CADUCEUS_ROOT", &fixture)
            .args(["config", "get", "tabs.starred"])
            .output()
            .unwrap();
        assert!(get.status.success());
        let json: serde_json::Value = serde_json::from_slice(&get.stdout).unwrap();
        assert_eq!(json["schema"], "caduceus.household-config.get.v1");
        assert!(json["value"].as_array().unwrap().len() >= 2);
    }
}

#[test]
fn config_set_roundtrip_writes_backup_and_public_safe_receipt() {
    let root = config_temp_root("cli-set");
    let set = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args(["config", "set", "display.theme", "\"light\""])
        .output()
        .unwrap();
    assert!(
        set.status.success(),
        "{}",
        String::from_utf8_lossy(&set.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&set.stdout).unwrap();
    assert_eq!(receipt["schema"], "caduceus.household-config.mutation.v1");
    assert_eq!(receipt["ok"], true);
    assert_eq!(receipt["op"], "set");
    assert_eq!(receipt["changed"], true);
    assert_eq!(receipt["path"], "/etc/appliance/config.json");
    assert_eq!(receipt["keysTouched"][0], "display.theme");

    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(document["display"]["theme"], "light");
    assert_eq!(document["tabs"]["starred"][0], "jellyfin");

    let backups: Vec<_> = std::fs::read_dir(root.join("var/lib/caduceus/backups/household-config"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(backups.len(), 1);
    let backup_text = std::fs::read_to_string(&backups[0]).unwrap();
    assert!(backup_text.contains("\"dark\""));

    let receipts: Vec<_> = std::fs::read_dir(root.join("var/lib/caduceus/receipts"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(receipts.len(), 1);
    let receipt_text = std::fs::read_to_string(&receipts[0]).unwrap();
    assert!(receipt_text.contains("caduceus.household-config.mutation.v1"));
    assert!(!receipt_text.contains(root.to_str().unwrap()));
    assert!(!receipt_text.contains("Fulcrum"));

    let get = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args(["config", "get", "display.theme"])
        .output()
        .unwrap();
    assert!(get.status.success());
    let json: serde_json::Value = serde_json::from_slice(&get.stdout).unwrap();
    assert_eq!(json["value"], "light");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn config_set_asserts_declared_file_mode_despite_child_umask() {
    let root = config_temp_root("cli-mode");
    let config = root.join("etc/appliance/config.json");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
    let before = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
    assert_eq!(before, 0o600);

    let output = Command::new("sh")
        .env("CADUCEUS_ROOT", &root)
        .args([
            "-c",
            "umask 077; exec \"$@\"",
            "caduceus-umask",
            bin(),
            "config",
            "set",
            "display.theme",
            "\"light\"",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let after = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
    assert_eq!(after, 0o660, "mutate must override the child umask");
    eprintln!("config mode transition under umask 077: {before:04o} -> {after:04o}");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn config_patch_deep_merge_preserves_starred_unless_explicitly_patched() {
    let root = config_temp_root("cli-patch");
    let patch = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args([
            "config",
            "patch",
            r#"{"tabs":{"order":["media","home"]},"display":{"sleepMinutes":15}}"#,
        ])
        .output()
        .unwrap();
    assert!(
        patch.status.success(),
        "{}",
        String::from_utf8_lossy(&patch.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&patch.stdout).unwrap();
    assert_eq!(receipt["schema"], "caduceus.household-config.mutation.v1");
    assert_eq!(receipt["op"], "patch");
    assert_eq!(receipt["changed"], true);

    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(document["tabs"]["starred"][0], "jellyfin");
    assert_eq!(document["tabs"]["starred"][1], "photos");
    assert_eq!(document["tabs"]["order"][0], "media");
    assert_eq!(document["display"]["sleepMinutes"], 15);
    assert_eq!(document["display"]["theme"], "dark");

    let explicit = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args(["config", "patch", r#"{"tabs":{"starred":["photos"]}}"#])
        .output()
        .unwrap();
    assert!(explicit.status.success());
    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(document["tabs"]["starred"], serde_json::json!(["photos"]));
    assert_eq!(document["tabs"]["order"][0], "media");
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn config_unknown_profile_is_refused() {
    let root = std::env::temp_dir().join(format!("caduceus-config-unknown-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::write(
        root.join("etc/caduceus/profile.yaml"),
        "schema: caduceus.profile.v1\nprofile: toaster\ncommands:\n- config path\n- config show\n",
    )
    .unwrap();
    let out = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args(["config", "path"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)
        .unwrap()
        .contains("caduceus-household-config-profile-unknown"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn config_path_injection_is_refused_without_mutation() {
    let get = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/tv")
        .args(["config", "get", "../../etc/passwd"])
        .output()
        .unwrap();
    assert!(!get.status.success());
    assert!(String::from_utf8(get.stderr)
        .unwrap()
        .contains("caduceus-household-config-path-invalid"));

    let root = config_temp_root("cli-inject");
    let original = std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap();
    for hostile in ["../../etc/hostile", "/etc/hostile", "tabs..starred"] {
        let set = Command::new(bin())
            .env("CADUCEUS_ROOT", &root)
            .args(["config", "set", hostile, "\"x\""])
            .output()
            .unwrap();
        assert!(!set.status.success(), "{hostile} was not refused");
        assert!(String::from_utf8(set.stderr)
            .unwrap()
            .contains("caduceus-household-config-path-invalid"));
    }
    assert_eq!(
        std::fs::read_to_string(root.join("etc/appliance/config.json")).unwrap(),
        original
    );
    assert!(!root.join("var/lib/caduceus/backups").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn config_write_refuses_missing_homeserver_install_without_touching_legacy() {
    let root = std::env::temp_dir().join(format!(
        "caduceus-config-homeserver-missing-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::create_dir_all(root.join("var/www/homeserver/src/config")).unwrap();
    std::fs::copy(
        "tests/fixtures/homeserver/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    std::fs::copy(
        "tests/fixtures/homeserver/etc/caduceus/identity.json",
        root.join("etc/caduceus/identity.json"),
    )
    .unwrap();
    let legacy = root.join("var/www/homeserver/src/config/homeserver.json");
    std::fs::copy(
        "tests/fixtures/homeserver/var/www/homeserver/src/config/homeserver.json",
        &legacy,
    )
    .unwrap();
    let legacy_before = std::fs::read_to_string(&legacy).unwrap();

    let set = Command::new(bin())
        .env("CADUCEUS_ROOT", &root)
        .args(["config", "set", "display.theme", "\"light\""])
        .output()
        .unwrap();
    assert!(!set.status.success());
    assert!(String::from_utf8(set.stderr)
        .unwrap()
        .contains("caduceus-household-config-installed-path-missing"));
    assert_eq!(std::fs::read_to_string(legacy).unwrap(), legacy_before);
    assert!(!root.join("etc/appliance/config.json").exists());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn profile_sources_reseed_crosses_public_cli_launcher_staff_and_is_idempotent() {
    let root = std::env::temp_dir().join(format!(
        "caduceus-source-map-public-crossing-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("etc/caduceus")).unwrap();
    std::fs::create_dir_all(root.join("etc/appliance")).unwrap();
    std::fs::copy(
        "tests/fixtures/tv/etc/caduceus/profile.yaml",
        root.join("etc/caduceus/profile.yaml"),
    )
    .unwrap();
    std::fs::write(
        root.join("etc/appliance/profile.json"),
        r#"{
  "schema": "homeserver.device-profile.v1",
  "birth_provenance": {"born":"fixture"},
  "hardware": {"serial":"abc"},
  "kernel": {"profile":"tv"},
  "profile": "tv"
}
"#,
    )
    .unwrap();
    std::fs::write(
        root.join("etc/caduceus/source-map.json"),
        r#"{"caduceus":{"ref":"main","candidates":[{"kind":"git","url":"git@git.home.arpa:HOMESERVERSLTD/caduceus.git"}]}}"#,
    )
    .unwrap();
    let worktree = std::env::current_dir().unwrap();
    let launcher = worktree.join("data/staff-actuators/caduceus-profile-sources-reseed");
    let staff = worktree.join("data/staff-actuators");
    let run = || {
        Command::new("sudo")
            .args(["-n", "env"])
            .arg(format!("CADUCEUS_ROOT={}", root.display()))
            .arg(format!(
                "CADUCEUS_PROFILE_SOURCES_RESEED_CMD={}",
                launcher.display()
            ))
            .arg("CADUCEUS_STAFF_PYTHON=/usr/bin/python3")
            .arg(format!("PYTHONPATH={}", staff.display()))
            .arg(bin())
            .args(["profile", "sources", "reseed"])
            .output()
            .unwrap()
    };
    let first = run();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_receipt: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first_receipt["ok"], true);
    assert_eq!(first_receipt["changed"], true);
    let certificate = std::fs::read(root.join("etc/appliance/profile.json")).unwrap();
    assert!(String::from_utf8_lossy(&certificate).contains("\"sources\""));
    let metadata = std::fs::metadata(root.join("etc/appliance/profile.json")).unwrap();
    assert_eq!(metadata.permissions().mode() & 0o777, 0o444);
    assert_eq!(metadata.uid(), 0);
    assert_eq!(metadata.gid(), 0);
    let second = run();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    let second_receipt: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(second_receipt["changed"], false);
    assert_eq!(
        certificate,
        std::fs::read(root.join("etc/appliance/profile.json")).unwrap()
    );
    let _ = Command::new("sudo")
        .args(["-n", "rm", "-rf"])
        .arg(&root)
        .status();
}
