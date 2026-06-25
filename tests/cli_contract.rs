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
    assert!(text.contains("caduceus pjlink devices"));
    assert!(text.contains("caduceus pjlink scan <device-id> [--dry-run]"));
    assert!(text.contains("caduceus pjlink known-products"));
    assert!(text.contains("caduceus pjlink known add <device-id> [--dry-run] [--from-profile]"));
    assert!(text.contains("caduceus pjlink known remove <entry-id>"));
    assert!(text.contains("caduceus pjlink power set <device-id> <on|off> [--dry-run]"));
    assert!(text.contains("caduceus identity show"));
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
    assert!(text.contains("count=5"));
    assert!(text.contains("actuator=backblaze-b2-recover"));
    assert!(text.contains("actuator=calibre-helper-daemon"));
    assert!(text.contains("class=staff-python"));
    assert!(text.contains("/usr/local/sbin/caduceus-backblaze-recover"));
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
fn staff_intent_cli_accepts_coronatio_route_shape() {
    let output = Command::new(bin())
        .env("CADUCEUS_ROOT", "tests/fixtures/homeserver")
        .args(["staff", "intent", "POST", "/api/admin/system/restart"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("caduceus.staff.intent.v1"));
    assert!(stdout.contains("/api/admin/system/restart"));
}
