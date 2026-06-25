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
    assert!(text.contains("caduceus network status"));
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
