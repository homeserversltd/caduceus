pub mod bands;
#[path = "lib/mod.rs"]
pub mod shared;
pub mod staff_commands;
pub mod trigger_gate;
#[doc(hidden)]
pub use shared as tools;

use crate::shared::policy;
use crate::bands::{
    child_device, config, dhcp, disk, dns, drive_test, gui, health, help, homeserver_sbin,
    hyalos, identity, legacy_sbin, local_ai, logs, network, network_identity, network_read, pjlink,
    profile, profile_module, receipts, serve, settings, source_map, staff, sync, update,
};

pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    match args.as_slice() {
        [] => {
            print_help();
            0
        }
        [flag] if flag == "--help" || flag == "-h" => {
            print_help();
            0
        }
        [domain] if domain == "help" => help::show(),
        [domain, verb] if domain == "identity" && verb == "show" => identity::show(),
        [domain, verb] if domain == "profile" && verb == "show" => profile::show(),
        [domain, object, verb, rest @ ..]
            if domain == "profile" && object == "sources" && verb == "reseed" =>
        {
            match require_policy(source_map::public_command(), rest) {
                Ok(filtered) if filtered.is_empty() => source_map::command(),
                Ok(_) => {
                    eprintln!("caduceus-source-map-reseed-arguments-forbidden");
                    2
                }
                Err(code) => code,
            }
        }
        [domain] if domain == "health" => health::show(),
        [domain, verb, rest @ ..] if domain == "logs" && verb == "read" => {
            match policy::allows_command("logs read") {
                Ok(true) => logs::show(
                    option_usize(rest, "--offset", 0),
                    option_usize(rest, "--limit", logs::DEFAULT_LIMIT).min(logs::MAX_LIMIT),
                ),
                Ok(false) => public_action_not_allowed(),
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        [domain, verb, rest @ ..] if domain == "logs" && verb == "clear" => {
            match require_policy("logs clear", rest) {
                Ok(_) => logs::clear(),
                Err(code) => code,
            }
        }
        [domain, verb] if domain == "disk" && verb == "census" => {
            match policy::allows_command("disk census") {
                Ok(true) => disk::show(),
                Ok(false) => public_action_not_allowed(),
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        [domain, object, verb] if domain == "disk" && object == "test" && verb == "progress" => {
            match policy::allows_command("disk test progress") {
                Ok(true) => drive_test_print(drive_test::progress_json()),
                Ok(false) => public_action_not_allowed(),
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        [domain, object, verb] if domain == "disk" && object == "test" && verb == "results" => {
            match policy::allows_command("disk test results") {
                Ok(true) => drive_test_print(drive_test::results_json()),
                Ok(false) => public_action_not_allowed(),
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        [domain, object, verb, device, test_type, rest @ ..]
            if domain == "disk" && object == "test" && verb == "start" =>
        {
            if rest.iter().any(|arg| arg == "--dry-run") {
                match policy::allows_command("disk test start") {
                    Ok(true) => drive_test_print(drive_test::start_json(device, test_type, true)),
                    Ok(false) => public_action_not_allowed(),
                    Err(error) => {
                        eprintln!("{error}");
                        1
                    }
                }
            } else {
                match require_policy("disk test start", rest) {
                    Ok(_) => drive_test_print(drive_test::start_json(device, test_type, false)),
                    Err(code) => code,
                }
            }
        }
        [domain, verb] if domain == "cert" && verb == "status" => {
            cert_command("cert status", "status", &[], crate::staff_commands::issue_certificate::status)
        }
        [domain, verb] if domain == "cert" && verb == "refresh-root" => {
            cert_command("cert refresh-root", "refresh_root", &[], || {
                cert_print(crate::staff_commands::issue_certificate::legacy_refresh_root_json())
            })
        }
        [domain, verb, rest @ ..] if domain == "cert" && verb == "ensure-root" => {
            cert_command("cert ensure-root", "ensure_root", &[], || {
                cert_print(crate::staff_commands::issue_certificate::ensure_root_json(
                    rest.iter().any(|arg| arg == "--dry-run"),
                    option_value(rest, "--renewal-authority"),
                ))
            })
        }
        [domain, verb, rest @ ..] if domain == "cert" && verb == "issue-leaf" => {
            cert_command("cert issue-leaf", "issue_leaf", &[], || {
                let dry = rest.iter().any(|a| a == "--dry-run");
                let sans = option_list(rest, "--sans");
                let ips = option_list(rest, "--ips");
                let identity = rest
                    .iter()
                    .find(|a| !a.starts_with('-') && !sans.contains(a) && !ips.contains(a))
                    .map(String::as_str)
                    .unwrap_or("home.arpa");
                match crate::staff_commands::issue_certificate::issue_leaf_json(identity, &sans, &ips, dry) {
                    Ok(v) => {
                        println!("{v}");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                }
            })
        }
        [domain, verb, rest @ ..] if domain == "cert" && verb == "bundle-export" => cert_command(
            "cert bundle-export",
            "bundle_export",
            &["cert bundle create"],
            || {
                let dry = rest.iter().any(|a| a == "--dry-run");
                let platform = rest
                    .iter()
                    .find(|a| !a.starts_with('-'))
                    .map(String::as_str)
                    .unwrap_or("linux");
                crate::staff_commands::issue_certificate::bundle_create(platform, dry)
            },
        ),
        [domain, object, verb, rest @ ..]
            if domain == "cert" && object == "bundle" && verb == "create" =>
        {
            cert_command(
                "cert bundle-export",
                "bundle_export",
                &["cert bundle create"],
                || {
                    let dry = rest.iter().any(|a| a == "--dry-run");
                    let platform = rest
                        .iter()
                        .find(|a| !a.starts_with('-'))
                        .map(String::as_str)
                        .unwrap_or("linux");
                    crate::staff_commands::issue_certificate::bundle_create(platform, dry)
                },
            )
        }
        [domain, verb, portal, lan_ip, rest @ ..]
            if domain == "cert" && verb == "constituent-lock" =>
        {
            cert_command("cert constituent-lock", "constituent_lock", &[], || {
                cert_print(crate::staff_commands::admit_portal::constituent_lock_json(
                    portal,
                    lan_ip,
                    rest.iter().any(|arg| arg == "--dry-run"),
                ))
            })
        }
        [domain, verb, portal, upstream, certificate, key, rest @ ..]
            if domain == "cert" && (verb == "apply-nginx" || verb == "apply") =>
        {
            cert_command("cert apply-nginx", "apply_nginx", &["cert apply"], || {
                let result = crate::staff_commands::admit_portal::apply_json(
                    portal,
                    upstream,
                    certificate,
                    key,
                    rest.iter().any(|a| a == "--dry-run"),
                );
                match result {
                    Ok(v) => {
                        println!("{v}");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                }
            })
        }
        [domain, verb, flag]
            if domain == "cert" && verb == "trust-fetch" && (flag == "--help" || flag == "-h") =>
        {
            println!("caduceus cert trust-fetch <server-ip-or-host>");
            0
        }
        [domain, verb, server] if domain == "cert" && verb == "trust-fetch" => {
            cert_command("cert trust-fetch", "trust_fetch", &[], || {
                cert_print(crate::staff_commands::install_trust::trust_fetch_json(server, "linux"))
            })
        }
        [domain, verb, bundle, rest @ ..] if domain == "cert" && verb == "trust-install" => {
            cert_command("cert trust-install", "trust_install", &[], || {
                let platform = option_value(rest, "--platform").unwrap_or("linux");
                let result = crate::staff_commands::install_trust::trust_install_json(
                    bundle,
                    platform,
                    rest.iter().any(|a| a == "--dry-run"),
                );
                match result {
                    Ok(v) => {
                        println!("{v}");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                }
            })
        }
        [domain, verb, portal, ip, upstream, rest @ ..]
            if domain == "cert" && verb == "portal-admit" =>
        {
            cert_command("cert portal-admit", "portal_admit", &[], || {
                let aliases = option_list(rest, "--aliases");
                let result = crate::staff_commands::admit_portal::portal_admit_json(
                    portal,
                    ip,
                    upstream,
                    &aliases,
                    rest.iter().any(|a| a == "--dry-run"),
                );
                match result {
                    Ok(v) => {
                        println!("{v}");
                        0
                    }
                    Err(e) => {
                        eprintln!("{e}");
                        1
                    }
                }
            })
        }
        [domain, verb] if domain == "config" && verb == "path" => {
            config_command("config path", config::path_json)
        }
        [domain, verb] if domain == "config" && verb == "show" => {
            config_command("config show", config::show_json)
        }
        [domain, verb, key] if domain == "config" && verb == "get" => {
            config_command("config get", || config::get_json(key))
        }
        [domain, verb, key, value, rest @ ..] if domain == "config" && verb == "set" => {
            match require_policy("config set", rest) {
                Ok(_) => config_print(config::set_json(key, parse_json_value(value))),
                Err(code) => code,
            }
        }
        [domain, verb, merge, rest @ ..] if domain == "config" && verb == "patch" => {
            match require_policy("config patch", rest) {
                Ok(_) => config_print(config::patch_json(parse_json_value(merge))),
                Err(code) => code,
            }
        }
        [domain, family, rest @ ..] if domain == "settings" && !rest.is_empty() => {
            let command = if rest.first().is_some_and(|verb| verb == "read") {
                settings::read_command(family)
            } else {
                settings::mutate_command(family)
            };
            match command {
                Some(command) => match policy::allows_command(&command) {
                    Ok(true) => settings::command(family, rest),
                    Ok(false) => public_action_not_allowed(),
                    Err(error) => { eprintln!("{error}"); 1 }
                },
                None => public_action_not_allowed(),
            }
        }
        [domain] if domain == "serve" => serve::run(),
        [domain, rest @ ..] if domain == "hyalos" => hyalos::command(rest),
        [domain, verb] if domain == "legacy-sbin" && verb == "list" => legacy_sbin::list(),
        [domain, verb] if domain == "homeserver-sbin" && verb == "list" => homeserver_sbin::list(),
        [domain, verb] if domain == "network" && verb == "status" => network::status(),
        [domain, rest @ ..] if domain == "child-device" && !rest.is_empty() => {
            match policy::allows_command("child-device") {
                Ok(true) => child_device::command(rest),
                Ok(false) => {
                    eprintln!("caduceus-public-action-not-allowed");
                    2
                }
                Err(error) => {
                    eprintln!("{error}");
                    1
                }
            }
        }
        [domain, object, rest @ ..]
            if domain == "network" && object == "dhcp" && !rest.is_empty() =>
        {
            let command = format!("network dhcp {}", rest.join(" "));
            match network_read::named(&command) {
                Some(read) => read_command(read),
                None => dhcp::command(rest),
            }
        }
        [domain, object, rest @ ..]
            if domain == "network" && object == "device" && !rest.is_empty() =>
        {
            let command = format!("network device {}", rest.join(" "));
            match network_read::named(&command) {
                Some(read) => read_command(read),
                None if command == "network device claim"
                    || rest.first().is_some_and(|v| v == "claim") =>
                {
                    match policy::allows_command("network device claim") {
                        Ok(true) => network_identity::command(rest),
                        Ok(false) => public_action_not_allowed(),
                        Err(error) => {
                            eprintln!("{error}");
                            1
                        }
                    }
                }
                None => public_action_not_allowed(),
            }
        }
        [domain, object, rest @ ..]
            if domain == "network" && object == "dns" && !rest.is_empty() =>
        {
            let command = format!("network dns {}", rest.join(" "));
            if let Some(read) = network_read::named(&command) {
                read_command(read)
            } else if let Some((command, target)) = dns::command_admission(rest) {
                match require_policy(command, rest) {
                    Ok(filtered) => dns::command(&filtered),
                    Err(code) => code,
                }
            } else {
                public_action_not_allowed()
            }
        }
        [domain, verb] if domain == "time" && verb == "state" => {
            time_command("time state", || crate::staff_commands::set_time::command(&["state".into()]))
        }
        [domain, verb] if domain == "time" && verb == "resolve" => {
            time_command("time resolve", || crate::staff_commands::set_time::command(&["resolve".into()]))
        }
        [domain, verb] if domain == "time" && verb == "ensure-ntp" => {
            time_command("time ensure-ntp", || crate::staff_commands::set_time::command(&["ensure-ntp".into()]))
        }
        [domain, verb, timezone] if domain == "time" && verb == "set-timezone" => {
            time_command("time set-timezone", || {
                crate::staff_commands::set_time::command(&["set-timezone".into(), timezone.clone()])
            })
        }
        [domain, verb] if domain == "pjlink" && verb == "devices" => pjlink::devices(),
        [domain, verb] if domain == "pjlink" && verb == "known-products" => {
            pjlink::known_products()
        }
        [domain, verb, device_id, rest @ ..] if domain == "pjlink" && verb == "scan" => {
            match require_policy("pjlink scan", rest) {
                Ok(filtered) => pjlink::scan_product(device_id, &filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, device_id]
            if domain == "pjlink" && object == "power" && verb == "status" =>
        {
            pjlink::power_status(device_id)
        }
        [domain, object, verb, device_id, rest @ ..]
            if domain == "pjlink" && object == "known" && verb == "add" =>
        {
            match require_policy("pjlink known add", rest) {
                Ok(filtered) => pjlink::add_known_product(device_id, &filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, entry_id, rest @ ..]
            if domain == "pjlink" && object == "known" && verb == "remove" =>
        {
            match require_policy("pjlink known remove", rest) {
                Ok(_) => pjlink::remove_known_product(entry_id),
                Err(code) => code,
            }
        }
        [domain, verb] if domain == "staff" && verb == "status" => staff::status(),
        [domain, verb] if domain == "staff" && verb == "actuators" => staff::actuators(),
        [domain, verb, method, route, rest @ ..] if domain == "staff" && verb == "intent" => {
            match require_policy("staff intent", rest) {
                Ok(_) => staff::intent(method, route),
                Err(code) => code,
            }
        }
        [domain, verb, script_id] if domain == "legacy-sbin" && verb == "show" => {
            legacy_sbin::show(script_id)
        }
        [domain, verb, script_id] if domain == "homeserver-sbin" && verb == "show" => {
            homeserver_sbin::show(script_id)
        }
        [domain, verb] if domain == "receipts" && verb == "latest" => receipts::latest(),
        [domain, verb] if domain == "update" && verb == "status" => update::status(),
        [domain, verb, rest @ ..] if domain == "update" && verb == "now" => {
            match require_policy("update now", rest) {
                Ok(filtered) => update::now(&filtered),
                Err(code) => code,
            }
        }
        [domain, verb, rest @ ..] if domain == "update" && verb == "check" => {
            match require_policy("update check", rest) {
                Ok(filtered) => update::check(&filtered),
                Err(code) => code,
            }
        }
        [domain, verb] if domain == "sync" && verb == "status" => sync::status(),
        [domain, verb, rest @ ..] if domain == "sync" && verb == "now" => {
            match require_policy("sync now", rest) {
                Ok(filtered) => sync::now(&filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, rest @ ..]
            if domain == "gui" && object == "update" && verb == "now" =>
        {
            match require_policy("gui update now", rest) {
                Ok(filtered) => gui::update_now(&filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb]
            if domain == "local-ai" && object == "runtime" && verb == "status" =>
        {
            local_ai::runtime_status()
        }
        [domain, object, verb, rest @ ..]
            if domain == "local-ai" && object == "runtime" && verb == "update" =>
        {
            match require_policy("local-ai runtime update", rest) {
                Ok(filtered) => local_ai::runtime_update(&filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, module_id, state, rest @ ..]
            if domain == "profile" && object == "module" && verb == "toggle" =>
        {
            match require_policy("profile module toggle", rest) {
                Ok(_) => profile_module::toggle(module_id, state),
                Err(code) => code,
            }
        }
        [domain, object, verb] if domain == "update" && object == "service" && verb == "status" => {
            update::service_status()
        }
        [domain, object, verb, state, rest @ ..]
            if domain == "update" && object == "service" && verb == "toggle" =>
        {
            match require_policy("update service toggle", rest) {
                Ok(filtered) => update::service_toggle(state, &filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, device_id, state, rest @ ..]
            if domain == "pjlink" && object == "power" && verb == "set" =>
        {
            match require_policy("pjlink power set", rest) {
                Ok(filtered) => pjlink::power(device_id, state, &filtered),
                Err(code) => code,
            }
        }
        _ => {
            eprintln!("caduceus-public-action-not-allowed");
            print_help();
            2
        }
    }
}

fn public_action_not_allowed() -> i32 {
    eprintln!("caduceus-public-action-not-allowed");
    2
}

fn drive_test_print(result: Result<serde_json::Value, String>) -> i32 {
    match result {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn read_command(read: &network_read::ReadCommand) -> i32 {
    match policy::allows_command(read.command) {
        Ok(true) => network_read::command(read),
        Ok(false) => public_action_not_allowed(),
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn require_policy(command: &str, rest: &[String]) -> Result<Vec<String>, i32> {
    match policy::allows_command(command) {
        Ok(true) => Ok(rest.to_vec()),
        Ok(false) => {
            eprintln!("caduceus-public-action-not-allowed");
            Err(2)
        }
        Err(_) => {
            eprintln!("caduceus-profile-missing");
            Err(1)
        }
    }
}

fn config_command<F: FnOnce() -> Result<serde_json::Value, String>>(command: &str, read: F) -> i32 {
    match policy::allows_command(command) {
        Ok(true) => config_print(read()),
        Ok(false) => {
            eprintln!("caduceus-public-action-not-allowed");
            2
        }
        Err(error) => {
            eprintln!("{error}");
            2
        }
    }
}

fn config_print(result: Result<serde_json::Value, String>) -> i32 {
    match result {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(err) => {
            eprintln!("{err}");
            1
        }
    }
}

fn parse_json_value(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|_| serde_json::Value::String(text.to_string()))
}

fn cert_command<F: FnOnce() -> i32>(
    command: &str,
    primitive: &str,
    aliases: &[&str],
    run: F,
) -> i32 {
    match cert_allowed_command(command, aliases) {
        Ok(Some(_)) => run(),
        Ok(None) => {
            println!("{}", cert_profile_refused(command, primitive));
            2
        }
        Err(error) => {
            eprintln!("{error}");
            2
        }
    }
}

fn cert_allowed_command(command: &str, aliases: &[&str]) -> Result<Option<String>, String> {
    if policy::allows_command(command)? {
        return Ok(Some(command.to_string()));
    }
    for alias in aliases {
        if policy::allows_command(alias)? {
            return Ok(Some((*alias).to_string()));
        }
    }
    Ok(None)
}

fn cert_profile_refused(command: &str, primitive: &str) -> serde_json::Value {
    let role = policy::load_profile_value()
        .ok()
        .and_then(|profile| {
            profile
                .get("profile")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());
    serde_json::json!({
        "schema": "caduceus.cert.profile_refused.v1",
        "ok": false,
        "primitive": primitive,
        "role": role,
        "refused_verb": command,
        "firstMissingSignal": "profile_refused"
    })
}

fn cert_print(result: Result<serde_json::Value, String>) -> i32 {
    match result {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn time_command<F: FnOnce() -> i32>(command: &str, run: F) -> i32 {
    match policy::allows_command(command) {
        Ok(true) => run(),
        Ok(false) => {
            eprintln!("caduceus-public-action-not-allowed");
            2
        }
        Err(error) => {
            eprintln!("{error}");
            2
        }
    }
}

fn option_value<'a>(rest: &'a [String], name: &str) -> Option<&'a str> {
    rest.iter()
        .position(|v| v == name)
        .and_then(|i| rest.get(i + 1))
        .map(String::as_str)
}

fn option_usize(rest: &[String], name: &str, default: usize) -> usize {
    option_value(rest, name)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn option_list(rest: &[String], name: &str) -> Vec<String> {
    option_value(rest, name)
        .map(|v| {
            v.split(',')
                .filter(|v| !v.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn print_help() {
    println!("caduceus 0.1.0");
    println!("public appliance-control lever");
    println!();
    println!("commands:");
    println!("  caduceus help");
    println!("  caduceus identity show");
    println!("  caduceus profile show");
    println!("  caduceus profile sources reseed");
    println!("  caduceus health");
    println!("  caduceus logs read [--offset N] [--limit N]");
    println!("  caduceus logs clear");
    println!("  caduceus disk test progress");
    println!("  caduceus disk test results");
    println!("  caduceus disk test start <device> <quick|full|ultimate> [--dry-run]");
    println!("  caduceus cert status");
    println!("  caduceus cert refresh-root");
    println!("  caduceus cert ensure-root [--dry-run] [--renewal-authority AUTHORITY]");
    println!("  caduceus cert issue-leaf [identity] [--sans h1,h2] [--ips a,b] [--dry-run]");
    println!("  caduceus cert bundle-export [platform] [--dry-run]");
    println!("  caduceus cert constituent-lock <portal> <lan-ip> [--dry-run]");
    println!("  caduceus cert apply-nginx <portal> <upstream> <certificate> <key> [--dry-run]");
    println!("  caduceus cert trust-install <bundle> [--platform linux] [--dry-run]");
    println!("  caduceus cert trust-fetch <server-ip-or-host>");
    println!(
        "  caduceus cert portal-admit <portal> <lan-ip> <upstream> [--aliases a,b] [--dry-run]"
    );
    println!("  caduceus legacy-sbin list");
    println!("  caduceus legacy-sbin show <script-id>");
    println!("  caduceus homeserver-sbin list");
    println!("  caduceus homeserver-sbin show <script-id>");
    println!("  caduceus network status");
    println!("  caduceus network dhcp status|leases|reservations list|boundary show");
    println!("  caduceus network dns status|read");
    println!("  caduceus network dns intent POST /api/dns/unbound/drop-in --metadata-json <json>");
    println!("  caduceus network dns device-name <create|remove> --hostname <name> --ip <ip>");
    println!("  caduceus network dns alias <create|remove> --label <label> --hostname <name>");
    println!("  caduceus network device list");
    println!("  caduceus network device claim --mac <mac> [--ip <ip>|--auto-ip] --hostname <name>");
    println!("  caduceus service restart coronatio");
    println!("  caduceus pjlink devices");
    println!("  caduceus pjlink scan <device-id> [--dry-run]");
    println!("  caduceus pjlink known-products");
    println!("  caduceus pjlink known add <device-id> [--dry-run] [--from-profile]");
    println!("  caduceus pjlink known remove <entry-id>");
    println!("  caduceus pjlink power status <device-id>");
    println!("  caduceus pjlink power set <device-id> <on|off> [--dry-run]");
    println!("  caduceus staff status");
    println!("  caduceus staff actuators");
    println!("  caduceus staff intent <method> <route>");
    println!("  caduceus hyalos reflect <organ> <kind> <message> [--payload JSON]");
    println!("  caduceus hyalos append <event-json>");
    println!("  caduceus hyalos tail [count] [--kind K] [--organ O] [--world W] [--correlation-id ID] [--level L] [--ok true|false]");
    println!("  caduceus sync status");
    println!("  caduceus sync now [--no-restart] [--dry-run]");
    println!("  caduceus update status");
    println!("  caduceus update now [--dry-run]");
    println!("  caduceus update check [--dry-run]");
    println!("  caduceus update service status");
    println!("  caduceus update service toggle <on|off> [--dry-run]");
    println!("  caduceus gui update now [--dry-run]");
    println!("  caduceus local-ai runtime status");
    println!("  caduceus local-ai runtime update [--dry-run]");
    println!("  caduceus profile module toggle <module-id> <on|off>");
    println!("  caduceus receipts latest");
    println!("  caduceus config path");
    println!("  caduceus config show");
    println!("  caduceus config get <dotted.path>");
    println!("  caduceus config set <dotted.path> <json-value>");
    println!("  caduceus config patch <merge-json>");
    println!("  caduceus settings <family> read");
    println!("  caduceus settings <family> mutate <fields-json>");
    println!("  caduceus serve");
}
