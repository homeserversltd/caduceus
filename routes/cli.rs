pub fn show() -> i32 {
    println!("caduceus 0.1.0 — Hermes public staff on this appliance");
    println!();
    println!("Operator aliases (deployable-owned shell shortcuts):");
    println!("  sync              caduceus sync now");
    println!("  sync-no-restart   caduceus sync now --no-restart");
    println!("  update            caduceus update now");
    println!("  update-check      caduceus update status");
    println!("  update-status     caduceus receipts latest");
    println!("  health            caduceus health");
    println!("  disk-census       caduceus disk census");
    println!();
    println!("Caduceus routes to Harmonia; Harmonia converges profile state.");
    println!("Private tooling remains on the land — not on the appliance.");
    0
}

#[cfg(leaf_settings_child_device)]
use crate::routes::child_device;
#[cfg(any(
    leaf_display_projector_power,
    leaf_display_projector_products,
    leaf_display_projector_scan
))]
use crate::routes::control_projector as pjlink;
#[cfg(leaf_local_ai_query)]
use crate::routes::local_ai;
#[cfg(leaf_update_module)]
use crate::routes::update_module;
#[cfg(carapace_feature_kea)]
use crate::routes::{dhcp, network_identity};
use crate::routes::{
    disk, dns, drive_test, health, help, homeserver_sbin, hyalos, identity, legacy_sbin, logs,
    network, network_read, profile, receipts, serve, source_map, staff,
};
use crate::routes::{
    sync_sources as sync, toggle_harmonia_module as profile_module, update_appliance as update,
};
use crate::shared::config;
use crate::shared::policy;
#[path = "cli_staff.rs"]
pub(crate) mod cli_staff;
#[cfg(any(
    leaf_settings_appearance,
    leaf_settings_child_device,
    leaf_settings_datetime,
    leaf_settings_default_apps,
    leaf_settings_display,
    leaf_settings_input,
    leaf_settings_notifications,
    leaf_settings_pin,
    leaf_settings_sound,
    leaf_settings_ssh
))]
use crate::shared::settings;

pub fn run<I, S>(args: I) -> i32
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args: Vec<String> = args.into_iter().map(Into::into).collect();
    if let Some(help_at) = args.iter().position(|arg| arg == "--help" || arg == "-h") {
        if help_at == 0 {
            print_help();
        } else {
            print_verb_help(&args[..help_at]);
        }
        return 0;
    }
    #[cfg(leaf_pid2)]
    if args.first().is_some_and(|v| v=="schedule") { return crate::pid2::schedule::cli(&args[1..]); }
    #[cfg(leaf_pid2)]
    if args.as_slice() == ["pid2-owner-sense"] { return crate::pid2::events::owner_sense_cli(); }
    #[cfg(leaf_pid2)]
    if args.first().is_some_and(|v| ["enable", "disable", "start", "stop", "restart", "hold", "release", "status", "list", "pid2-observe-drm"].contains(&v.as_str())) {
        return crate::pid2::cli(&args);
    }
    if let Some(namespace) = crate::routes::route_for_cli(&args) {
        let declaration_source = crate::routes::selected_declaration(namespace)
            .expect("selected CLI route must have a declaration");
        let declaration = match serde_json::from_str::<serde_json::Value>(declaration_source) {
            Ok(declaration) => declaration,
            Err(error) => {
                eprintln!("{error}");
                return 2;
            }
        };
        let serve = match declaration
            .get("serve")
            .and_then(serde_json::Value::as_array)
        {
            Some(serve) => serve,
            None => {
                eprintln!("serve");
                return 2;
            }
        };
        let prefix_len = namespace.split('/').count();
        let raw = serde_json::json!({
            "schema": crate::protocol::SCHEMA_ID,
            "intent_id": format!("cli:{namespace}"),
            "transition": crate::routes::selected_transition(namespace).unwrap_or(namespace),
            "origin_of_intent": "near",
            "payload": { "args": args[prefix_len..].to_vec() }
        });
        if let Err(signal) = crate::gate::receive(raw.clone(), serve, &declaration, false) {
            eprintln!("{signal}");
            let (noun, verb) = namespace.rsplit_once('/').unwrap_or((namespace, ""));
            let walked: Vec<&str> = namespace.split('/').collect();
            println!("{}", cli_refusal(&signal, noun, verb, &args, &walked, None, "receive", "receive", serde_json::Value::Null));
            return 2;
        }
        if namespace == "storage/nas/role/swap" && args.len()==4 {
            if let Err(code)=require_policy("storage nas role swap",&[]) { return code; }
            return cli_staff::swap();
        }
    }
    // Legacy dispatch remains below; the declaration pass is admission only.
    match args.as_slice() {
        [] => {
            print_help();
            0
        }
        [flag] if flag == "--help" || flag == "-h" => {
            print_help();
            0
        }
        [domain, profile, flag] if domain == "carapace" && flag == "--tree" => {
            crate::routes::profile_routes::show_tree(profile)
        }
        [domain] if domain == "help" => { let result = help::show(); print_help(); result },
        [domain, verb] if domain == "identity" && verb == "show" => identity::show(),
        [domain, verb] if domain == "profile" && verb == "show" => profile::show(),
        [domain, object, verb, rest @ ..]
            if domain == "profile" && object == "sources" && verb == "reseed" =>
        {
            match require_policy(source_map::public_command(), rest) {
                Ok(filtered) if filtered.is_empty() => source_map::command(),
                Ok(_) => {
                    eprintln!("caduceus-source-map-reseed-arguments-forbidden");
                    println!("{}", cli_refusal("caduceus-source-map-reseed-arguments-forbidden", "profile/sources", "reseed", &args, &["profile", "sources", "reseed"], None, "arguments", "argument-walk", serde_json::json!({"usage": "  caduceus profile sources reseed"})));
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
        [domain, object, verb]
            if domain == "storage" && object == "categories" && verb == "scan" =>
        {
            match require_policy("storage categories scan", &[]) {
                Ok(_) => crate::storage_categories::scan_command(),
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
        [domain, verb] if domain == "cert" && verb == "status" => cert_command(
            "cert status",
            "status",
            &[],
            crate::routes::issue_certificate::status,
        ),
        [domain, verb] if domain == "cert" && verb == "refresh-root" => {
            cert_command("cert refresh-root", "refresh_root", &[], || {
                cert_print(crate::routes::issue_certificate::legacy_refresh_root_json())
            })
        }
        [domain, verb, rest @ ..] if domain == "cert" && verb == "ensure-root" => {
            cert_command("cert ensure-root", "ensure_root", &[], || {
                cert_print(crate::routes::issue_certificate::ensure_root_json(
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
                match crate::routes::issue_certificate::issue_leaf_json(identity, &sans, &ips, dry)
                {
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
                crate::routes::issue_certificate::bundle_create(platform, dry)
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
                    crate::routes::issue_certificate::bundle_create(platform, dry)
                },
            )
        }
        #[cfg(leaf_portals_admit)]
        [domain, verb, portal, lan_ip, rest @ ..]
            if domain == "cert" && verb == "constituent-lock" =>
        {
            cert_command("cert constituent-lock", "constituent_lock", &[], || {
                cert_print(crate::routes::admit_portal::constituent_lock_json(
                    portal,
                    lan_ip,
                    rest.iter().any(|arg| arg == "--dry-run"),
                ))
            })
        }
        #[cfg(leaf_portals_admit)]
        [domain, verb, portal, upstream, certificate, key, rest @ ..]
            if domain == "cert" && (verb == "apply-nginx" || verb == "apply") =>
        {
            cert_command("cert apply-nginx", "apply_nginx", &["cert apply"], || {
                let result = crate::routes::admit_portal::apply_json(
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
            println!("caduceus cert trust-fetch <server-ip-or-host> [--renew]");
            0
        }
        [domain, verb, server, rest @ ..] if domain == "cert" && verb == "trust-fetch" => {
            cert_command(
                "cert trust-fetch",
                "trust_fetch",
                &["cert trust-install"],
                || {
                    if rest.iter().any(|arg| arg != "--renew") {
                        return cert_print(Err(
                            "caduceus-cert-trust-fetch-option-invalid".to_string()
                        ));
                    }
                    cert_print(crate::routes::install_trust::trust_fetch_json(
                        server,
                        "linux",
                        rest.iter().any(|arg| arg == "--renew"),
                    ))
                },
            )
        }
        [domain, verb, bundle, rest @ ..] if domain == "cert" && verb == "trust-install" => {
            cert_command("cert trust-install", "trust_install", &[], || {
                let platform = option_value(rest, "--platform").unwrap_or("linux");
                let result = crate::routes::install_trust::trust_install_json(
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
        #[cfg(leaf_portals_admit)]
        [domain, verb, rest @ ..] if domain == "cert" && verb == "portal-retire" => {
            cert_command("cert portal-retire", "portal_retire", &[], || {
                let positional: Vec<_> = rest.iter().filter(|arg| arg.as_str() != "--dry-run").collect();
                if positional.len() != 2 || rest.iter().any(|arg| arg.starts_with("--") && arg != "--dry-run") {
                    eprintln!("agathodaimon-house-ca-refused");
                    let stopped_at = if positional.len() != 2 { "positional-count" } else { "flag" };
                    println!("{}", cli_refusal("agathodaimon-house-ca-refused", "cert", "portal-retire", &args, &["cert", "portal-retire"], None, stopped_at, "flag-walk", serde_json::json!({"usage": "  caduceus cert portal-retire [--dry-run] <portal> <owner-mac>"})));
                    return 1;
                }
                match crate::routes::issue_certificate::portal_retire_receipt(positional[0], positional[1], rest.iter().any(|arg| arg == "--dry-run"), None) {
                    Ok(value) => { println!("{value}"); 0 },
                    Err(value) => { eprintln!("{value}"); 1 },
                }
            })
        }
        #[cfg(leaf_portals_admit)]
        [domain, verb, portal, ip, args @ ..]
            if domain == "cert" && verb == "portal-admit" =>
        {
            cert_command("cert portal-admit", "portal_admit", &[], || {
                let (upstream, rest) = match args.split_first() {
                    Some((word, rest)) if !word.starts_with("--") => (Some(word.as_str()), rest),
                    _ => (None, args),
                };
                let (mut aliases_arg, mut owner_mac, mut origin, mut claim_arg) = (None, None, None, None);
                let (mut tailnet_port, mut locations, mut dry_run) = (None, None, false);
                let (mut max_body_size, mut read_timeout) = (None, None);
                let mut forwarded = serde_json::Map::new();
                let mut i = 0;
                while i < rest.len() {
                    let name = rest[i].as_str();
                    if name == "--dry-run" {
                        dry_run = true;
                        i += 1;
                        continue;
                    }
                    let slot = match name {
                        "--aliases" => &mut aliases_arg,
                        "--owner-mac" => &mut owner_mac,
                        "--origin" => &mut origin,
                        "--claim-tiles" => &mut claim_arg,
                        "--tailnet-port" => &mut tailnet_port,
                        "--locations" => &mut locations,
                        "--max-body-size" => &mut max_body_size,
                        "--read-timeout" => &mut read_timeout,
                        _ => {
                            let Some(key) = name.strip_prefix("--").filter(|key| !key.is_empty()) else {
                                println!("{}", portal_admit_refusal(portal, ip, args, usize::from(upstream.is_some()) + i, if name == "--" { "empty-flag" } else { "unplaced-word" }));
                                return 1;
                            };
                            if matches!(key, "portal" | "lan-ip" | "upstream") {
                                println!("{}", portal_admit_refusal(portal, ip, args, usize::from(upstream.is_some()) + i, "reserved-flag"));
                                return 1;
                            }
                            let value = match rest.get(i + 1) {
                                Some(next) if !next.starts_with("--") => {
                                    i += 1;
                                    serde_json::Value::String(next.clone())
                                }
                                _ => serde_json::Value::Bool(true),
                            };
                            match forwarded.entry(key.to_owned()) {
                                serde_json::map::Entry::Vacant(entry) => { entry.insert(value); }
                                serde_json::map::Entry::Occupied(mut entry) => {
                                    if let serde_json::Value::Array(values) = entry.get_mut() {
                                        values.push(value);
                                    } else {
                                        let first = entry.get().clone();
                                        entry.insert(serde_json::Value::Array(vec![first, value]));
                                    }
                                }
                            }
                            i += 1;
                            continue;
                        }
                    };
                    let Some(value) = rest.get(i + 1) else {
                        println!("{}", portal_admit_refusal(portal, ip, args, usize::from(upstream.is_some()) + i, "flag-without-value"));
                        return 1;
                    };
                    slot.get_or_insert(value.as_str());
                    i += 2;
                }
                let list = |arg: Option<&str>| -> Vec<String> {
                    arg.unwrap_or("").split(',').filter(|item| !item.is_empty()).map(str::to_string).collect()
                };
                let aliases = list(aliases_arg);
                let claim_tiles = list(claim_arg);
                let owner = owner_mac.zip(origin);
                let result = crate::routes::issue_certificate::portal_admit_cli_receipt(
                    portal, ip, upstream, &aliases, owner, &claim_tiles, dry_run, tailnet_port, locations,
                    max_body_size, read_timeout, forwarded,
                );
                match result {
                    Ok(value) => { println!("{value}"); 0 }
                    Err(value) => { println!("{value}"); 1 }
                }
            })
        }
        [domain, verb] if domain == "config" && verb == "path" => {
            config_command("config path", config::path_json)
        }
        [domain, verb] if domain == "config" && verb == "show" => {
            config_command("config show", config::show_public_json)
        }
        [domain, verb, key] if domain == "config" && verb == "get" => {
            config_command("config get", || config::get_public_json(key))
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
        #[cfg(any(
            leaf_settings_appearance,
            leaf_settings_child_device,
            leaf_settings_datetime,
            leaf_settings_default_apps,
            leaf_settings_display,
            leaf_settings_input,
            leaf_settings_notifications,
            leaf_settings_pin,
            leaf_settings_sound,
            leaf_settings_ssh
        ))]
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
                    Err(error) => {
                        eprintln!("{error}");
                        1
                    }
                },
                None => public_action_not_allowed(),
            }
        }
        [domain] if domain == "serve" => serve::run(),
        [domain, rest @ ..] if domain == "hyalos" => hyalos::command(rest),
        [domain, verb] if domain == "legacy-sbin" && verb == "list" => legacy_sbin::list(),
        [domain, verb] if domain == "homeserver-sbin" && verb == "list" => homeserver_sbin::list(),
        [domain, verb] if domain == "network" && verb == "status" => network::status(),
        #[cfg(leaf_settings_child_device)]
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
                None => {
                    #[cfg(carapace_feature_kea)]
                    {
                        dhcp::command(rest)
                    }
                    #[cfg(not(carapace_feature_kea))]
                    {
                        public_action_not_allowed()
                    }
                }
            }
        }
        [domain, object, rest @ ..]
            if domain == "network" && object == "device" && !rest.is_empty() =>
        {
            let command = format!("network device {}", rest.join(" "));
            match network_read::named(&command) {
                Some(read) => read_command(read),
                #[cfg(carapace_feature_kea)]
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
        #[cfg(leaf_time)]
        [domain, verb] if domain == "time" && verb == "state" => time_command("time state", || {
            crate::routes::set_time::command(&["state".into()])
        }),
        #[cfg(leaf_time)]
        [domain, verb] if domain == "time" && verb == "resolve" => {
            time_command("time resolve", || {
                crate::routes::set_time::command(&["resolve".into()])
            })
        }
        #[cfg(leaf_time)]
        [domain, verb] if domain == "time" && verb == "ensure-ntp" => {
            time_command("time ensure-ntp", || {
                crate::routes::set_time::command(&["ensure-ntp".into()])
            })
        }
        #[cfg(leaf_time)]
        [domain, verb, timezone] if domain == "time" && verb == "set-timezone" => {
            time_command("time set-timezone", || {
                crate::routes::set_time::command(&["set-timezone".into(), timezone.clone()])
            })
        }
        #[cfg(any(
            leaf_display_projector_power,
            leaf_display_projector_products,
            leaf_display_projector_scan
        ))]
        [domain, verb] if domain == "pjlink" && verb == "devices" => pjlink::devices(),
        #[cfg(any(
            leaf_display_projector_power,
            leaf_display_projector_products,
            leaf_display_projector_scan
        ))]
        [domain, object, verb] if domain == "pjlink" && object == "catalog" && verb == "import" => {
            match require_policy("pjlink catalog import", &[]) {
                Ok(_) => pjlink::import_known_catalog(),
                Err(code) => code,
            }
        }
        #[cfg(any(
            leaf_display_projector_power,
            leaf_display_projector_products,
            leaf_display_projector_scan
        ))]
        [domain, verb] if domain == "pjlink" && verb == "known-products" => {
            pjlink::known_products()
        }
        #[cfg(any(
            leaf_display_projector_power,
            leaf_display_projector_products,
            leaf_display_projector_scan
        ))]
        [domain, verb, device_id, rest @ ..] if domain == "pjlink" && verb == "scan" => {
            match require_policy("pjlink scan", rest) {
                Ok(filtered) => pjlink::scan_product(device_id, &filtered),
                Err(code) => code,
            }
        }
        #[cfg(any(
            leaf_display_projector_power,
            leaf_display_projector_products,
            leaf_display_projector_scan
        ))]
        [domain, object, verb, device_id]
            if domain == "pjlink" && object == "power" && verb == "status" =>
        {
            pjlink::power_status(device_id)
        }
        #[cfg(any(
            leaf_display_projector_power,
            leaf_display_projector_products,
            leaf_display_projector_scan
        ))]
        [domain, object, verb, device_id, rest @ ..]
            if domain == "pjlink" && object == "known" && verb == "add" =>
        {
            match require_policy("pjlink known add", rest) {
                Ok(filtered) => pjlink::add_known_product(device_id, &filtered),
                Err(code) => code,
            }
        }
        #[cfg(any(
            leaf_display_projector_power,
            leaf_display_projector_products,
            leaf_display_projector_scan
        ))]
        [domain, object, verb, entry_id, rest @ ..]
            if domain == "pjlink" && object == "known" && verb == "remove" =>
        {
            match require_policy("pjlink known remove", rest) {
                Ok(_) => pjlink::remove_known_product(entry_id),
                Err(code) => code,
            }
        }
        [domain, verb] if domain == "staff" && verb == "status" => staff::status(),
        [domain, verb] if domain == "staff" && verb == "actuators" => {
            match crate::crossings::raw() {
                Ok(raw) => {
                    print!("{raw}");
                    0
                }
                Err(err) => {
                    eprintln!("{err}");
                    1
                }
            }
        }
        [domain, verb] if domain == "staff" && verb == "crossings" => staff::crossings(),
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
        #[cfg(leaf_update_module)]
        [domain, verb, rest @ ..] if domain == "update" && verb == "module" => {
            match require_policy("update module", rest) {
                Ok(filtered) => update_module::cli(&filtered),
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
        #[cfg(leaf_local_ai_query)]
        [domain, object, verb]
            if domain == "local-ai" && object == "runtime" && verb == "status" =>
        {
            local_ai::runtime_status()
        }
        #[cfg(leaf_local_ai_query)]
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
            match require_policy("update service status", &[]) {
                Ok(_) => update::service_status(),
                Err(code) => code,
            }
        }
        [domain, object, verb, state, rest @ ..]
            if domain == "update" && object == "service" && verb == "toggle" =>
        {
            match require_policy("update service toggle", rest) {
                Ok(filtered) => update::service_toggle(state, &filtered),
                Err(code) => code,
            }
        }
        #[cfg(any(
            leaf_display_projector_power,
            leaf_display_projector_products,
            leaf_display_projector_scan
        ))]
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
            let unplaced = args.iter().position(|word| !word.starts_with("--"));
            println!("{}", cli_refusal("caduceus-public-action-not-allowed", "cli", "front-door", &args, &[], unplaced, "walk", "walk", serde_json::json!({"help": "caduceus help", "children": null, "nearest": null})));
            2
        }
    }
}

fn cli_refusal(signal: &str, noun: &str, verb: &str, args: &[String], walked: &[&str], unplaced: Option<usize>, stopped_at: &str, step: &str, could_change_to: serde_json::Value) -> serde_json::Value {
    let words: Vec<&str> = args.iter().enumerate().map(|(index, word)| {
        if let Some(segment) = walked.get(index) { *segment }
        else if word.starts_with("--") { "<not-a-option>" }
        else if unplaced == Some(index) { "<not-a-noun>" }
        else { "<not-a-value>" }
    }).collect();
    serde_json::json!({
        "schema": "caduceus.staff.receipt.v1", "ok": false,
        "firstMissingSignal": signal, "doorSignal": signal, "mutationPerformed": false,
        "stop": {"noun": noun, "verb": verb},
        "observed": {"words": words, "walked": walked, "stopped_at": stopped_at},
        "could_change_to": could_change_to,
        "attempt": {"attempted": false, "step": step},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    })
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
            eprintln!("caduceus-carapace-desync");
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

#[cfg(leaf_portals_admit)]
fn portal_admit_refusal(portal: &str, ip: &str, args: &[String], stop_in_args: usize, reason: &str) -> serde_json::Value {
    let children = ["--aliases", "--owner-mac", "--origin", "--claim-tiles", "--tailnet-port", "--locations", "--max-body-size", "--read-timeout", "--dry-run"];
    let full_args: Vec<&str> = ["cert", "portal-admit", portal, ip].into_iter().chain(args.iter().map(String::as_str)).collect();
    let stop_at = 4 + stop_in_args;
    let words: Vec<&str> = full_args.iter().enumerate().map(|(index, word)| {
        if index == 0 { "cert" }
        else if index == 1 { "portal-admit" }
        else if word.starts_with("--") { "<not-a-option>" }
        else if index == stop_at && reason == "unplaced-word" { "<not-a-noun>" }
        else { "<not-a-value>" }
    }).collect();

    // Normalized Levenshtein similarity; only a declared child can be returned.
    let word: Vec<char> = full_args[stop_at].chars().collect();
    let mut nearest = None;
    let mut best = 0.6_f64;
    for child in children {
        let chars: Vec<char> = child.chars().collect();
        let longest = word.len().max(chars.len());
        if longest == 0 || (word.len().abs_diff(chars.len()) as f64 / longest as f64) > 0.4 { continue; }
        let mut row: Vec<usize> = (0..=chars.len()).collect();
        for (i, a) in word.iter().enumerate() {
            let mut diagonal = row[0];
            row[0] = i + 1;
            for (j, b) in chars.iter().enumerate() {
                let above = row[j + 1];
                row[j + 1] = (above + 1).min(row[j] + 1).min(diagonal + usize::from(a != b));
                diagonal = above;
            }
        }
        let score = 1.0 - row[chars.len()] as f64 / longest as f64;
        if score >= 0.6 && (nearest.is_none() || score > best) { nearest = Some(child); best = score; }
    }
    let signal = "agathodaimon-house-ca-refused";
    serde_json::json!({
        "schema": "caduceus.staff.receipt.v1", "ok": false,
        "firstMissingSignal": signal, "mutationPerformed": false,
        "stop": {"noun": "cert", "verb": "portal-admit"},
        "observed": {"words": words, "walked": ["cert", "portal-admit"], "stopped_at": reason},
        "could_change_to": {"children": children, "nearest": nearest, "payload_fields": {
            "--aliases": "Comma-separated aliases",
            "--owner-mac": "Owner MAC, sent only with --origin",
            "--origin": "Origin, sent only with --owner-mac",
            "--claim-tiles": "Comma-separated tiles, sent only with owner MAC and origin",
            "--tailnet-port": "Tailnet port value",
            "--locations": "Locations value",
            "--max-body-size": "Maximum body size value",
            "--read-timeout": "Read timeout value",
            "--dry-run": "Boolean: make the act a dry run"
        }},
        "attempt": {"attempted": false, "step": "flag-walk"},
        "final_receipt": {"ok": false, "firstMissingSignal": signal}
    })
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
    print_usage(None);
}

fn print_verb_help(args: &[String]) {
    let mut canonical = args.to_vec();
    if canonical.first().is_some_and(|arg| arg == "cert") {
        if canonical.get(1).is_some_and(|arg| arg == "apply") {
            canonical[1] = "apply-nginx".into();
        } else if canonical.get(1).is_some_and(|arg| arg == "bundle")
            && canonical.get(2).is_some_and(|arg| arg == "create")
        {
            canonical.splice(1..3, ["bundle-export".into()]);
        }
    }
    print_usage(Some(&canonical));
}

fn print_usage(args: Option<&[String]>) {
    let mut best: Option<(usize, &str)> = None;
    macro_rules! println {
        ($line:literal) => {{
            if let Some(args) = args {
                if let Some(usage) = $line.trim_start().strip_prefix("caduceus ") {
                    let mut matched = 0;
                    let mut complete = true;
                    for (index, word) in usage.split_whitespace().enumerate() {
                        if word.starts_with('[') || word.starts_with("--") {
                            break;
                        }
                        if word.starts_with('<') && word.ends_with('>')
                            && !word.contains('|') && word != "<family>" {
                            break;
                        }
                        let Some(arg) = args.get(index) else { complete = false; break };
                        if word.starts_with('<') && word.ends_with('>') {
                            let inner = &word[1..word.len() - 1];
                            if inner.contains('|') && !inner.split('|').any(|choice| choice == arg) {
                                complete = false;
                                break;
                            }
                        } else if !word.split('|').any(|choice| choice == arg) {
                            complete = false;
                            break;
                        }
                        matched += 1;
                    }
                    if complete && matched > 0 && best.map_or(true, |(n, _)| matched > n) {
                        best = Some((matched, $line));
                    }
                }
            } else {
                std::println!($line);
            }
        }};
        () => {{ if args.is_none() { std::println!(); } }};
    }
    println!("caduceus 0.1.0");
    println!("public appliance-control lever");
    println!();
    println!("commands:");
    println!("  caduceus help");
    #[cfg(leaf_pid2)]
    {
        println!("  caduceus schedule list|status|enable|disable|update|run|register");
        println!("  caduceus enable < routine-envelope-on-stdin");
        println!("  caduceus disable <routine-id>");
        println!("  caduceus hold|release <routine-id>");
        println!("  caduceus start|stop|restart <unit>");
        println!("  caduceus status <routine-id-or-unit>");
        println!("  caduceus list");
    }
    println!("  caduceus carapace <profile> --tree");
    println!("  caduceus identity show");
    println!("  caduceus profile show");
    println!("  caduceus profile sources reseed");
    println!("  caduceus health");
    println!("  caduceus logs read [--offset N] [--limit N]");
    println!("  caduceus storage categories scan");
    println!("  caduceus disk census");
    println!("  caduceus time state");
    println!("  caduceus time resolve");
    println!("  caduceus time ensure-ntp");
    println!("  caduceus time set-timezone <timezone>");
    println!("  caduceus child-device <command> [arguments]");
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
    println!("  caduceus cert trust-fetch <server-ip-or-host> [--renew]");
    println!(
        "  caduceus cert portal-admit <portal> <lan-ip> [<upstream>] [options] (templates and notes: GET /api/v1/schema/hestia.portal.v1)"
    );
    println!("  caduceus cert portal-retire [--dry-run] <portal> <owner-mac>");
    println!("  caduceus legacy-sbin list");
    println!("  caduceus legacy-sbin show <script-id>");
    println!("  caduceus homeserver-sbin list");
    println!("  caduceus homeserver-sbin show <script-id>");
    println!("  caduceus network status");
    println!("  caduceus network dhcp status");
    println!("  caduceus network dhcp leases");
    println!("  caduceus network dhcp reservations list");
    println!("  caduceus network dhcp boundary show");
    println!("  caduceus network dhcp statistics");
    println!("  caduceus network dhcp health");
    println!("  caduceus network dns status|read");
    println!("  caduceus network dns resolver status");
    println!("  caduceus network dns intent POST /api/dns/unbound/drop-in --metadata-json <json>");
    println!("  caduceus network dns device-name <create|remove> --hostname <name> --ip <ip>");
    println!("  caduceus network dns alias <create|remove> --label <label> --hostname <name>");
    println!("  caduceus network device list");
    println!("  caduceus network device claim --mac <mac> [--ip <ip>|--auto-ip] --hostname <name>");
    println!("  caduceus service restart coronatio");
    println!("  caduceus pjlink devices");
    println!("  caduceus pjlink scan <device-id> [--dry-run]");
    println!("  caduceus pjlink known-products");
    println!("  caduceus pjlink catalog import");
    println!("  caduceus pjlink known add <device-id> [--dry-run] [--from-profile]");
    println!("  caduceus pjlink known remove <entry-id>");
    println!("  caduceus pjlink power status <device-id>");
    println!("  caduceus pjlink power set <device-id> <on|off> [--dry-run]");
    println!("  caduceus staff status");
    println!("  caduceus staff actuators");
    println!("  caduceus staff crossings");
    println!("  caduceus staff intent <method> <route>");
    println!("  caduceus hyalos reflect <organ> <kind> <message> [--payload JSON]");
    println!("  caduceus hyalos append <event-json>");
    println!("  caduceus hyalos tail [count] [--kind K] [--organ O] [--world W] [--correlation-id ID] [--level L] [--ok true|false]");
    println!("  caduceus sync status");
    println!("  caduceus sync now [--no-restart] [--dry-run]");
    println!("  caduceus update status");
    println!("  caduceus update now [--dry-run]");
    println!("  caduceus update module <module-id> [--apply]");
    println!("  caduceus update check [--dry-run]");
    println!("  caduceus update service status");
    println!("  caduceus update service toggle <on|off> [--dry-run]");
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
    if let Some(args) = args {
        if let Some((_, usage)) = best {
            std::println!("{}", usage.trim_start());
        } else {
            std::println!("Usage is not listed for this command; run caduceus --help.");
        }
    }
}
