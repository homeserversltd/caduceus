pub mod bands;
pub mod tools;

use crate::tools::policy;
use bands::{
    cert, gui, health, help, homeserver_sbin, identity, legacy_sbin, local_ai, network, pjlink, profile,
    profile_module, receipts, serve, staff, sync, update,
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
        [domain] if domain == "health" => health::show(),
        [domain, verb] if domain == "cert" && verb == "status" => cert::status(),
        [domain, verb, rest @ ..] if domain == "cert" && verb == "issue-leaf" => {
            let dry = rest.iter().any(|a| a == "--dry-run");
            let mut sans = Vec::new();
            let mut i = 0;
            while i < rest.len() {
                if rest[i] == "--sans" && i + 1 < rest.len() {
                    sans.extend(rest[i + 1].split(',').filter(|s| !s.is_empty()).map(str::to_string));
                    i += 2;
                    continue;
                }
                i += 1;
            }
            cert::issue_leaf(&sans, dry)
        }
        [domain, verb, rest @ ..] if domain == "cert" && verb == "rotate-ca" => {
            let dry = rest.iter().any(|a| a == "--dry-run");
            let understood = rest.iter().any(|a| a == "--i-understand-clients-reinstall");
            cert::rotate_ca(dry, understood)
        }
        [domain, object, verb, rest @ ..]
            if domain == "cert" && object == "bundle" && verb == "create" =>
        {
            let dry = rest.iter().any(|a| a == "--dry-run");
            let platform = rest
                .iter()
                .find(|a| !a.starts_with('-'))
                .map(String::as_str)
                .unwrap_or("linux");
            cert::bundle_create(platform, dry)
        }
        [domain] if domain == "serve" => serve::run(),
        [domain, verb] if domain == "legacy-sbin" && verb == "list" => legacy_sbin::list(),
        [domain, verb] if domain == "homeserver-sbin" && verb == "list" => homeserver_sbin::list(),
        [domain, verb] if domain == "network" && verb == "status" => network::status(),
        [domain, verb] if domain == "pjlink" && verb == "devices" => pjlink::devices(),
        [domain, verb] if domain == "pjlink" && verb == "known-products" => {
            pjlink::known_products()
        }
        [domain, verb, device_id, rest @ ..] if domain == "pjlink" && verb == "scan" => {
            match require_capability("pjlink scan", device_id, rest) {
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
            match require_capability("pjlink known add", device_id, rest) {
                Ok(filtered) => pjlink::add_known_product(device_id, &filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, entry_id, rest @ ..]
            if domain == "pjlink" && object == "known" && verb == "remove" =>
        {
            match require_capability("pjlink known remove", entry_id, rest) {
                Ok(_) => pjlink::remove_known_product(entry_id),
                Err(code) => code,
            }
        }
        [domain, verb] if domain == "staff" && verb == "status" => staff::status(),
        [domain, verb] if domain == "staff" && verb == "actuators" => staff::actuators(),
        [domain, verb, method, route, rest @ ..] if domain == "staff" && verb == "intent" => {
            match require_capability("staff intent", route, rest) {
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
            match require_capability("update now", "local", rest) {
                Ok(filtered) => update::now(&filtered),
                Err(code) => code,
            }
        }
        [domain, verb, rest @ ..] if domain == "update" && verb == "check" => {
            match require_capability("update check", "local", rest) {
                Ok(filtered) => update::check(&filtered),
                Err(code) => code,
            }
        }
        [domain, verb] if domain == "sync" && verb == "status" => sync::status(),
        [domain, verb, rest @ ..] if domain == "sync" && verb == "now" => {
            match require_capability("sync now", "local", rest) {
                Ok(filtered) => sync::now(&filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, rest @ ..]
            if domain == "gui" && object == "update" && verb == "now" =>
        {
            match require_capability("gui update now", "local", rest) {
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
            match require_capability("local-ai runtime update", "local", rest) {
                Ok(filtered) => local_ai::runtime_update(&filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, module_id, state, rest @ ..]
            if domain == "profile" && object == "module" && verb == "toggle" =>
        {
            match require_capability("profile module toggle", module_id, rest) {
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
            match require_capability("update service toggle", state, rest) {
                Ok(filtered) => update::service_toggle(state, &filtered),
                Err(code) => code,
            }
        }
        [domain, object, verb, device_id, state, rest @ ..]
            if domain == "pjlink" && object == "power" && verb == "set" =>
        {
            match require_capability("pjlink power set", device_id, rest) {
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

fn require_capability(command: &str, target: &str, rest: &[String]) -> Result<Vec<String>, i32> {
    match policy::allows_command(command) {
        Ok(true) => {}
        Ok(false) => {
            eprintln!("caduceus-public-action-not-allowed");
            return Err(2);
        }
        Err(_) => {
            eprintln!("caduceus-profile-missing");
            return Err(1);
        }
    }
    let token = capability_arg(rest);
    if let Err(reason) = policy::capability_admits(command, target, token) {
        eprintln!("{}", reason.signal());
        return Err(2);
    }
    Ok(rest_without_capability(rest))
}

fn capability_arg(rest: &[String]) -> Option<&str> {
    let mut index = 0;
    while index < rest.len() {
        let arg = rest[index].as_str();
        if arg == "--capability" {
            return rest.get(index + 1).map(String::as_str);
        }
        if let Some(value) = arg.strip_prefix("--capability=") {
            return Some(value);
        }
        index += 1;
    }
    None
}

fn rest_without_capability(rest: &[String]) -> Vec<String> {
    let mut filtered = Vec::new();
    let mut index = 0;
    while index < rest.len() {
        let arg = &rest[index];
        if arg == "--capability" {
            index += 2;
            continue;
        }
        if arg.starts_with("--capability=") {
            index += 1;
            continue;
        }
        filtered.push(arg.clone());
        index += 1;
    }
    filtered
}

fn print_help() {
    println!("caduceus 0.1.0");
    println!("public appliance-control lever");
    println!();
    println!("commands:");
    println!("  caduceus help");
    println!("  caduceus identity show");
    println!("  caduceus profile show");
    println!("  caduceus health");
    println!("  caduceus cert status");
    println!("  caduceus cert issue-leaf [--sans h1,h2] [--dry-run]");
    println!("  caduceus cert rotate-ca --i-understand-clients-reinstall [--dry-run]");
    println!("  caduceus cert bundle create [platform] [--dry-run]");
    println!("  caduceus legacy-sbin list");
    println!("  caduceus legacy-sbin show <script-id>");
    println!("  caduceus homeserver-sbin list");
    println!("  caduceus homeserver-sbin show <script-id>");
    println!("  caduceus network status");
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
    println!("  caduceus serve");
}
