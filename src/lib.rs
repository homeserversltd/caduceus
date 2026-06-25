pub mod bands;
pub mod tools;

use bands::{
    gui, health, help, homeserver_sbin, identity, legacy_sbin, local_ai, network, pjlink, profile,
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
        [domain] if domain == "serve" => serve::run(),
        [domain, verb] if domain == "legacy-sbin" && verb == "list" => legacy_sbin::list(),
        [domain, verb] if domain == "homeserver-sbin" && verb == "list" => homeserver_sbin::list(),
        [domain, verb] if domain == "network" && verb == "status" => network::status(),
        [domain, verb] if domain == "pjlink" && verb == "devices" => pjlink::devices(),
        [domain, object, verb, device_id]
            if domain == "pjlink" && object == "power" && verb == "status" =>
        {
            pjlink::power_status(device_id)
        }
        [domain, verb] if domain == "staff" && verb == "status" => staff::status(),
        [domain, verb] if domain == "staff" && verb == "actuators" => staff::actuators(),
        [domain, verb, script_id] if domain == "legacy-sbin" && verb == "show" => {
            legacy_sbin::show(script_id)
        }
        [domain, verb, script_id] if domain == "homeserver-sbin" && verb == "show" => {
            homeserver_sbin::show(script_id)
        }
        [domain, verb] if domain == "receipts" && verb == "latest" => receipts::latest(),
        [domain, verb] if domain == "update" && verb == "status" => update::status(),
        [domain, verb, rest @ ..] if domain == "update" && verb == "now" => update::now(rest),
        [domain, verb, rest @ ..] if domain == "update" && verb == "check" => update::check(rest),
        [domain, verb] if domain == "sync" && verb == "status" => sync::status(),
        [domain, verb, rest @ ..] if domain == "sync" && verb == "now" => sync::now(rest),
        [domain, object, verb, rest @ ..]
            if domain == "gui" && object == "update" && verb == "now" =>
        {
            gui::update_now(rest)
        }
        [domain, object, verb]
            if domain == "local-ai" && object == "runtime" && verb == "status" =>
        {
            local_ai::runtime_status()
        }
        [domain, object, verb, rest @ ..]
            if domain == "local-ai" && object == "runtime" && verb == "update" =>
        {
            local_ai::runtime_update(rest)
        }
        [domain, object, verb, module_id, state]
            if domain == "profile" && object == "module" && verb == "toggle" =>
        {
            profile_module::toggle(module_id, state)
        }
        [domain, object, verb] if domain == "update" && object == "service" && verb == "status" => {
            update::service_status()
        }
        [domain, object, verb, state, rest @ ..]
            if domain == "update" && object == "service" && verb == "toggle" =>
        {
            update::service_toggle(state, rest)
        }
        [domain, object, verb, device_id, state, rest @ ..]
            if domain == "pjlink" && object == "power" && verb == "set" =>
        {
            pjlink::power(device_id, state, rest)
        }
        _ => {
            eprintln!("caduceus-public-action-not-allowed");
            print_help();
            2
        }
    }
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
    println!("  caduceus legacy-sbin list");
    println!("  caduceus legacy-sbin show <script-id>");
    println!("  caduceus homeserver-sbin list");
    println!("  caduceus homeserver-sbin show <script-id>");
    println!("  caduceus network status");
    println!("  caduceus pjlink devices");
    println!("  caduceus pjlink power status <device-id>");
    println!("  caduceus pjlink power set <device-id> <on|off> [--dry-run]");
    println!("  caduceus staff status");
    println!("  caduceus staff actuators");
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
