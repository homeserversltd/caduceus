pub mod bands;
pub mod tools;

use bands::{health, help, identity, profile, receipts, serve, sync, update};

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
        [domain, verb] if domain == "receipts" && verb == "latest" => receipts::latest(),
        [domain, verb] if domain == "update" && verb == "status" => update::status(),
        [domain, verb, rest @ ..] if domain == "update" && verb == "now" => update::now(rest),
        [domain, verb, rest @ ..] if domain == "update" && verb == "check" => update::check(rest),
        [domain, verb] if domain == "sync" && verb == "status" => sync::status(),
        [domain, verb, rest @ ..] if domain == "sync" && verb == "now" => sync::now(rest),
        [domain, object, verb] if domain == "update" && object == "service" && verb == "status" => {
            update::service_status()
        }
        [domain, object, verb, state, rest @ ..]
            if domain == "update" && object == "service" && verb == "toggle" =>
        {
            update::service_toggle(state, rest)
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
    println!("  caduceus sync status");
    println!("  caduceus sync now [--no-restart] [--dry-run]");
    println!("  caduceus update status");
    println!("  caduceus update now [--dry-run]");
    println!("  caduceus update check [--dry-run]");
    println!("  caduceus update service status");
    println!("  caduceus update service toggle <on|off> [--dry-run]");
    println!("  caduceus receipts latest");
    println!("  caduceus serve");
}
