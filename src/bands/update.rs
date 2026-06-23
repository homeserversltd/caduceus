use crate::tools::{config, harmonia, receipts, systemd};

pub fn status() -> i32 {
    let profile_ok = config::read_public_file("etc/caduceus/profile.json").is_ok();
    let state = config::read_public_file("var/lib/caduceus/state.json")
        .unwrap_or_else(|_| "{}".to_string());
    let route_ok = harmonia::route("update_now").is_ok();
    println!("schema=caduceus.update.status.v1");
    println!("profile_present={profile_ok}");
    println!("state_present={}", state != "{}");
    println!("route_present={route_ok}");
    println!(
        "first_missing_signal={}",
        if profile_ok && route_ok {
            "none"
        } else if !profile_ok {
            "caduceus-profile-missing"
        } else {
            "caduceus-harmonia-route-missing:update_now"
        }
    );
    if profile_ok && route_ok {
        0
    } else {
        1
    }
}

pub fn now(rest: &[String]) -> i32 {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("update_now", &flags, dry_run);
    if !dry_run {
        let _ = receipts::write_latest(&body);
    }
    print!("{body}");
    code
}

pub fn service_status() -> i32 {
    println!("schema=caduceus.update.service.status.v1");
    println!(
        "timer_state={}",
        systemd::timer_status("arch-console-maintenance.timer")
    );
    println!("first_missing_signal=none");
    0
}

pub fn service_toggle(state: &str, rest: &[String]) -> i32 {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    match state {
        "on" | "off" => {
            let body = format!(
                "schema=caduceus.update.service.toggle.v1
mutation={}
requested_state={}
first_missing_signal=none
",
                !dry_run, state
            );
            if !dry_run {
                let _ = receipts::write_latest(&body);
            }
            print!("{body}");
            0
        }
        _ => {
            eprintln!("caduceus-public-action-not-allowed");
            2
        }
    }
}
