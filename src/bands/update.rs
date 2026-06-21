use crate::tools::{config, receipts, systemd};

pub fn status() -> i32 {
    let profile_ok = config::read_public_file("etc/caduceus/profile.json").is_ok();
    let state = config::read_public_file("var/lib/caduceus/state.json")
        .unwrap_or_else(|_| "{}".to_string());
    println!("schema=caduceus.update.status.v1");
    println!("profile_present={profile_ok}");
    println!("state_present={}", state != "{}");
    println!(
        "first_missing_signal={}",
        if profile_ok {
            "none"
        } else {
            "caduceus-profile-missing"
        }
    );
    if profile_ok {
        0
    } else {
        1
    }
}

pub fn now(rest: &[String]) -> i32 {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    if dry_run {
        println!("schema=caduceus.update.now.v1");
        println!("mutation=false");
        println!("would_invoke=harmonia-profile-command");
        println!("first_missing_signal=none");
        return 0;
    }
    let body = "schema=caduceus.update.now.v1
mutation=false
ok=false
first_missing_signal=caduceus-harmonia-command-not-yet-wired
";
    let _ = receipts::write_latest(body);
    eprint!("{body}");
    1
}

pub fn service_status() -> i32 {
    println!("schema=caduceus.update.service.status.v1");
    println!(
        "timer_state={}",
        systemd::timer_status("harmonia-profile.timer")
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
