use crate::tools::{harmonia, receipts};

pub fn now(rest: &[String]) -> i32 {
    let dry_run = rest.iter().any(|arg| arg == "--dry-run");
    let flags: Vec<String> = rest
        .iter()
        .filter(|arg| *arg != "--dry-run")
        .cloned()
        .collect();
    let (code, body) = harmonia::invoke("sync_now", &flags, dry_run);
    if !dry_run {
        let _ = receipts::write_latest(&body);
    }
    print!("{body}");
    code
}

pub fn status() -> i32 {
    println!("schema=caduceus.sync.status.v1");
    match harmonia::route("sync_now") {
        Ok(_) => {
            println!("route_present=true");
            println!("first_missing_signal=none");
            0
        }
        Err(err) => {
            println!("route_present=false");
            println!("first_missing_signal={err}");
            1
        }
    }
}
