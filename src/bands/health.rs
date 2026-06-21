use crate::tools::config;

pub fn show() -> i32 {
    let identity = config::read_public_file("etc/caduceus/identity.json").is_ok();
    let profile = config::read_public_file("etc/caduceus/profile.json").is_ok();
    println!("schema=caduceus.health.v1");
    println!("identity_present={identity}");
    println!("profile_present={profile}");
    println!("private_land_organs_exposed=false");
    if identity && profile {
        0
    } else {
        1
    }
}
