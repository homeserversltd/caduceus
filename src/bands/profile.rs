use crate::tools::config;

pub fn show() -> i32 {
    match config::read_public_file("etc/caduceus/profile.json") {
        Ok(text) => {
            println!("schema=caduceus.profile.v1");
            print!("{}", text);
            0
        }
        Err(err) => {
            eprintln!("caduceus-profile-missing: {err}");
            1
        }
    }
}
