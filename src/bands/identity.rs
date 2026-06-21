use crate::tools::config;

pub fn show() -> i32 {
    match config::read_public_file("etc/caduceus/identity.json") {
        Ok(text) => {
            println!("schema=caduceus.identity.v1");
            print!("{}", text);
            0
        }
        Err(err) => {
            eprintln!("caduceus-identity-missing: {err}");
            1
        }
    }
}
