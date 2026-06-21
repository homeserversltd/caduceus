use crate::tools::config;

pub fn latest() -> i32 {
    match config::read_public_file("var/lib/caduceus/receipts/latest/run.txt") {
        Ok(text) => {
            println!("schema=caduceus.receipts.latest.v1");
            print!("{}", text);
            0
        }
        Err(_) => {
            println!("schema=caduceus.receipts.latest.v1");
            println!("ok=false");
            println!("first_missing_signal=caduceus-receipt-missing");
            1
        }
    }
}
