use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=CADUCEUS_BUILD_SHA");

    if let Ok(build_sha) = env::var("CADUCEUS_BUILD_SHA") {
        assert!(
            build_sha.len() == 40
                && build_sha
                    .bytes()
                    .all(|byte| matches!(byte, 48..=57 | 97..=102)),
            "CADUCEUS_BUILD_SHA must be 40 lowercase hexadecimal characters"
        );
        println!("cargo:rustc-env=CADUCEUS_BUILD_SHA={build_sha}");
    }
}
