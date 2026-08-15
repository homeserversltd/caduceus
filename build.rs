use std::{env, fs, path::Path};

fn rust_string(value: &str) -> String {
    serde_json::to_string(value).expect("seat strings must be serializable")
}

fn main() {
    println!("cargo:rerun-if-env-changed=CADUCEUS_BUILD_SHA");
    println!("cargo:rerun-if-changed=protocol/index.json");

    let source = fs::read_to_string("protocol/index.json").expect("protocol seat must be readable");
    let seat: serde_json::Value =
        serde_json::from_str(&source).expect("protocol seat must be valid JSON");
    let schema = seat
        .get("schema")
        .and_then(serde_json::Value::as_str)
        .expect("protocol seat schema must be a string");
    let kernel_fields = seat["kernel"]["required"]
        .as_array()
        .expect("protocol seat kernel.required must be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("protocol seat kernel fields must be strings")
        })
        .collect::<Vec<_>>();
    let target_default = seat["target"]["default"]
        .as_str()
        .expect("protocol seat target.default must be a string");
    let flags_presence_gated = seat["flags"]["presence_gated"]
        .as_bool()
        .expect("protocol seat flags.presence_gated must be boolean");
    let flags_version_compared = seat["flags"]["version_compared"]
        .as_bool()
        .expect("protocol seat flags.version_compared must be boolean");

    let generated = format!("pub const SEAT_JSON: &str = {source};\n         pub const SCHEMA_ID: &str = {schema};\n         pub const KERNEL_FIELDS: &[&str] = &[{fields}];\n         pub const TARGET_DEFAULT: &str = {target_default};\n         pub const FLAGS_PRESENCE_GATED: bool = {flags_presence_gated};\n         pub const FLAGS_VERSION_COMPARED: bool = {flags_version_compared};\n", source = rust_string(source.trim()), schema = rust_string(schema), fields = kernel_fields.iter().map(|field| rust_string(field)).collect::<Vec<_>>().join(", "), target_default = rust_string(target_default));
    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set");
    fs::write(Path::new(&out_dir).join("protocol_seat.rs"), generated)
        .expect("generated protocol metadata must be writable");

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
