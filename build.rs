use std::{env, fs, path::Path};

fn rust_string(value: &str) -> String {
    serde_json::to_string(value).expect("seat strings must be serializable")
}

fn module_ident(namespace: &str) -> String {
    let mut ident = String::from("leaf_");
    for byte in namespace.bytes() {
        match byte {
            97..=122 | 65..=90 | 48..=57 => ident.push(byte as char),
            47 | 45 => ident.push(char::from(95)),
            58 => ident.push_str("_colon_"),
            _ => ident.push_str(&format!("_x{byte:02x}_")),
        }
    }
    ident
}

fn walk_json_leaves(root: &Path) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(root) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(walk_json_leaves(&path));
        } else if path.file_name().and_then(|n| n.to_str()) == Some("index.json") {
            if let Some(value) = fs::read_to_string(&path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
            {
                out.push(value);
            }
        }
    }
    out
}

fn yaml_for_profile(profile: &str) -> Vec<String> {
    let text = fs::read_to_string(format!("profiles/{profile}/index.yaml"))
        .expect("selected profile index readable");
    let value: serde_yaml::Value =
        serde_yaml::from_str(&text).expect("selected profile index valid YAML");
    value
        .get("routes")
        .and_then(serde_yaml::Value::as_sequence)
        .expect("selected profile routes list present")
        .iter()
        .filter_map(serde_yaml::Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn shelf_band_is_indexed(sbin: &Path, wanted: &str) -> bool {
    let root = sbin.join("agathodaimon");
    let read = |path: &Path| -> Option<serde_json::Value> {
        serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
    };
    fn walk(
        dir: &Path,
        prefix: &str,
        wanted: &str,
        read: &dyn Fn(&Path) -> Option<serde_json::Value>,
    ) -> bool {
        let Some(index) = read(&dir.join("index.json")) else {
            return false;
        };
        let Some(children) = index
            .get("children")
            .or_else(|| index.get("entries"))
            .and_then(serde_json::Value::as_array)
        else {
            return false;
        };
        for child in children {
            let name = match child {
                serde_json::Value::String(s) => s.as_str(),
                serde_json::Value::Object(m) => m
                    .get("path")
                    .or_else(|| m.get("name"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or(""),
                _ => "",
            };
            let band = if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}/{name}")
            };
            let child_dir = dir.join(name);
            let child_index_path = child_dir.join("index.json");
            let child_index = read(&child_index_path);
            if band == wanted {
                if child_index_path.is_file() && child_index.is_none() {
                    return false;
                }
                let face = child_index
                    .as_ref()
                    .and_then(|index| index.get("face"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("index.py");
                return child_dir.join(face).is_file();
            }
            if child_dir.is_dir()
                && child_index_path.is_file()
                && walk(&child_dir, &band, wanted, read)
            {
                return true;
            }
        }
        false
    }
    walk(&root, "", wanted, &read)
}

fn main() {
    // Profile authority is read before the canopy walk and before code generation.
    let requested = env::var("CADUCEUS_PROFILE").unwrap_or_else(|_| "homeserver".into());
    let profile_path = format!("profiles/{requested}/index.yaml");
    let _profile_authority = fs::read_to_string(&profile_path)
        .unwrap_or_else(|_| panic!("profile authority must be readable: {profile_path}"));
    println!("cargo:rerun-if-env-changed=CADUCEUS_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=CADUCEUS_SBIN_PATH");
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
    let shelf_path = seat["shelf"]["path"]
        .as_str()
        .expect("protocol seat shelf.path must be a string");
    let flags_presence_gated = seat["flags"]["presence_gated"]
        .as_bool()
        .expect("protocol seat flags.presence_gated must be boolean");
    let flags_version_compared = seat["flags"]["version_compared"]
        .as_bool()
        .expect("protocol seat flags.version_compared must be boolean");

    let generated = format!("pub const SEAT_JSON: &str = {source};\n         pub const SCHEMA_ID: &str = {schema};\n         pub const KERNEL_FIELDS: &[&str] = &[{fields}];\n         pub const TARGET_DEFAULT: &str = {target_default};\n         pub const SHELF_PATH: &str = {shelf_path};\n         pub const FLAGS_PRESENCE_GATED: bool = {flags_presence_gated};\n         pub const FLAGS_VERSION_COMPARED: bool = {flags_version_compared};\n", source = rust_string(source.trim()), schema = rust_string(schema), fields = kernel_fields.iter().map(|field| rust_string(field)).collect::<Vec<_>>().join(", "), target_default = rust_string(target_default), shelf_path = rust_string(shelf_path));
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

    // C2 compile-time canopy selection: YAML is the profile authority.
    let profiles = ["homeserver", "tv", "console", "bench", "everything-lit"];
    assert!(
        profiles.contains(&requested.as_str()),
        "unknown CADUCEUS_PROFILE: {requested}"
    );
    let mut generated = String::from("pub const ACTIVE_PROFILE: &str = ");
    generated.push_str(&rust_string(&requested));
    generated.push_str(";\n");
    for profile in profiles {
        let path = format!("profiles/{profile}/index.yaml");
        println!("cargo:rerun-if-changed={path}");
        let yaml = if profile == "everything-lit" || profile == "bench" {
            let mut routes = Vec::<String>::new();
            for name in ["homeserver", "tv", "console", "bench"] {
                let text = fs::read_to_string(format!("profiles/{name}/index.yaml"))
                    .expect("profile index readable");
                let value: serde_yaml::Value =
                    serde_yaml::from_str(&text).expect("profile index valid YAML");
                if let Some(items) = value.get("routes").and_then(serde_yaml::Value::as_sequence) {
                    for item in items {
                        if let Some(route) = item.as_str() {
                            routes.push(route.to_string());
                        }
                    }
                }
            }
            routes.sort();
            routes.dedup();
            routes
        } else {
            let text = fs::read_to_string(&path).expect("profile index readable");
            let value: serde_yaml::Value =
                serde_yaml::from_str(&text).expect("profile index valid YAML");
            value
                .get("routes")
                .and_then(serde_yaml::Value::as_sequence)
                .expect("profile routes list present")
                .iter()
                .filter_map(serde_yaml::Value::as_str)
                .map(str::to_owned)
                .collect()
        };
        let leaf_entries = walk_json_leaves(Path::new("routes"));
        let leaf_namespaces = leaf_entries
            .iter()
            .filter_map(|entry| entry.get("namespace").and_then(serde_json::Value::as_str))
            .collect::<std::collections::HashSet<_>>();
        for route in &yaml {
            assert!(
                leaf_namespaces.contains(route.as_str()),
                "profile-lit route is not a root canopy leaf: {route}"
            );
        }
        let ident = profile.replace('-', "_").to_uppercase();
        generated.push_str(&format!(
            "pub static {ident}_ROUTES: &[&str] = &[{}];\n",
            yaml.iter()
                .map(|route| rust_string(route))
                .collect::<Vec<_>>()
                .join(",")
        ));
    }
    generated.push_str("pub fn routes_for(profile: &str) -> Option<&'static [&'static str]> { match profile { \"homeserver\" => Some(HOMESERVER_ROUTES), \"tv\" => Some(TV_ROUTES), \"console\" => Some(CONSOLE_ROUTES), \"bench\" => Some(BENCH_ROUTES), \"everything-lit\" => Some(EVERYTHING_LIT_ROUTES), _ => None } }\n");
    generated.push_str("pub fn compiled_route_leaves(profile: &str) -> Option<&'static [&'static str]> { routes_for(profile) }\n");
    // Emit the selected leaf module set and canonical registrations. The routes module
    // includes only this generated set, so an unlit leaf is never compiled.
    let selected = yaml_for_profile(&requested);
    let mut modules = String::from("// generated by build.rs; profile-selected leaf inclusion\n");
    for namespace in &selected {
        let ident = module_ident(namespace);
        let path = format!("{namespace}/index.rs");
        let source_text =
            fs::read_to_string(format!("routes/{path}")).expect("leaf source readable");
        let mut prelude = String::from("use super::*; ");
        if source_text.contains("HeaderMap")
            && !source_text.contains("use axum::http::{HeaderMap")
            && !source_text.contains("http::{HeaderMap")
        {
            prelude.push_str("use axum::http::HeaderMap; ");
        }
        if source_text.contains("StatusCode")
            && !source_text.contains("http::StatusCode")
            && !source_text.contains("http::{HeaderMap, StatusCode")
        {
            prelude.push_str("use axum::http::StatusCode; ");
        }
        if source_text.contains("OriginalUri")
            && !source_text.contains("extract::{Json, OriginalUri")
            && !source_text.contains("extract::OriginalUri")
        {
            prelude.push_str("use axum::extract::OriginalUri; ");
        }
        if (source_text.contains("Path<")
            || source_text
                .lines()
                .any(|line| line.contains("Path(") && !line.contains("Path::new(")))
            && !source_text.contains("extract::Path")
            && !source_text.contains("extract::{Json, Path")
            && !source_text.contains("extract::{ConnectInfo, Json, OriginalUri, Path")
        {
            prelude.push_str("use axum::extract::Path; ");
        }
        if source_text.contains("Method") && !source_text.contains("http::Method") {
            prelude.push_str("use axum::http::Method; ");
        }
        if source_text.contains("#[derive(Deserialize)]")
            && !source_text.contains("use serde::Deserialize")
        {
            prelude.push_str("use serde::Deserialize; ");
        }
        if source_text.contains("policy::")
            && !source_text
                .lines()
                .any(|line| line.contains("use crate::shared") && line.contains("policy"))
        {
            prelude.push_str("use crate::shared::policy; ");
        }
        if source_text.contains("FIREWALL_DOCUMENT_TARGET") {
            prelude.push_str("use crate::gate::FIREWALL_DOCUMENT_TARGET; ");
        }
        for name in [
            "api_error",
            "api_error_signal",
            "document_attendance_admits",
            "attendance_admits",
            "mutation_status",
            "gated_json",
        ] {
            if source_text.contains(name)
                && !source_text
                    .lines()
                    .any(|line| line.contains("use crate::gate") && line.contains(name))
            {
                prelude.push_str(&format!("use crate::gate::{name}; "));
            }
        }
        if source_text.contains("network_read_route(")
            && !source_text.contains("async fn network_read_route")
        {
            prelude.push_str("use crate::routes::network_read_route; ");
        }
        modules.push_str(&format!("pub mod {ident} {{ {prelude} include!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/routes/{path}\")); }}\n"));
        modules.push_str(&format!(
            "pub const {}_CANONICAL: &str = \"/api/v1/{namespace}\";\n",
            ident.to_uppercase()
        ));
    }
    modules.push_str(&format!(
        "pub const SELECTED_LEAF_MODULES: &[&str] = &[{}];\n",
        selected
            .iter()
            .map(|n| rust_string(n))
            .collect::<Vec<_>>()
            .join(",")
    ));
    modules.push_str(&format!(
        "pub const SELECTED_DISCOVERY: &[&str] = &[{}];\n",
        selected
            .iter()
            .map(|n| rust_string(&format!("/api/v1/{n}")).to_string())
            .collect::<Vec<_>>()
            .join(",")
    ));
    modules.push_str("pub fn register_selected(mut router: axum::Router) -> axum::Router {\n");
    for namespace in &selected {
        let ident = module_ident(namespace);
        modules.push_str(&format!("    router = {ident}::register(router);\n"));
    }
    modules.push_str("    router\n}\n");
    fs::write(Path::new(&out_dir).join("selected_leaves.rs"), modules)
        .expect("generated selected leaves writable");
    // The enumerable registry is the sole source of valid Rust serve primitives.
    let registry_source =
        fs::read_to_string("lib/primitives.rs").expect("primitive registry must be readable");
    let registry = registry_source
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("\"")
                .and_then(|v| v.strip_suffix("\","))
        })
        .collect::<Vec<_>>();
    for entry in walk_json_leaves(Path::new("routes")) {
        if let Some(serve) = entry.get("serve").and_then(serde_json::Value::as_array) {
            for step in serve {
                if let Some(name) = step.get("rust").and_then(serde_json::Value::as_str) {
                    assert!(
                        registry.contains(&name),
                        "dangling route Rust primitive: {name}"
                    );
                }
            }
        }
    }
    // Validate declared snake bands only when a local shelf is supplied.
    if let Ok(sbin) = env::var("CADUCEUS_SBIN_PATH") {
        let shelf = Path::new(&sbin);
        for entry in walk_json_leaves(Path::new("routes")) {
            if let Some(serve) = entry.get("serve").and_then(serde_json::Value::as_array) {
                for step in serve {
                    if let Some(name) = step.get("snake").and_then(serde_json::Value::as_str) {
                        assert!(
                            !name.starts_with('/') && !name.split('/').any(|part| part == ".."),
                            "invalid snake band path: {name}"
                        );
                        assert!(
                            shelf_band_is_indexed(shelf, name),
                            "snake band is absent from authoritative CADUCEUS_SBIN_PATH index chain: {}",
                            name
                        );
                    }
                }
            }
        }
    } else {
        println!("cargo:warning=CADUCEUS_SBIN_PATH absent; skipping snake shelf validation");
    }
    fs::write(Path::new(&out_dir).join("profile_routes.rs"), generated)
        .expect("generated profile routes writable");
}
