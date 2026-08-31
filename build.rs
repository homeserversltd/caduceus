use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

fn caduceus_root() -> PathBuf {
    env::var_os("CADUCEUS_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

fn birth_certificate_path(root: &Path) -> PathBuf {
    root.join("etc/appliance/profile.json")
}

pub(crate) fn resolve_build_profile(explicit: Option<&str>, root: &Path) -> String {
    if let Some(profile) = explicit {
        return profile.to_owned();
    }

    let profile = fs::read_to_string(birth_certificate_path(root))
        .ok()
        .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
        .and_then(|value| {
            value
                .get("profile")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        });
    match profile.as_deref() {
        Some("homeserver") => "homeserver".to_owned(),
        Some("console") => "console".to_owned(),
        Some("tv") => "tv".to_owned(),
        _ => "probe".to_owned(),
    }
}

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
    let root = caduceus_root();
    let birth_certificate = birth_certificate_path(&root);
    let explicit = env::var("CADUCEUS_PROFILE").ok();
    let requested = resolve_build_profile(explicit.as_deref(), &root);
    let profile_path = format!("profiles/{requested}/index.yaml");
    let _profile_authority = fs::read_to_string(&profile_path)
        .unwrap_or_else(|_| panic!("profile authority must be readable: {profile_path}"));
    println!("cargo:rerun-if-env-changed=CADUCEUS_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=CADUCEUS_PROFILE");
    println!("cargo:rerun-if-env-changed=CADUCEUS_ROOT");
    println!("cargo:rerun-if-changed={}", birth_certificate.display());
    println!("cargo:rerun-if-env-changed=CADUCEUS_SBIN_PATH");
    println!("cargo:rerun-if-changed=schema.json");

    let source = fs::read_to_string("schema.json").expect("protocol seat must be readable");
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
    let serpents_shelf_path = seat["serpents_shelf"]["path"]
        .as_str()
        .expect("protocol seat serpents_shelf.path must be a string");
    let flags_presence_gated = seat["flags"]["presence_gated"]
        .as_bool()
        .expect("protocol seat flags.presence_gated must be boolean");
    let flags_version_compared = seat["flags"]["version_compared"]
        .as_bool()
        .expect("protocol seat flags.version_compared must be boolean");

    let generated = format!("pub const SEAT_JSON: &str = {source};\n         pub const SCHEMA_ID: &str = {schema};\n         pub const KERNEL_FIELDS: &[&str] = &[{fields}];\n         pub const SERPENTS_SHELF_PATH: &str = {serpents_shelf_path};\n         pub const FLAGS_PRESENCE_GATED: bool = {flags_presence_gated};\n         pub const FLAGS_VERSION_COMPARED: bool = {flags_version_compared};\n", source = rust_string(source.trim()), schema = rust_string(schema), fields = kernel_fields.iter().map(|field| rust_string(field)).collect::<Vec<_>>().join(", "), serpents_shelf_path = rust_string(serpents_shelf_path));
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
    let profiles = [
        "homeserver",
        "tv",
        "console",
        "bench",
        "everything-lit",
        "probe",
    ];
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
    generated.push_str("pub fn routes_for(profile: &str) -> Option<&'static [&'static str]> { match profile { \"homeserver\" => Some(HOMESERVER_ROUTES), \"tv\" => Some(TV_ROUTES), \"console\" => Some(CONSOLE_ROUTES), \"bench\" => Some(BENCH_ROUTES), \"everything-lit\" => Some(EVERYTHING_LIT_ROUTES), \"probe\" => Some(PROBE_ROUTES), _ => None } }\n");
    generated.push_str("pub fn compiled_route_leaves(profile: &str) -> Option<&'static [&'static str]> { routes_for(profile) }\n");
    // Every discovered declaration is a production leaf. The requested profile
    // remains runtime policy authority; it must not control compilation or
    // registration, otherwise cold canopy leaves are dead code by construction.
    let declarations = walk_json_leaves(Path::new("routes"))
        .into_iter()
        .filter_map(|entry| {
            let namespace = entry
                .get("namespace")
                .and_then(serde_json::Value::as_str)?
                .to_owned();
            Some((namespace, entry))
        })
        .collect::<BTreeMap<_, _>>();
    let mut all_declarations = declarations.keys().cloned().collect::<Vec<_>>();
    all_declarations.sort();
    all_declarations.dedup();
    for namespace in &all_declarations {
        let cfg = module_ident(namespace);
        println!("cargo:rustc-check-cfg=cfg({cfg})");
    }
    for namespace in &all_declarations {
        println!("cargo:rustc-cfg={}", module_ident(namespace));
    }
    let mut modules = String::from("// generated by build.rs; profile-selected leaf inclusion\n");
    for namespace in &all_declarations {
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
        all_declarations
            .iter()
            .map(|n| rust_string(n))
            .collect::<Vec<_>>()
            .join(",")
    ));
    for namespace in &all_declarations {
        assert!(
            namespace.split('/').all(|component| !component.is_empty()),
            "selected namespace must be representable by namespace.split('/'): {namespace}"
        );
    }
    modules.push_str("pub fn selected_declaration(namespace: &str) -> Option<&'static str> { match namespace {\n");
    for namespace in &all_declarations {
        let path = format!("routes/{namespace}/index.json");
        modules.push_str(&format!(
            "    {} => Some(include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{path}\"))),\n",
            rust_string(namespace)
        ));
    }
    modules.push_str("    _ => None,\n} }\n");
    modules.push_str("pub fn route_for_cli(args: &[String]) -> Option<&'static str> {\n");
    modules.push_str("    if let Some(namespace) = SELECTED_LEAF_MODULES.iter().find(|namespace| **namespace == args.join(\"/\")) { return Some(*namespace); }\n");
    modules.push_str("    let mut best = None; let mut best_len = 0usize; let mut ambiguous = false;\n    for namespace in SELECTED_LEAF_MODULES {\n        let components = namespace.split('/').collect::<Vec<_>>();\n        if components.len() <= args.len() && components.iter().zip(args).all(|(component, arg)| *component == arg) {\n            if components.len() > best_len { best = Some(*namespace); best_len = components.len(); ambiguous = false; } else if components.len() == best_len { ambiguous = true; }\n        }\n    }\n    if ambiguous { None } else { best }\n}\n");
    modules.push_str(&format!(
        "pub const SELECTED_DISCOVERY: &[&str] = &[{}];\n",
        all_declarations
            .iter()
            .map(|n| rust_string(&format!("/api/v1/{n}")).to_string())
            .collect::<Vec<_>>()
            .join(",")
    ));
    modules.push_str("pub fn register_selected(mut router: axum::Router) -> axum::Router {\n");
    for namespace in &all_declarations {
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
