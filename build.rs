use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[path = "carapace/index.rs"]
mod carapace;

fn local_build_env_sha() -> Option<String> {
    fn command_stdout(program: &str, args: &[&str]) -> Option<Vec<u8>> {
        let output = Command::new(program).args(args).output().ok()?;
        if !output.status.success() || std::str::from_utf8(&output.stdout).is_err() {
            return None;
        }
        Some(output.stdout)
    }

    let mut rustc = command_stdout("rustc", &["-Vv"])?;
    let mut cargo = command_stdout("cargo", &["-V"])?;
    while rustc.last() == Some(&b'\n') {
        rustc.pop();
    }
    while cargo.last() == Some(&b'\n') {
        cargo.pop();
    }

    let mut input = rustc;
    input.push(b'\n');
    input.extend_from_slice(&cargo);
    input.extend_from_slice(b"\nx86_64-unknown-linux-gnu\n");

    let mut sha256sum = Command::new("sha256sum")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    sha256sum.stdin.take()?.write_all(&input).ok()?;
    let output = sha256sum.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    let digest = String::from_utf8(output.stdout)
        .ok()?
        .split_whitespace()
        .next()?
        .to_owned();
    (digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, 48..=57 | 97..=102)))
    .then_some(digest)
}

fn local_rustc_version() -> Option<String> {
    let output = Command::new("rustc").arg("-Vv").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = std::str::from_utf8(&output.stdout).ok()?;
    let mut release = None;
    for line in stdout.lines() {
        let Some(value) = line.strip_prefix("release:") else {
            continue;
        };
        if release.is_some() {
            return None;
        }
        let value = value.trim();
        if value.is_empty() || value.chars().any(char::is_whitespace) {
            return None;
        }
        let (core, prerelease) = match value.split_once('-') {
            Some((core, prerelease)) => (core, Some(prerelease)),
            None => (value, None),
        };
        let core_is_valid = core.split('.').count() == 3
            && core.split('.').all(|component| {
                !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
            });
        let prerelease_is_valid = prerelease.map_or(true, |suffix| {
            !suffix.is_empty()
                && suffix.split('.').all(|identifier| !identifier.is_empty())
                && suffix
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
        });
        if !core_is_valid || !prerelease_is_valid {
            return None;
        }
        release = Some(value.to_owned());
    }
    release
}

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
        Some("homeconsole") => "homeconsole".to_owned(),
        Some("tv") => "tv".to_owned(),
        _ => "specula".to_owned(),
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

fn feature_cfg_ident(feature: &str) -> String {
    let mut ident = String::from("carapace_feature_");
    for byte in feature.bytes() {
        match byte {
            97..=122 | 48..=57 => ident.push(byte as char),
            _ => ident.push('_'),
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

fn defconfig_for_profile(profile: &str) -> Vec<String> {
    let path = format!("profiles/{profile}/index.yaml");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("carapace-defconfig-unreadable:{path}:{error}"));
    let value: serde_yaml::Value = serde_yaml::from_str(&text)
        .unwrap_or_else(|error| panic!("carapace-defconfig-invalid:{path}:{error}"));
    let declared = value
        .get("profile")
        .and_then(serde_yaml::Value::as_str)
        .unwrap_or_default();
    assert_eq!(declared, profile, "carapace-defconfig-profile-mismatch:{path}");
    value
        .get("sclerites")
        .and_then(serde_yaml::Value::as_sequence)
        .unwrap_or_else(|| panic!("carapace-defconfig-sclerites-missing:{path}"))
        .iter()
        .map(|feature| {
            feature
                .as_str()
                .unwrap_or_else(|| panic!("carapace-defconfig-answer-invalid:{path}"))
                .to_owned()
        })
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
    let root = caduceus_root();
    let birth_certificate = birth_certificate_path(&root);
    let explicit = env::var("CADUCEUS_PROFILE").ok();
    let requested = resolve_build_profile(explicit.as_deref(), &root);
    let profile_path = format!("profiles/{requested}/index.yaml");
    let _profile_authority = fs::read_to_string(&profile_path)
        .unwrap_or_else(|_| panic!("profile authority must be readable: {profile_path}"));
    println!("cargo:rerun-if-env-changed=CADUCEUS_BUILD_SHA");
    println!("cargo:rerun-if-env-changed=CADUCEUS_BUILD_ENV_SHA");
    println!("cargo:rerun-if-env-changed=CADUCEUS_PROFILE");
    println!("cargo:rerun-if-env-changed=CADUCEUS_ROOT");
    println!("cargo:rerun-if-changed={}", birth_certificate.display());
    println!("cargo:rerun-if-env-changed=CADUCEUS_SBIN_PATH");
    println!("cargo:rerun-if-changed=schema.json");
    println!("cargo:rerun-if-changed=routes");

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
    let benchmark_families = seat["flags"]["families"]
        .as_object()
        .expect("protocol seat flags.families must be an object");
    let mut benchmark_declaration = None;
    for (name, family) in benchmark_families {
        if let Some(native) = family.get("native_benchmark") {
            assert!(
                benchmark_declaration.is_none(),
                "protocol seat must declare one native benchmark flag family"
            );
            benchmark_declaration = Some((name.as_str(), family, native));
        }
    }
    let (benchmark_flag_name, benchmark_family, native_benchmark) = benchmark_declaration
        .expect("protocol seat native benchmark flag family must be declared");
    assert_eq!(
        benchmark_family.get("shape").and_then(serde_json::Value::as_str),
        Some("boolean"),
        "protocol seat benchmark flag shape must be boolean"
    );
    assert_eq!(
        benchmark_family.get("absent").and_then(serde_json::Value::as_str),
        Some("primitive"),
        "protocol seat absent benchmark flag must select the primitive path"
    );
    let benchmark_seat_bytes = fs::read_to_string("schema/caduceus.benchmark.v1.json")
        .expect("canonical benchmark declaration readable");
    let benchmark_seat: serde_json::Value = serde_json::from_str(&benchmark_seat_bytes)
        .expect("canonical benchmark declaration valid");
    let benchmark_schema = benchmark_seat["schema"]
        .as_str()
        .expect("canonical benchmark declaration schema must be a string");
    assert_eq!(
        native_benchmark["schema"].as_str(),
        Some(benchmark_schema),
        "protocol seat benchmark schema must name the canonical public declaration"
    );
    let event_seat_bytes = fs::read_to_string("schema/hyalos.channel.event.v2.json")
        .expect("canonical Hyalos event declaration readable");
    let event_seat: serde_json::Value = serde_json::from_str(&event_seat_bytes)
        .expect("canonical Hyalos event declaration valid");
    let hyalos_event_schema = event_seat["schema"]
        .as_str()
        .expect("canonical Hyalos event declaration schema must be a string");
    assert_eq!(
        hyalos_event_schema,
        "hyalos.channel.event.v2",
        "canonical Hyalos event declaration must name the v2 channel event"
    );
    let benchmark_receive_locus = native_benchmark["receive_locus"]
        .as_str()
        .expect("protocol seat benchmark receive locus must be a string");
    let benchmark_serve_locus = native_benchmark["serve_locus"]
        .as_str()
        .expect("protocol seat benchmark serve locus must be a string");
    let benchmark_serve_ordinal_base = native_benchmark["serve_ordinal_base"]
        .as_u64()
        .expect("protocol seat benchmark serve ordinal base must be an unsigned integer");

    let generated = format!("pub const SEAT_JSON: &str = {source};\n         pub const SCHEMA_ID: &str = {schema};\n         pub const KERNEL_FIELDS: &[&str] = &[{fields}];\n         pub const SERPENTS_SHELF_PATH: &str = {serpents_shelf_path};\n         pub const FLAGS_PRESENCE_GATED: bool = {flags_presence_gated};\n         pub const FLAGS_VERSION_COMPARED: bool = {flags_version_compared};\n         pub const BENCHMARK_FLAG_NAME: &str = {benchmark_flag_name};\n         pub const BENCHMARK_REPORT_SCHEMA: &str = {benchmark_schema};\n         pub const HYALOS_EVENT_SCHEMA: &str = {hyalos_event_schema};\n         pub const BENCHMARK_RECEIVE_LOCUS: &str = {benchmark_receive_locus};\n         pub const BENCHMARK_SERVE_LOCUS: &str = {benchmark_serve_locus};\n         pub const BENCHMARK_SERVE_ORDINAL_BASE: u64 = {benchmark_serve_ordinal_base};\n", source = rust_string(source.trim()), schema = rust_string(schema), fields = kernel_fields.iter().map(|field| rust_string(field)).collect::<Vec<_>>().join(", "), serpents_shelf_path = rust_string(serpents_shelf_path), benchmark_flag_name = rust_string(benchmark_flag_name), benchmark_schema = rust_string(benchmark_schema), hyalos_event_schema = rust_string(hyalos_event_schema), benchmark_receive_locus = rust_string(benchmark_receive_locus), benchmark_serve_locus = rust_string(benchmark_serve_locus));
    let out_dir = env::var_os("OUT_DIR").expect("OUT_DIR must be set");
    fs::write(Path::new(&out_dir).join("protocol_seat.rs"), generated)
        .expect("generated protocol metadata must be writable");

    // Public seats have one source each. Preserve their exact bytes in the binary.
    println!("cargo:rerun-if-changed=schema");
    // Expose the contracted public seats, including release and update-set.
    let seats = [
        "caduceus.beam.v1",
        "caduceus.docs.seal.v1",
        "caduceus.ruyi.v1",
        "caduceus.appliance.stats.sample.v1",
        "caduceus.appliance.stats.admin.v1",
        "caduceus.doors.readback.v1",
        "harmonia.ruyi-perspective.v1",
        "harmonia.ruyi-register.v1",
        "harmonia.config_proposals.feed.v1",
        "harmonia.interactables.ruyi_bump.receipt.v1",
        "harmonia.interactables.household_trust_renew.receipt.v1",
        "harmonia.interactables.dns_record.receipt.v1",
        "harmonia.interactables.ruyi_perspective_seed.receipt.v1",
        "estate.release-flag.v1",
        "harmonia.update-set.v1",
        "harmonia.update_module.v1",
        "appliance.xenia.v1",
        "coronatio.face-surface.v1",
        "harmonia.engine.source_resolution.v1",
        "xenia.health.v1",
        "xenia.events.v1",
        "caduceus.xenia.verdict.v1",
        "caduceus.access.gate.v1",
        "appliance.load.context.v1",
        "caduceus.benchmark.v1",
        "hyalos.channel.event.v2",
        "caduceus.exousia.posture.v1",
        "coronatio.exousia.agent.service.v1",
        "coronatio.exousia.agent.posture.v1",
        "caduceus.nas.setup.v1",
        "caduceus.nas.attach.v1",
        "caduceus.nas.detach.v1",
        "caduceus.transmission.up.v1",
        "caduceus.transmission.down.v1",
        "caduceus.transmission.status.v1",
        "caduceus.transmission.keys.v1",
        "caduceus.transmission.vpn.settings.v1",
        "caduceus.network.tailscale.v1",
        "caduceus.disk.census.v1",
        "appliance.crossings.v1",
    ]
    .map(|id| PathBuf::from(format!("schema/{id}.json")));
    let mut embedded = String::from("const EMBEDDED_SEATS: &[(&str, &str)] = &[\n");
    for path in seats {
        println!("cargo:rerun-if-changed={}", path.display());
        let bytes = fs::read_to_string(&path).expect("public seat readable");
        let id = path
            .file_stem()
            .and_then(|name| name.to_str())
            .expect("schema id filename");
        embedded.push_str(&format!(
            "({}, {}),\n",
            rust_string(id),
            rust_string(&bytes)
        ));
    }
    embedded.push_str("];\n");
    fs::write(Path::new(&out_dir).join("public_schema_seats.rs"), embedded)
        .expect("embedded public seats writable");

    let mut embedded_crossings = String::from("const EMBEDDED_CROSSINGS: &[(&str, &str)] = &[\n");
    for profile in ["homeserver", "homeconsole", "tv", "lab"] {
        let path = format!("crossings/{profile}.json");
        println!("cargo:rerun-if-changed={path}");
        let bytes = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!("caduceus-crossings-declaration-invalid: {path} unavailable: {error}")
        });
        let declaration: serde_json::Value = serde_json::from_str(&bytes).unwrap_or_else(|error| {
            panic!("caduceus-crossings-declaration-invalid: {path} invalid JSON: {error}")
        });
        let observed_schema = declaration
            .get("schema")
            .and_then(serde_json::Value::as_str);
        assert_eq!(
            observed_schema,
            Some("appliance.crossings.v1"),
            "caduceus-crossings-declaration-invalid: {path} schema expected appliance.crossings.v1, observed {observed_schema:?}"
        );
        let observed_profile = declaration
            .get("profile")
            .and_then(serde_json::Value::as_str);
        assert_eq!(
            observed_profile,
            Some(profile),
            "caduceus-crossings-declaration-invalid: {path} profile expected {profile}, observed {observed_profile:?}"
        );
        embedded_crossings.push_str(&format!(
            "({}, {}),\n",
            rust_string(profile),
            rust_string(&bytes)
        ));
    }
    embedded_crossings.push_str("];\n");
    fs::write(
        Path::new(&out_dir).join("embedded_crossings.rs"),
        embedded_crossings,
    )
    .expect("embedded crossings declarations writable");

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
    match env::var("CADUCEUS_BUILD_ENV_SHA") {
        Ok(env_sha) => {
            assert!(
                env_sha.len() == 64
                    && env_sha
                        .bytes()
                        .all(|byte| matches!(byte, 48..=57 | 97..=102)),
                "CADUCEUS_BUILD_ENV_SHA must be 64 lowercase hexadecimal characters"
            );
            println!("cargo:rustc-env=CADUCEUS_BUILD_ENV_SHA={env_sha}");
        }
        Err(_) => println!(
            "cargo:rustc-env=CADUCEUS_BUILD_ENV_SHA={}",
            local_build_env_sha().unwrap_or_else(|| "unset".to_owned())
        ),
    }
    println!(
        "cargo:rustc-env=CADUCEUS_BUILD_RUSTC_VERSION={}",
        local_rustc_version().unwrap_or_else(|| "unset".to_owned())
    );

    // The feature model is the sole capability authority. Defconfigs answer the
    // model; the same resolution derives code, /doors, commands, and the inspectable tree.
    let profiles = [
        "homeserver",
        "homeconsole",
        "tv",
        "specula",
        "bench",
        "everything-lit",
    ];
    assert!(
        profiles.contains(&requested.as_str()),
        "unknown CADUCEUS_PROFILE: {requested}"
    );
    println!("cargo:rerun-if-changed=carapace/index.json");
    println!("cargo:rerun-if-changed=carapace/index.rs");
    println!("cargo:rerun-if-changed=profiles");
    let model_source = fs::read_to_string("carapace/index.json")
        .expect("carapace feature model must be readable");
    let model: serde_json::Value = serde_json::from_str(&model_source)
        .expect("carapace feature model must be valid JSON");
    assert_eq!(
        model.get("schema").and_then(serde_json::Value::as_str),
        Some("caduceus.carapace.model.v1"),
        "carapace feature model schema must be caduceus.carapace.model.v1"
    );
    let features = model
        .get("features")
        .and_then(serde_json::Value::as_object)
        .expect("carapace model features must be an object");
    let feature_ids = features.keys().cloned().collect::<BTreeSet<_>>();
    let validate_needs = |entry: &serde_json::Value, label: &str| -> Result<(), String> {
        for field in ["needs", "needs_any"] {
            if field == "needs" && entry.get(field).is_none() {
                return Err(format!("{label}:carapace-needs-missing"));
            }
            let Some(value) = entry.get(field) else {
                continue;
            };
            let values = value
                .as_array()
                .ok_or_else(|| format!("{label}:carapace-{field}-invalid"))?;
            for value in values {
                let id = value
                    .as_str()
                    .ok_or_else(|| format!("{label}:carapace-{field}-invalid"))?;
                if !feature_ids.contains(id) {
                    return Err(format!("{label}:carapace-feature-unknown:{id}"));
                }
            }
        }
        Ok(())
    };

    let leaf_entries = walk_json_leaves(Path::new("routes"));
    let mut namespace_set = BTreeSet::new();
    for entry in &leaf_entries {
        let namespace = entry
            .get("namespace")
            .and_then(serde_json::Value::as_str)
            .expect("every route leaf declares namespace");
        assert!(
            namespace_set.insert(namespace.to_owned()),
            "duplicate route namespace: {namespace}"
        );
        validate_needs(entry, namespace)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            entry.get("commands").and_then(serde_json::Value::as_array).is_some(),
            "{namespace}:carapace-commands-missing"
        );
        if let Some(operations) = entry.get("operations").and_then(serde_json::Value::as_array) {
            for (index, operation) in operations.iter().enumerate() {
                let label = format!("{namespace}:operation:{index}");
                validate_needs(operation, &label)
                    .unwrap_or_else(|error| panic!("{error}"));
                assert!(
                    operation.get("commands").and_then(serde_json::Value::as_array).is_some(),
                    "{label}:carapace-commands-missing"
                );
            }
        }
    }
    assert!(
        !namespace_set.is_empty(),
        "carapace canopy contains no route namespaces"
    );

    let mut generated = String::from("pub const ACTIVE_PROFILE: &str = ");
    generated.push_str(&rust_string(&requested));
    generated.push_str(";\n");
    let mut resolved_profiles = BTreeMap::<
        String,
        (Vec<String>, Vec<String>, Vec<String>, String),
    >::new();
    for profile in profiles {
        let path = format!("profiles/{profile}/index.yaml");
        println!("cargo:rerun-if-changed={path}");
        let answers = defconfig_for_profile(profile);
        let resolution = carapace::resolve(&model, &answers)
            .unwrap_or_else(|error| panic!("{profile}:carapace-resolution-failed:{error}"));
        let mut routes = BTreeSet::new();
        let mut commands = BTreeSet::new();
        for id in &resolution.lit {
            let feature = features
                .get(id)
                .unwrap_or_else(|| panic!("carapace-feature-unknown:{id}"));
            if let Some(values) = feature.get("commands") {
                let values = values
                    .as_array()
                    .unwrap_or_else(|| panic!("{id}:carapace-feature-commands-invalid"));
                for command in values {
                    let command = command
                        .as_str()
                        .unwrap_or_else(|| panic!("{id}:carapace-feature-command-invalid"));
                    commands.insert(command.to_owned());
                }
            }
        }
        for entry in &leaf_entries {
            if carapace::route_is_lit(entry, &resolution)
                .unwrap_or_else(|error| panic!("{profile}:carapace-route-resolution-failed:{error}"))
            {
                let namespace = entry["namespace"]
                    .as_str()
                    .expect("validated route namespace");
                routes.insert(namespace.to_owned());
                commands.extend(
                    carapace::commands_for_leaf(entry, &resolution)
                        .unwrap_or_else(|error| panic!("{namespace}:carapace-command-resolution-failed:{error}")),
                );
            }
        }
        for mandatory in ["beam", "ruyi", "schema"] {
            assert!(
                routes.contains(mandatory),
                "{profile}:mandatory carapace door missing: {mandatory}"
            );
        }
        let routes = routes.into_iter().collect::<Vec<_>>();
        let commands = commands.into_iter().collect::<Vec<_>>();
        let sclerites = resolution.lit.iter().cloned().collect::<Vec<_>>();
        let mut profile_model = model.clone();
        profile_model["profile"] = serde_json::Value::String(profile.to_owned());
        let tree = carapace::render_tree(&profile_model, &resolution, &leaf_entries)
            .unwrap_or_else(|error| panic!("{profile}:carapace-tree-render-failed:{error}"));
        let ident = profile.replace('-', "_").to_uppercase();
        let rust_values = |values: &[String]| {
            values
                .iter()
                .map(|value| rust_string(value))
                .collect::<Vec<_>>()
                .join(",")
        };
        generated.push_str(&format!(
            "pub static {ident}_ROUTES: &[&str] = &[{}];\n",
            rust_values(&routes)
        ));
        generated.push_str(&format!(
            "pub static {ident}_COMMANDS: &[&str] = &[{}];\n",
            rust_values(&commands)
        ));
        generated.push_str(&format!(
            "pub static {ident}_SCLERITES: &[&str] = &[{}];\n",
            rust_values(&sclerites)
        ));
        generated.push_str(&format!(
            "pub static {ident}_TREE: &str = {};\n",
            rust_string(&tree)
        ));
        resolved_profiles.insert(profile.to_owned(), (routes, commands, sclerites, tree));
    }
    generated.push_str("pub static SCLERITES: &[&str] = &[\n");
    for id in &feature_ids {
        generated.push_str(&format!("{},\n", rust_string(id)));
        println!("cargo:rustc-check-cfg=cfg({})", feature_cfg_ident(id));
    }
    generated.push_str("];\n");
    generated.push_str("pub fn routes_for(profile: &str) -> Option<&'static [&'static str]> { match profile {\n");
    for profile in profiles {
        let ident = profile.replace('-', "_").to_uppercase();
        generated.push_str(&format!(
            "    {} => Some({ident}_ROUTES),\n",
            rust_string(profile)
        ));
    }
    generated.push_str("    _ => None,\n} }\n");
    generated.push_str("pub fn commands_for(profile: &str) -> Option<&'static [&'static str]> { match profile {\n");
    for profile in profiles {
        let ident = profile.replace('-', "_").to_uppercase();
        generated.push_str(&format!(
            "    {} => Some({ident}_COMMANDS),\n",
            rust_string(profile)
        ));
    }
    generated.push_str("    _ => None,\n} }\n");
    generated.push_str("pub fn sclerites_for(profile: &str) -> Option<&'static [&'static str]> { match profile {\n");
    for profile in profiles {
        let ident = profile.replace('-', "_").to_uppercase();
        generated.push_str(&format!(
            "    {} => Some({ident}_SCLERITES),\n",
            rust_string(profile)
        ));
    }
    generated.push_str("    _ => None,\n} }\n");
    generated.push_str("pub fn tree_for(profile: &str) -> Option<&'static str> { match profile {\n");
    for profile in profiles {
        let ident = profile.replace('-', "_").to_uppercase();
        generated.push_str(&format!(
            "    {} => Some({ident}_TREE),\n",
            rust_string(profile)
        ));
    }
    generated.push_str("    _ => None,\n} }\n");
    generated.push_str("pub fn compiled_route_leaves(profile: &str) -> Option<&'static [&'static str]> { routes_for(profile) }\n");
    generated.push_str("pub fn show_tree(profile: &str) -> i32 { match tree_for(profile) { Some(tree) => { print!(\"{tree}\"); 0 }, None => { eprintln!(\"caduceus-profile-unknown:{profile}\"); 2 } } }\n");
    generated.push_str("pub static COMMANDS: &[&str] = &[");
    let active = resolved_profiles
        .get(&requested)
        .unwrap_or_else(|| panic!("resolved profile missing: {requested}"));
    generated.push_str(
        &active
            .1
            .iter()
            .map(|command| rust_string(command))
            .collect::<Vec<_>>()
            .join(","),
    );
    generated.push_str("];\n");
    generated.push_str("pub static ACTIVE_SCLERITES: &[&str] = &[");
    generated.push_str(
        &active
            .2
            .iter()
            .map(|feature| rust_string(feature))
            .collect::<Vec<_>>()
            .join(","),
    );
    generated.push_str("];\n");
    generated.push_str("pub fn feature_lit(feature: &str) -> bool { ACTIVE_SCLERITES.contains(&feature) }\n");

    for feature in &feature_ids {
        let cfg = feature_cfg_ident(feature);
        if active.2.contains(feature) {
            println!("cargo:rustc-cfg={cfg}");
        }
    }
    let selected = active.0.clone();
    let selected_leaf_entries = leaf_entries.clone();
    // The generated module set is the active resolved carapace closure.
    for entry in walk_json_leaves(Path::new("routes")) {
        if let Some(namespace) = entry.get("namespace").and_then(serde_json::Value::as_str) {
            let cfg = module_ident(namespace);
            println!("cargo:rustc-check-cfg=cfg({cfg})");
        }
    }
    for namespace in &selected {
        println!("cargo:rustc-cfg={}", module_ident(namespace));
    }
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
    for namespace in &selected {
        assert!(
            namespace.split('/').all(|component| !component.is_empty()),
            "selected namespace must be representable by namespace.split('/'): {namespace}"
        );
    }
    modules.push_str("pub fn selected_declaration(namespace: &str) -> Option<&'static str> { match namespace {\n");
    for namespace in &selected {
        let path = format!("routes/{namespace}/index.json");
        modules.push_str(&format!(
            "    {} => Some(include_str!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/{path}\"))),\n",
            rust_string(namespace)
        ));
    }
    modules.push_str("    _ => None,\n} }\n");
    modules.push_str(
        "pub fn selected_transition(namespace: &str) -> Option<&'static str> { match namespace {\n",
    );
    for namespace in &selected {
        let transition = selected_leaf_entries
            .iter()
            .find(|entry| {
                entry.get("namespace").and_then(serde_json::Value::as_str)
                    == Some(namespace.as_str())
            })
            .and_then(|entry| entry.get("transition").and_then(serde_json::Value::as_str));
        if let Some(transition) = transition {
            modules.push_str(&format!(
                "    {} => Some({}),\n",
                rust_string(namespace),
                rust_string(transition)
            ));
        }
    }
    modules.push_str("    _ => None,\n} }\n");
    modules.push_str("pub fn route_for_cli(args: &[String]) -> Option<&'static str> {\n");
    modules.push_str("    let mut best = None; let mut best_len = 0usize; let mut ambiguous = false;\n    for namespace in SELECTED_LEAF_MODULES {\n        let components = namespace.split('/').collect::<Vec<_>>();\n        if components.len() > args.len() { continue; }\n        let transition = selected_transition(namespace);\n        let separator = if transition.is_some() { \".\" } else { \"/\" };\n        let candidate = args[..components.len()].join(separator);\n        let wanted = transition.unwrap_or(namespace);\n        if candidate == wanted {\n            if components.len() > best_len { best = Some(*namespace); best_len = components.len(); ambiguous = false; } else if components.len() == best_len { ambiguous = true; }\n        }\n    }\n    if ambiguous { None } else { best }\n}\n");
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
