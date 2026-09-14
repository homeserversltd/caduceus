use super::{observation, observe, remote, seat, store, Refusal, Result, VERDICT, XENIA};
use crate::shared::policy;
use serde_json::{json, Value};
use std::fs;
use std::io::Read;
use std::net::ToSocketAddrs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub struct Candidate {
    pub house: store::House,
    pub entry: Value,
    pub row: Value,
    pub observed: Value,
}

fn refuse(check: &str, field: &str, message: &str) -> Refusal {
    Refusal::new(
        check,
        field,
        message,
        "Correct the named declaration and repeat validation before admission.",
    )
}

fn forbidden(value: &Value, keys: &[Value], check: &str, path: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                // Household extension payloads are opaque; these are not instructions
                // the staff executes. Retain them, including nested extension data.
                if key.starts_with("x-household") {
                    continue;
                }
                if !value.is_null() && keys.iter().any(|k| k.as_str() == Some(key)) {
                    return Err(refuse(
                        check,
                        &format!("{path}.{key}"),
                        "forbidden-instruction",
                    ));
                }
                forbidden(value, keys, check, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(array) => {
            for (i, value) in array.iter().enumerate() {
                forbidden(value, keys, check, &format!("{path}[{i}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn policy_keys(name: &str) -> Result<&'static [Value]> {
    seat::declaration(VERDICT)?["admission_policy"][name]
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| observation("schema", name, "admission-policy-seat-desync"))
}

/// Read rows, never a compiled list of native/shipped identities. An unknown
/// outer shape is a missing observation, not an empty native registry.
fn rows(value: &Value, path: &str) -> Result<Vec<(String, Value)>> {
    if let Some(array) = value.as_array() {
        return array
            .iter()
            .map(|row| {
                let id = row
                    .get("id")
                    .or_else(|| row.get("tabId"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| observation("D", path, "registry-row-id-absent"))?;
                Ok((id.into(), row.clone()))
            })
            .collect();
    }
    if let Some(object) = value.as_object() {
        return object
            .iter()
            .map(|(id, row)| {
                if !row.is_object() {
                    return Err(observation("D", path, "registry-row-invalid"));
                }
                Ok((id.clone(), row.clone()))
            })
            .collect();
    }
    Err(observation("D", path, "registry-observation-absent"))
}

fn registry() -> Result<Vec<(String, Value)>> {
    let native = remote::crown("/api/registry", "D")?;
    let native_rows = native.get("nativeTabContracts").ok_or_else(|| {
        observation(
            "D",
            "nativeTabContracts",
            "native-registry-observation-absent",
        )
    })?;
    let mut result = rows(native_rows, "nativeTabContracts")?;
    let tabs = remote::crown("/api/tabs", "D")?;
    let dynamic = tabs.get("tabs").unwrap_or(&tabs);
    result.extend(rows(dynamic, "crown.tabs")?);
    Ok(result)
}

fn declaration_equal(existing: &Value, entry: &Value) -> Result<bool> {
    let mut existing = existing.clone();
    let mut entry = entry.clone();
    // Stamps are observations, and grant policy is evaluated at I, not before D.
    // Do not erase arbitrary unknown fields to manufacture an idempotent match.
    for value in [&mut existing, &mut entry] {
        let object = value
            .as_object_mut()
            .ok_or_else(|| refuse("D", "entry", "entry-object-required"))?;
        for key in ["installed", "discovered", "granted"] {
            object.remove(key);
        }
    }
    Ok(existing == entry)
}

fn source(manifest: &Value) -> Result<bool> {
    let source = &manifest["source"];
    seat::field(XENIA, "source", source, "E", "manifest.source")?;
    if source
        .get("candidates")
        .is_some_and(|value| !value.is_null())
    {
        return Err(refuse(
            "E",
            "manifest.source.candidates",
            "source-road-deferred",
        ));
    }
    forbidden(
        source,
        policy_keys("forbidden_instructions")?,
        "E",
        "manifest.source",
    )?;
    if source["kind"].as_str() == Some("clone") {
        let repo = source["repo"]
            .as_str()
            .ok_or_else(|| refuse("E", "manifest.source.repo", "clone-repo-required"))?;
        let parts: Vec<_> = repo.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|p| {
                p.is_empty()
                    || *p == "."
                    || *p == ".."
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            })
        {
            return Err(refuse("E", "manifest.source.repo", "clone-repo-required"));
        }
        let reference = source["ref"]
            .as_str()
            .ok_or_else(|| refuse("E", "manifest.source.ref", "clone-ref-required"))?;
        if reference.is_empty() || reference.chars().any(char::is_whitespace) {
            return Err(refuse("E", "manifest.source.ref", "clone-ref-required"));
        }
        // Clone repos use the body's one reachable Forgejo host. This is a
        // bounded DNS observation only: validation never fetches or runs git.
        if ("git.home.arpa", 443)
            .to_socket_addrs()
            .ok()
            .and_then(|mut addresses| addresses.next())
            .is_none()
        {
            return Err(observation(
                "E",
                "manifest.source.repo",
                "clone-host-unreachable",
            ));
        }
        return Ok(true);
    }
    let repo = source["release_repo"]
        .as_str()
        .ok_or_else(|| refuse("E", "manifest.source.release_repo", "release-road-required"))?;
    let parts: Vec<_> = repo.split('/').collect();
    if parts.len() != 2
        || parts.iter().any(|p| {
            p.is_empty()
                || *p == "."
                || *p == ".."
                || !p
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
    {
        return Err(refuse(
            "E",
            "manifest.source.release_repo",
            "release-repo-invalid",
        ));
    }
    if !source["ref"].as_str().is_some_and(|s| !s.is_empty()) || source.get("url").is_some() {
        return Err(refuse("E", "manifest.source.ref", "release-ref-required"));
    }
    Ok(false)
}

fn inventory_claims(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if key.starts_with("x-household") {
                    continue;
                }
                inventory_claims(value, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(array) => {
            for (i, value) in array.iter().enumerate() {
                inventory_claims(value, &format!("{path}[{i}]"))?;
            }
        }
        Value::String(text) => {
            for name in text.split('/') {
                if policy_keys("forbidden_inventory_names")?
                    .iter()
                    .any(|v| v.as_str() == Some(name))
                    || policy_keys("forbidden_inventory_suffixes")?
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|suffix| name.ends_with(suffix))
                {
                    return Err(refuse("F", path, "forbidden-inventory-name"));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

fn inside(path: &str, root: &str) -> bool {
    let path = Path::new(path);
    path.is_absolute()
        && path.starts_with(root)
        && !path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
}

fn check_permissions(id: &str) -> Result<()> {
    let seat_root = format!("/var/lib/xenia/{id}");
    let path = crate::shared::config::path(&format!("{seat_root}/permissions/xenia"));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(refuse(
                "F",
                &format!("{seat_root}/permissions/xenia"),
                "permissions-visudo-refused",
            ));
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(refuse(
            "F",
            &format!("{seat_root}/permissions/xenia"),
            "permissions-file-symlink",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(refuse(
            "F",
            &format!("{seat_root}/permissions/xenia"),
            "permissions-file-writable",
        ));
    }
    let contents = fs::read_to_string(&path).map_err(|_| {
        refuse(
            "F",
            &format!("{seat_root}/permissions/xenia"),
            "permissions-visudo-refused",
        )
    })?;
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.split_whitespace().next() != Some("caduceus") {
            return Err(refuse(
                "F",
                &format!("{seat_root}/permissions/xenia"),
                "permissions-grantee-refused",
            ));
        }
        if line.contains('*') {
            return Err(refuse(
                "F",
                &format!("{seat_root}/permissions/xenia"),
                "permissions-wildcard-refused",
            ));
        }
        let Some(commands) = line.split_once("NOPASSWD:").map(|(_, value)| value.trim()) else {
            return Err(refuse(
                "F",
                &format!("{seat_root}/permissions/xenia"),
                "permissions-grantee-refused",
            ));
        };
        if commands.is_empty() {
            return Err(refuse(
                "F",
                &format!("{seat_root}/permissions/xenia"),
                "permissions-grantee-refused",
            ));
        }
        for command in commands.split(',') {
            let command = command.split_whitespace().next().unwrap_or("");
            if command == "ALL" {
                return Err(refuse(
                    "F",
                    &format!("{seat_root}/permissions/xenia"),
                    "permissions-wildcard-refused",
                ));
            }
            if !inside(command, &format!("{seat_root}/")) {
                return Err(refuse(
                    "F",
                    &format!("{seat_root}/permissions/xenia"),
                    "permissions-path-outside-seat",
                ));
            }
        }
    }
    let visudo = ["/usr/sbin/visudo", "/usr/bin/visudo"]
        .iter()
        .find(|candidate| Path::new(candidate).is_file())
        .ok_or_else(|| {
            refuse(
                "F",
                &format!("{seat_root}/permissions/xenia"),
                "visudo-absent",
            )
        })?;
    let mut child = Command::new(visudo)
        .args(["-c", "-f"])
        .arg(&path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| {
            refuse(
                "F",
                &format!("{seat_root}/permissions/xenia"),
                "permissions-visudo-refused",
            )
        })?;
    let reader = child.stdout.take().ok_or_else(|| {
        refuse(
            "F",
            &format!("{seat_root}/permissions/xenia"),
            "permissions-visudo-refused",
        )
    })?;
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        reader.take(65_537).read_to_end(&mut output).map(|_| output)
    });
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let output = reader.join().ok().and_then(std::result::Result::ok);
    if status.is_none()
        || output.as_ref().is_none_or(|output| output.len() > 65_536)
        || !status.is_some_and(|status| status.success())
    {
        return Err(refuse(
            "F",
            &format!("{seat_root}/permissions/xenia"),
            "permissions-visudo-refused",
        ));
    }
    Ok(())
}

fn install(manifest: &Value, id: &str) -> Result<()> {
    let install = &manifest["install"];
    let kind = manifest["kind"].as_str().unwrap_or("");
    if install.is_null() {
        return if kind == "cartridge-process" {
            Err(Refusal::new(
                "G",
                "manifest.install.owner",
                "owner-absent",
                "Declare an existing non-root passwd account in manifest.install.owner.",
            ))
        } else {
            Ok(())
        };
    }
    seat::field(XENIA, "install", install, "G", "manifest.install")?;
    if kind == "iframe" {
        let empty = install.as_object().is_some_and(|object| {
            ["bin", "unit", "static_dir", "owner"]
                .iter()
                .all(|key| object.get(*key).is_none_or(Value::is_null))
        });
        return if empty {
            Ok(())
        } else {
            Err(refuse("G", "install", "iframe-install-forbidden"))
        };
    }
    let process = format!("/var/lib/xenia/{id}/");
    let static_root = format!("/var/lib/coronatio/tabs/{id}/");
    if let Some(bin) = install["bin"].as_str() {
        if kind != "cartridge-process"
            || !inside(bin, &process)
            || Path::new(bin) == Path::new(&process)
        {
            return Err(refuse(
                "G",
                "manifest.install.bin",
                "process-seat-outside-guest",
            ));
        }
    }
    if let Some(dir) = install["static_dir"].as_str() {
        let safe = if Path::new(dir).is_absolute() {
            inside(dir, &static_root)
        } else {
            !dir.is_empty()
                && Path::new(dir)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
        };
        if !safe {
            return Err(refuse(
                "G",
                "manifest.install.static_dir",
                "static-seat-outside-guest",
            ));
        }
    }
    if kind == "cartridge-process" {
        let owner = install["owner"].as_str().ok_or_else(|| {
            Refusal::new(
                "G",
                "manifest.install.owner",
                "owner-absent",
                "Declare an existing non-root passwd account in manifest.install.owner.",
            )
        })?;
        store::owner_ids(owner)?;
    }
    Ok(())
}

fn endpoint(value: &Value) -> Result<Option<(Option<u16>, String)>> {
    let Some(text) = value.as_str() else {
        if value.is_null() {
            return Ok(None);
        }
        return Err(refuse("H", "transport.declared", "transport-shape-invalid"));
    };
    if let Some(path) = text.strip_prefix("unix:") {
        if !Path::new(path).is_absolute()
            || Path::new(path)
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(refuse("H", "transport.declared", "unix-path-invalid"));
        }
        return Ok(Some((None, text.into())));
    }
    let url = url::Url::parse(text)
        .map_err(|_| refuse("H", "transport.declared", "transport-url-invalid"))?;
    let local = url
        .host_str()
        .and_then(|h| h.trim_matches(['[', ']']).parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.scheme() != "http" || !local || !url.username().is_empty() || url.password().is_some() {
        return Err(refuse("H", "transport.declared", "loopback-http-required"));
    }
    Ok(Some((url.port_or_known_default(), text.into())))
}

fn static_claim(entry: &Value, id: &str) -> Option<String> {
    let dir = entry["install"]
        .get("static_dir")
        .or_else(|| entry.get("static_dir"))
        .or_else(|| entry.get("staticDir"))?
        .as_str()?;
    Some(if Path::new(dir).is_absolute() {
        Path::new(dir)
            .to_string_lossy()
            .trim_end_matches('/')
            .into()
    } else {
        format!("/var/lib/coronatio/tabs/{id}/{dir}")
            .trim_end_matches('/')
            .into()
    })
}

fn claims(
    manifest: &Value,
    house: &store::House,
    registry: &[(String, Value)],
    own: bool,
) -> Result<Value> {
    let id = manifest["id"].as_str().unwrap_or("");
    let declared = endpoint(&manifest["transport"]["declared"])?;
    let static_dir = static_claim(manifest, id);
    let guests = house.register["xenoi"]
        .as_object()
        .ok_or_else(|| observation("H", "register", "register-map-absent"))?;
    // Both authoritative registry rows and admitted guests participate.
    let all: Vec<(&str, &Value)> = registry
        .iter()
        .map(|(id, row)| (id.as_str(), row))
        .chain(guests.iter().map(|(id, row)| (id.as_str(), row)))
        .collect();
    for (other, row) in all {
        if other == id && own {
            continue;
        }
        let row_manifest = row.get("manifest").unwrap_or(row);
        if row_manifest
            .get("proxy_route")
            .or_else(|| row_manifest.get("proxyRoute"))
            .or_else(|| row_manifest.get("stateRoute"))
            .is_some_and(|route| route == &manifest["proxy_route"])
        {
            return Err(refuse("H", "proxy_route", "route-already-claimed"));
        }
        if static_dir.is_some() && static_claim(row_manifest, other) == static_dir {
            return Err(refuse(
                "H",
                "install.static_dir",
                "static-dir-already-claimed",
            ));
        }
        if let Some((port, socket)) = &declared {
            if let Some((other_port, other_socket)) = endpoint(
                row_manifest["transport"]
                    .get("declared")
                    .or_else(|| row_manifest.get("local_transport_endpoint"))
                    .or_else(|| row_manifest.get("localTransportEndpoint"))
                    .unwrap_or(&Value::Null),
            )? {
                if (port.is_some() && *port == other_port)
                    || (*port == None && *socket == other_socket)
                {
                    return Err(refuse(
                        "H",
                        "transport.declared",
                        "registry-transport-already-claimed",
                    ));
                }
            }
        }
    }
    let listeners = observe::sockets()?;
    if let Some((port, socket)) = declared {
        let owned = if own {
            Some(observe::runtime(&guests[id])?)
        } else {
            None
        };
        for listener in &listeners {
            if (port.is_some() && port == listener.port)
                || (port.is_none() && socket == listener.endpoint)
            {
                let own_inode = owned
                    .as_ref()
                    .and_then(|v| v["socket_inodes"].as_array())
                    .is_some_and(|values| {
                        values.iter().any(|v| v.as_u64() == Some(listener.inode))
                    });
                if !own_inode {
                    return Err(refuse(
                        "H",
                        "transport.declared",
                        "listener-already-claimed",
                    ));
                }
            }
        }
    }
    Ok(json!(listeners
        .iter()
        .map(observe::Listener::value)
        .collect::<Vec<_>>()))
}

fn compatibility(manifest: &Value) -> Result<()> {
    if let Some(value) = manifest.get("requires_kit") {
        seat::field(XENIA, "requires_kit", value, "J", "manifest.requires_kit")?;
    }
    if manifest
        .get("requires_kit")
        .is_some_and(|value| !value.is_null())
    {
        return Err(observation(
            "J",
            "manifest.requires_kit",
            "compatibility-readback-absent",
        ));
    }
    Ok(())
}

pub fn validate(body: &Value) -> Result<Candidate> {
    seat::startup().map_err(|e| observation("A", "schema", e))?;
    // A: snapshot lock ends before the first HTTP read.
    let house = store::snapshot()?;
    let health = remote::health()?;
    let manifest = body
        .get("manifest")
        .ok_or_else(|| refuse("B", "manifest", "manifest-absent"))?;
    seat::kernel(XENIA, Some("manifest"), manifest, "B", "manifest")?;
    // B only judges the frozen kernel, custody and types. Identity, source,
    // seats, transport and compatibility keep their own first-failure rungs.
    let fields = seat::declaration(XENIA)?["fields"]
        .as_object()
        .ok_or_else(|| observation("B", "schema.fields", "seat-fields-absent"))?;
    for (key, rule) in fields {
        if [
            "id",
            "version",
            "proxy_route",
            "source",
            "install",
            "transport",
            "requires_kit",
            "content_inventory_digest",
            "capabilities",
        ]
        .contains(&key.as_str())
        {
            continue;
        }
        if let Some(value) = manifest.get(key) {
            seat::node(rule, value, "B", &format!("manifest.{key}"))?;
        }
    }
    // C: the loaded slug/semver expressions and literal identity relation.
    for key in ["id", "version", "proxy_route"] {
        seat::field(XENIA, key, &manifest[key], "C", &format!("manifest.{key}"))?;
    }
    let id = manifest["id"]
        .as_str()
        .ok_or_else(|| refuse("C", "manifest.id", "id-string-required"))?;
    if manifest["proxy_route"].as_str() != Some(format!("/api/tabs/{id}").as_str()) {
        return Err(refuse("C", "manifest.proxy_route", "proxy-id-mismatch"));
    }
    if let Some(unit) = manifest["install"]["unit"].as_str() {
        if unit != format!("{id}.service") {
            return Err(refuse("C", "manifest.install.unit", "unit-id-mismatch"));
        }
    }
    for path in ["id", "slug"] {
        if body
            .get(path)
            .is_some_and(|value| value.as_str() != Some(id))
            || manifest
                .get("slug")
                .is_some_and(|value| value.as_str() != Some(id))
        {
            return Err(refuse("C", path, "identity-mismatch"));
        }
    }
    // D: the new outcome seat governs only this proposed row.
    let row = body
        .get("tabs")
        .ok_or_else(|| refuse("D", "tabs", "proposed-row-absent"))?
        .clone();
    seat::field(VERDICT, "tabs", &row, "D", "tabs")?;
    forbidden(&row, policy_keys("forbidden_row_keys")?, "D", "tabs")?;
    let mut entry = manifest.clone();
    let object = entry
        .as_object_mut()
        .ok_or_else(|| refuse("B", "manifest", "manifest-object-required"))?;
    if let Some(body) = body.as_object() {
        for (key, value) in body {
            if key.starts_with("x-household") {
                object.insert(key.clone(), value.clone());
            }
        }
    }
    if let Some(choices) = body.get("choices") {
        if !choices.is_object() {
            return Err(refuse("D", "choices", "choices-object-required"));
        }
        // Preserve the original choices envelope, including household extensions.
        object.insert("choices".into(), choices.clone());
    }
    for key in ["enabled", "priority"] {
        let value = body
            .get("choices")
            .and_then(|choices| choices.get(key))
            .or_else(|| body.get(key))
            .cloned()
            .unwrap_or_else(|| fields[key]["default"].clone());
        seat::field(XENIA, key, &value, "D", &format!("choices.{key}"))?;
        object.insert(key.into(), value);
    }
    object.insert("granted".into(), json!([]));
    let own = house.register["xenoi"].get(id);
    if let Some(existing) = own {
        if !declaration_equal(existing, &entry)? {
            return Err(refuse("D", "id", "owned-entry-differs"));
        }
    } else if house.config["tabs"].get(id).is_some() {
        return Err(refuse("D", "tabs", "tab-id-already-claimed"));
    }
    if let Some(existing_row) = house.config["tabs"].get(id) {
        if own.is_some() && existing_row != &row {
            return Err(refuse("D", "tabs", "owned-row-differs"));
        }
    }
    let registry = registry()?;
    for (other, row) in &registry {
        if other != id {
            continue;
        }
        // An admitted own guest may occur in the dynamic readback, but never
        // licenses a native or first-party declaration with the same id.
        let guest = row.get("xenia").and_then(Value::as_bool) == Some(true)
            || row.get("origin").and_then(Value::as_str) == Some("xenia")
            || row
                .get("xeniaEntry")
                .is_some_and(|entry| own == Some(entry));
        if own.is_none() || !guest {
            return Err(refuse("D", "id", "native-or-shipped-id-collision"));
        }
    }
    // E and F: the clone road declares a repository; it never executes git.
    let clone = source(manifest)?;
    forbidden(
        manifest,
        policy_keys("forbidden_instructions")?,
        "F",
        "manifest",
    )?;
    if !manifest["install"]["unit"].is_null() {
        return Err(refuse(
            "F",
            "manifest.install.unit",
            "manifest-unit-forbidden",
        ));
    }
    let clone_digest_placeholder = "0".repeat(64);
    if clone
        && manifest["content_inventory_digest"].as_str()
            != Some(clone_digest_placeholder.as_str())
    {
        return Err(refuse(
            "F",
            "manifest.content_inventory_digest",
            "clone-digest-not-applicable",
        ));
    }
    seat::field(
        XENIA,
        "content_inventory_digest",
        &manifest["content_inventory_digest"],
        "F",
        "manifest.content_inventory_digest",
    )?;
    inventory_claims(&manifest["install"], "manifest.install")?;
    if let Some(inventory) = manifest.get("inventory") {
        inventory_claims(inventory, "manifest.inventory")?;
    }
    if clone {
        check_permissions(id)?;
    }
    let release = if clone {
        json!({"road": "clone", "host": "git.home.arpa", "release": null})
    } else {
        remote::release(manifest)?
    };
    // G, H, I and J, in that order.
    install(manifest, id)?;
    seat::field(
        XENIA,
        "transport",
        &manifest["transport"],
        "H",
        "manifest.transport",
    )?;
    let listeners = claims(manifest, &house, &registry, own.is_some())?;
    seat::field(
        XENIA,
        "capabilities",
        &manifest["capabilities"],
        "I",
        "manifest.capabilities",
    )?;
    let requested = manifest["capabilities"]
        .as_array()
        .ok_or_else(|| refuse("I", "capabilities", "capabilities-array-required"))?;
    let mut granted = Vec::new();
    for capability in requested {
        let command = capability
            .as_str()
            .ok_or_else(|| refuse("I", "capabilities", "capability-string-required"))?;
        match policy::allows_command(command) {
            Ok(true) => granted.push(capability.clone()),
            Ok(false) => return Err(refuse("I", command, "capability-not-granted")),
            Err(error) => return Err(observation("I", command, error)),
        }
    }
    entry["granted"] = json!(granted);
    compatibility(manifest)?;
    if let Some(existing) = own {
        if store::same_declaration(existing, &entry) {
            entry = existing.clone();
        } else {
            return Err(refuse("I", "granted", "existing-grant-differs"));
        }
    }
    seat::form(XENIA, Some("entry"), &entry, "B", "entry")?;
    Ok(Candidate {
        house,
        entry,
        row,
        observed: json!({"health": health, "release": release, "listeners": listeners}),
    })
}
