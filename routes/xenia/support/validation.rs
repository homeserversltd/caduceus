use super::{observation, observe, remote, seat, store, Refusal, Result, VERDICT, XENIA};
use crate::shared::policy;
use serde_json::{json, Value};
use std::path::{Component, Path};

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

fn source(manifest: &Value) -> Result<()> {
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
    Ok(())
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

fn install(manifest: &Value, id: &str) -> Result<()> {
    let install = &manifest["install"];
    if install.is_null() {
        return Ok(());
    }
    seat::field(XENIA, "install", install, "G", "manifest.install")?;
    let kind = manifest["kind"].as_str().unwrap_or("");
    if kind == "iframe" {
        return Ok(());
    } // C3 owns the lawful iframe shape.
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
    // E and F: never clone, execute an instruction or fetch a binary.
    source(manifest)?;
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
    let release = remote::release(manifest)?;
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
