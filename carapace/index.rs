use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default)]
pub struct Resolution {
    pub lit: BTreeSet<String>,
}

fn feature_map(model: &Value) -> Result<&serde_json::Map<String, Value>, String> {
    model
        .get("features")
        .and_then(Value::as_object)
        .ok_or_else(|| "carapace-model-features-invalid".to_string())
}

fn strings(value: Option<&Value>) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(values) = value.as_array() else {
        return Err("carapace-model-string-list-invalid".to_string());
    };
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "carapace-model-string-list-invalid".to_string())
        })
        .collect()
}

fn string_groups(value: Option<&Value>) -> Result<Vec<Vec<String>>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(groups) = value.as_array() else {
        return Err("carapace-model-string-groups-invalid".to_string());
    };
    groups.iter().map(|group| strings(Some(group))).collect()
}

fn require_known(ids: &[String], known: &BTreeSet<String>, label: &str) -> Result<(), String> {
    for id in ids {
        if !known.contains(id) {
            return Err(format!("{label}-unknown:{id}"));
        }
    }
    Ok(())
}

fn walk_feature_tree(
    id: &str,
    features: &serde_json::Map<String, Value>,
    visiting: &mut BTreeSet<String>,
    reached: &mut BTreeSet<String>,
) -> Result<(), String> {
    if visiting.contains(id) {
        return Err(format!("carapace-feature-tree-cycle:{id}"));
    }
    if reached.contains(id) {
        return Ok(());
    }
    let feature = features
        .get(id)
        .ok_or_else(|| format!("carapace-feature-unknown:{id}"))?;
    visiting.insert(id.to_owned());
    for child in strings(feature.get("children"))? {
        walk_feature_tree(&child, features, visiting, reached)?;
    }
    visiting.remove(id);
    reached.insert(id.to_owned());
    Ok(())
}

fn walk_feature_targets(
    id: &str,
    field: &str,
    features: &serde_json::Map<String, Value>,
    visiting: &mut BTreeSet<String>,
    visited: &mut BTreeSet<String>,
) -> Result<(), String> {
    if visiting.contains(id) {
        return Err(format!("carapace-{field}-cycle:{id}"));
    }
    if visited.contains(id) {
        return Ok(());
    }
    let feature = features
        .get(id)
        .ok_or_else(|| format!("carapace-feature-unknown:{id}"))?;
    visiting.insert(id.to_owned());
    for target in strings(feature.get(field))? {
        walk_feature_targets(&target, field, features, visiting, visited)?;
    }
    visiting.remove(id);
    visited.insert(id.to_owned());
    Ok(())
}

fn validate_model(model: &Value) -> Result<(), String> {
    if model.get("schema").and_then(Value::as_str) != Some("caduceus.carapace.model.v1") {
        return Err("carapace-model-schema-invalid".to_string());
    }
    let features = feature_map(model)?;
    let known = features.keys().cloned().collect::<BTreeSet<_>>();
    if known.is_empty() {
        return Err("carapace-model-features-empty".to_string());
    }

    for (id, feature) in features {
        if let Some(mandatory) = feature.get("mandatory") {
            if mandatory.as_bool().is_none() {
                return Err(format!("carapace-feature-mandatory-invalid:{id}"));
            }
        }
        for field in ["children", "requires", "select", "imply", "default_if"] {
            let values = strings(feature.get(field))?;
            require_known(&values, &known, &format!("carapace-{field}-target"))?;
        }
        for group in string_groups(feature.get("requires_any"))? {
            require_known(&group, &known, "carapace-requires-any-target")?;
        }
        if let Some(parent) = feature.get("parent") {
            let parent = parent
                .as_str()
                .ok_or_else(|| format!("carapace-feature-parent-invalid:{id}"))?;
            if !known.contains(parent) {
                return Err(format!("carapace-feature-parent-unknown:{id}:{parent}"));
            }
        }
    }

    let roots = strings(model.get("roots"))?;
    if roots.is_empty() {
        return Err("carapace-model-roots-empty".to_string());
    }
    let mut root_set = BTreeSet::new();
    for root in &roots {
        if !root_set.insert(root.clone()) {
            return Err(format!("carapace-model-root-duplicate:{root}"));
        }
        if !known.contains(root) {
            return Err(format!("carapace-model-root-unknown:{root}"));
        }
        if features
            .get(root)
            .and_then(|feature| feature.get("parent"))
            .is_some()
        {
            return Err(format!("carapace-root-has-parent:{root}"));
        }
    }
    for (id, feature) in features {
        let children = strings(feature.get("children"))?;
        let child_set = children.iter().cloned().collect::<BTreeSet<_>>();
        if child_set.len() != children.len() {
            return Err(format!("carapace-feature-child-duplicate:{id}"));
        }
        for child in children {
            let observed_parent = features
                .get(&child)
                .and_then(|child_feature| child_feature.get("parent"))
                .and_then(Value::as_str);
            if observed_parent != Some(id.as_str()) {
                return Err(format!("carapace-parent-child-mismatch:{id}:{child}"));
            }
        }
        match feature.get("parent") {
            Some(parent) => {
                let parent = parent.as_str().expect("validated parent string");
                if root_set.contains(id) {
                    return Err(format!("carapace-parent-is-root:{id}"));
                }
                let siblings = strings(
                    features
                        .get(parent)
                        .and_then(|parent_feature| parent_feature.get("children")),
                )?;
                if !siblings.iter().any(|child| child == id) {
                    return Err(format!("carapace-parent-child-mismatch:{parent}:{id}"));
                }
            }
            None if !root_set.contains(id) => {
                return Err(format!("carapace-feature-disconnected:{id}"));
            }
            None => {}
        }
    }
    let mut reached = BTreeSet::new();
    let mut visiting = BTreeSet::new();
    for root in &roots {
        walk_feature_tree(root, features, &mut visiting, &mut reached)?;
    }
    if let Some(disconnected) = known.iter().find(|id| !reached.contains(*id)) {
        walk_feature_tree(disconnected, features, &mut visiting, &mut reached)?;
        return Err(format!("carapace-feature-disconnected:{disconnected}"));
    }
    for field in ["select", "imply"] {
        let mut visited = BTreeSet::new();
        let mut visiting = BTreeSet::new();
        for id in &known {
            walk_feature_targets(id, field, features, &mut visiting, &mut visited)?;
        }
    }

    if let Some(relations) = model.get("relations") {
        let relations = relations
            .as_array()
            .ok_or_else(|| "carapace-relations-invalid".to_string())?;
        for relation in relations {
            match relation.get("kind").and_then(Value::as_str) {
                Some("imply") => {
                    let from = relation
                        .get("from")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "carapace-imply-source-invalid".to_string())?;
                    let to = relation
                        .get("to")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "carapace-imply-target-invalid".to_string())?;
                    require_known(&[from.to_owned()], &known, "carapace-imply-source")?;
                    require_known(&[to.to_owned()], &known, "carapace-imply-target")?;
                }
                Some("default_if") => {
                    let feature = relation
                        .get("feature")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "carapace-default-feature-invalid".to_string())?;
                    require_known(&[feature.to_owned()], &known, "carapace-default-feature")?;
                    let required = strings(Some(
                        relation
                            .get("all")
                            .ok_or_else(|| "carapace-default-all-missing".to_string())?,
                    ))?;
                    if required.is_empty() {
                        return Err("carapace-default-all-empty".to_string());
                    }
                    require_known(&required, &known, "carapace-default-target")?;
                }
                Some(other) => return Err(format!("carapace-relation-kind-unsupported:{other}")),
                None => return Err("carapace-relation-kind-invalid".to_string()),
            }
        }
    }

    if let Some(choices) = model.get("choices") {
        let choices = choices
            .as_array()
            .ok_or_else(|| "carapace-choices-invalid".to_string())?;
        let mut owners = BTreeSet::new();
        let mut grouped = BTreeSet::new();
        for choice in choices {
            let owner = choice
                .get("owner")
                .and_then(Value::as_str)
                .ok_or_else(|| "carapace-choice-owner-invalid".to_string())?;
            require_known(&[owner.to_owned()], &known, "carapace-choice-owner")?;
            if !owners.insert(owner.to_owned()) {
                return Err(format!("carapace-choice-owner-duplicate:{owner}"));
            }
            let kind = choice
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| "carapace-choice-kind-invalid".to_string())?;
            if kind != "or" && kind != "xor" {
                return Err(format!("carapace-choice-kind-unsupported:{kind}"));
            }
            let members = strings(choice.get("features"))?;
            if members.is_empty() {
                return Err(format!("carapace-choice-empty:{owner}"));
            }
            let member_set = members.iter().cloned().collect::<BTreeSet<_>>();
            if member_set.len() != members.len() {
                return Err(format!("carapace-choice-member-duplicate:{owner}"));
            }
            require_known(&members, &known, "carapace-choice-member")?;
            for member in &members {
                if features
                    .get(member)
                    .and_then(|member_feature| member_feature.get("parent"))
                    .and_then(Value::as_str)
                    != Some(owner)
                {
                    return Err(format!("carapace-choice-owner-child-mismatch:{owner}:{member}"));
                }
                if !grouped.insert(member.clone()) {
                    return Err(format!("carapace-choice-member-reused:{member}"));
                }
            }
            let defaults = match choice.get("default") {
                Some(Value::String(default)) => vec![default.clone()],
                Some(value) => strings(Some(value))?,
                None => return Err(format!("carapace-choice-default-missing:{owner}")),
            };
            if defaults.is_empty() || (kind == "xor" && defaults.len() != 1) {
                return Err(format!("carapace-choice-default-invalid:{owner}"));
            }
            let default_set = defaults.iter().cloned().collect::<BTreeSet<_>>();
            if default_set.len() != defaults.len() {
                return Err(format!("carapace-choice-default-duplicate:{owner}"));
            }
            for default in defaults {
                if !members.contains(&default) {
                    return Err(format!("carapace-choice-default-outside-group:{owner}:{default}"));
                }
            }
        }
    }
    Ok(())
}

fn requirements_met(feature: &Value, lit: &BTreeSet<String>) -> Result<bool, String> {
    let required = strings(feature.get("requires"))?;
    if !required.iter().all(|id| lit.contains(id)) {
        return Ok(false);
    }
    for members in string_groups(feature.get("requires_any"))? {
        if !members.iter().any(|id| lit.contains(id)) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn parent_is_lit(feature: &Value, lit: &BTreeSet<String>) -> bool {
    feature
        .get("parent")
        .and_then(Value::as_str)
        .map_or(true, |parent| lit.contains(parent))
}

fn add_select_closure(
    model: &Value,
    lit: &mut BTreeSet<String>,
) -> Result<bool, String> {
    let features = feature_map(model)?;
    let mut changed = false;
    loop {
        let before = lit.len();
        let current = lit.iter().cloned().collect::<Vec<_>>();
        for id in current {
            let feature = features
                .get(&id)
                .ok_or_else(|| format!("carapace-feature-unknown:{id}"))?;
            for selected in strings(feature.get("select"))? {
                if !features.contains_key(&selected) {
                    return Err(format!("carapace-select-target-unknown:{id}:{selected}"));
                }
                lit.insert(selected);
            }
        }
        if lit.len() == before {
            break;
        }
        changed = true;
    }
    Ok(changed)
}

fn add_wildcard_tree(
    id: &str,
    features: &serde_json::Map<String, Value>,
    choice_members: &BTreeSet<String>,
    blocked: &BTreeSet<String>,
    lit: &mut BTreeSet<String>,
) -> Result<bool, String> {
    let feature = features
        .get(id)
        .ok_or_else(|| format!("carapace-feature-unknown:{id}"))?;
    if !lit.contains(id) && (choice_members.contains(id) || blocked.contains(id)) {
        return Ok(false);
    }
    let mut changed = false;
    if !choice_members.contains(id) && !blocked.contains(id) && lit.insert(id.to_owned()) {
        changed = true;
    }
    if lit.contains(id) {
        for child in strings(feature.get("children"))? {
            changed |= add_wildcard_tree(&child, features, choice_members, blocked, lit)?;
        }
    }
    Ok(changed)
}

fn add_wildcard_closure(
    model: &Value,
    features: &serde_json::Map<String, Value>,
    choice_members: &BTreeSet<String>,
    blocked: &BTreeSet<String>,
    lit: &mut BTreeSet<String>,
) -> Result<bool, String> {
    let roots = strings(model.get("roots"))?;
    let mut changed = false;
    for root in roots {
        changed |= add_wildcard_tree(&root, features, choice_members, blocked, lit)?;
    }
    Ok(changed)
}

fn choice_defaults(
    model: &Value,
    lit: &mut BTreeSet<String>,
    blocked: &BTreeSet<String>,
) -> Result<bool, String> {
    let mut changed = false;
    let Some(value) = model.get("choices") else {
        return Ok(false);
    };
    let choices = value
        .as_array()
        .ok_or_else(|| "carapace-choices-invalid".to_string())?;
    for choice in choices {
        let owner = choice
            .get("owner")
            .and_then(Value::as_str)
            .ok_or_else(|| "carapace-choice-owner-invalid".to_string())?;
        if !lit.contains(owner) {
            continue;
        }
        let kind = choice
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| "carapace-choice-kind-invalid".to_string())?;
        if kind != "or" && kind != "xor" {
            return Err(format!("carapace-choice-kind-unsupported:{kind}"));
        }
        let members = strings(choice.get("features"))?;
        if members.is_empty() {
            return Err(format!("carapace-choice-empty:{owner}"));
        }
        let active = members.iter().filter(|id| lit.contains(*id)).count();
        if kind == "xor" && active > 1 {
            return Err(format!("carapace-choice-xor-conflict:{owner}"));
        }
        if active == 0 {
            let defaults = choice.get("default").ok_or_else(|| {
                format!("carapace-choice-default-missing:{owner}")
            })?;
            let defaults = if let Some(default) = defaults.as_str() {
                vec![default.to_owned()]
            } else {
                strings(Some(defaults))?
            };
            if defaults.is_empty() || (kind == "xor" && defaults.len() != 1) {
                return Err(format!("carapace-choice-default-invalid:{owner}"));
            }
            for default in defaults {
                if !members.contains(&default) {
                    return Err(format!("carapace-choice-default-outside-group:{owner}:{default}"));
                }
                if !blocked.contains(&default) && lit.insert(default) {
                    changed = true;
                }
            }
        }
    }
    Ok(changed)
}

fn apply_defaults_and_implies(
    model: &Value,
    lit: &mut BTreeSet<String>,
    blocked: &BTreeSet<String>,
) -> Result<bool, String> {
    let features = feature_map(model)?;
    let mut changed = false;
    let mut implications = Vec::<(String, String)>::new();
    for (id, feature) in features {
        for target in strings(feature.get("imply"))? {
            implications.push((id.clone(), target));
        }
        if feature.get("mandatory").and_then(Value::as_bool) == Some(true) {
            if blocked.contains(id) {
                return Err(format!("carapace-mandatory-feature-disabled:{id}"));
            }
            if lit.insert(id.clone()) {
                changed = true;
            }
        }
        if let Some(required) = feature.get("default_if") {
            let required = strings(Some(required))?;
            if !blocked.contains(id)
                && parent_is_lit(feature, lit)
                && required.iter().all(|need| lit.contains(need))
                && lit.insert(id.clone())
            {
                changed = true;
            }
        }
    }
    if let Some(relations) = model.get("relations") {
        let relations = relations
            .as_array()
            .ok_or_else(|| "carapace-relations-invalid".to_string())?;
        for relation in relations {
            match relation.get("kind").and_then(Value::as_str) {
                Some("imply") => {
                    let from = relation
                        .get("from")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "carapace-imply-source-invalid".to_string())?;
                    let to = relation
                        .get("to")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "carapace-imply-target-invalid".to_string())?;
                    implications.push((from.to_owned(), to.to_owned()));
                }
                Some("default_if") => {
                    let feature = relation
                        .get("feature")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "carapace-default-feature-invalid".to_string())?;
                    let required = strings(relation.get("all"))?;
                    let target = features
                        .get(feature)
                        .ok_or_else(|| format!("carapace-default-feature-unknown:{feature}"))?;
                    if !blocked.contains(feature)
                        && parent_is_lit(target, lit)
                        && required.iter().all(|need| lit.contains(need))
                        && lit.insert(feature.to_owned())
                    {
                        changed = true;
                    }
                }
                Some(other) => return Err(format!("carapace-relation-kind-unsupported:{other}")),
                None => return Err("carapace-relation-kind-invalid".to_string()),
            }
        }
    }
    for (source, target) in implications {
        if !lit.contains(&source) {
            continue;
        }
        let target_feature = features
            .get(&target)
            .ok_or_else(|| format!("carapace-imply-target-unknown:{source}:{target}"))?;
        if !blocked.contains(&target)
            && parent_is_lit(target_feature, lit)
            && requirements_met(target_feature, lit)?
            && lit.insert(target)
        {
            changed = true;
        }
    }
    Ok(changed)
}

pub fn resolve(model: &Value, answers: &[String]) -> Result<Resolution, String> {
    validate_model(model)?;
    let features = feature_map(model)?;
    let mut lit = BTreeSet::new();
    let mut explicit = BTreeMap::<String, bool>::new();
    let mut wildcard = false;
    for answer in answers {
        if answer == "*" {
            if wildcard {
                return Err("carapace-defconfig-answer-duplicate:*".to_string());
            }
            wildcard = true;
            continue;
        }
        let (id, enabled) = match answer.split_once('=') {
            Some((id, "y")) => (id, true),
            Some((id, "n")) => (id, false),
            Some(_) => return Err(format!("carapace-defconfig-answer-invalid:{answer}")),
            None => (answer.as_str(), true),
        };
        if id.is_empty() || !features.contains_key(id) {
            return Err(format!("carapace-defconfig-feature-unknown:{id}"));
        }
        if let Some(previous) = explicit.insert(id.to_owned(), enabled) {
            let reason = if previous == enabled { "duplicate" } else { "conflict" };
            return Err(format!("carapace-defconfig-answer-{reason}:{id}"));
        }
    }
    let mut blocked = BTreeSet::new();
    for (id, enabled) in &explicit {
        if *enabled {
            lit.insert(id.clone());
        } else {
            if features
                .get(id)
                .and_then(|feature| feature.get("mandatory"))
                .and_then(Value::as_bool)
                == Some(true)
            {
                return Err(format!("carapace-mandatory-feature-disabled:{id}"));
            }
            blocked.insert(id.clone());
        }
    }
    for (id, feature) in features {
        if feature.get("mandatory").and_then(Value::as_bool) == Some(true) {
            lit.insert(id.clone());
        }
    }
    let mut choice_members = BTreeSet::new();
    if let Some(choices) = model.get("choices").and_then(Value::as_array) {
        for choice in choices {
            choice_members.extend(strings(choice.get("features"))?);
        }
    }

    loop {
        let mut changed = if wildcard {
            add_wildcard_closure(model, features, &choice_members, &blocked, &mut lit)?
        } else {
            false
        };
        changed |= add_select_closure(model, &mut lit)?;
        changed |= apply_defaults_and_implies(model, &mut lit, &blocked)?;
        changed |= choice_defaults(model, &mut lit, &blocked)?;
        if !changed {
            break;
        }
    }
    add_select_closure(model, &mut lit)?;

    for (id, feature) in features {
        if !lit.contains(id) {
            continue;
        }
        if let Some(parent) = feature.get("parent").and_then(Value::as_str) {
            if !lit.contains(parent) {
                return Err(format!("carapace-parent-not-lit:{id}:{parent}"));
            }
        }
        let required = strings(feature.get("requires"))?;
        if !required.iter().all(|need| lit.contains(need)) {
            return Err(format!("carapace-requires-unsatisfied:{id}"));
        }
        for members in string_groups(feature.get("requires_any"))? {
            if !members.iter().any(|need| lit.contains(need)) {
                return Err(format!("carapace-requires-or-unsatisfied:{id}"));
            }
        }
    }
    if let Some(choices) = model.get("choices").and_then(Value::as_array) {
        for choice in choices {
            let owner = choice["owner"].as_str().expect("validated choice owner");
            if !lit.contains(owner) {
                continue;
            }
            let kind = choice["kind"].as_str().expect("validated choice kind");
            let members = strings(choice.get("features"))?;
            let active = members.iter().filter(|id| lit.contains(*id)).count();
            if kind == "xor" && active > 1 {
                return Err(format!("carapace-choice-xor-conflict:{owner}"));
            }
            if active == 0 {
                return Err(format!("carapace-choice-unselected:{owner}"));
            }
        }
    }
    Ok(Resolution { lit })
}

pub fn needs_met(entry: &Value, resolution: &Resolution) -> Result<bool, String> {
    let needs = strings(entry.get("needs"))?;
    if !needs.iter().all(|id| resolution.lit.contains(id)) {
        return Ok(false);
    }
    let any = strings(entry.get("needs_any"))?;
    Ok(any.is_empty() || any.iter().any(|id| resolution.lit.contains(id)))
}

fn operations(entry: &Value) -> Result<&[Value], String> {
    match entry.get("operations") {
        None => Ok(&[]),
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| "carapace-operations-invalid".to_string()),
    }
}

pub fn route_is_lit(entry: &Value, resolution: &Resolution) -> Result<bool, String> {
    if needs_met(entry, resolution)? {
        return Ok(true);
    }
    for operation in operations(entry)? {
        if needs_met(operation, resolution)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn command_names(value: Option<&Value>, resolution: &Resolution) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Some(commands) = value.as_array() else {
        return Err("carapace-command-list-invalid".to_string());
    };
    let mut out = Vec::new();
    for command in commands {
        if let Some(command) = command.as_str() {
            out.push(command.to_owned());
            continue;
        }
        let Some(object) = command.as_object() else {
            return Err("carapace-command-invalid".to_string());
        };
        if !needs_met(command, resolution)? {
            continue;
        }
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| "carapace-command-name-invalid".to_string())?;
        out.push(name.to_owned());
    }
    Ok(out)
}

pub fn commands_for_leaf(entry: &Value, resolution: &Resolution) -> Result<Vec<String>, String> {
    let mut commands = if needs_met(entry, resolution)? {
        command_names(entry.get("commands"), resolution)?
    } else {
        Vec::new()
    };
    for operation in operations(entry)? {
        if needs_met(operation, resolution)? {
            commands.extend(command_names(operation.get("commands"), resolution)?);
        }
    }
    commands.sort();
    commands.dedup();
    Ok(commands)
}

fn attach_door(
    doors: &mut BTreeMap<String, BTreeSet<String>>,
    feature: &str,
    label: String,
) {
    doors.entry(feature.to_owned()).or_default().insert(label);
}

fn attach_endpoint(
    doors: &mut BTreeMap<String, BTreeSet<String>>,
    label: &str,
    entry: &Value,
    resolution: &Resolution,
) -> Result<(), String> {
    let needs = strings(entry.get("needs"))?;
    let any = strings(entry.get("needs_any"))?;
    let needs_lit = needs.iter().all(|id| resolution.lit.contains(id));
    let any_lit = any.is_empty() || any.iter().any(|id| resolution.lit.contains(id));
    let endpoint_lit = needs_lit && any_lit;
    if needs.is_empty() && any.is_empty() {
        let status = if endpoint_lit { "lit" } else { "dark" };
        attach_door(doors, "all", format!("{label} [{status}]"));
    }
    for id in needs {
        let status = if endpoint_lit { "lit" } else { "dark" };
        attach_door(doors, &id, format!("{label} [{status}]"));
    }
    for id in any {
        let status = if needs_lit && resolution.lit.contains(&id) {
            "lit"
        } else {
            "dark"
        };
        attach_door(doors, &id, format!("{label} [{status}]"));
    }
    Ok(())
}

pub fn render_tree(model: &Value, resolution: &Resolution, leaves: &[Value]) -> Result<String, String> {
    validate_model(model)?;
    let features = feature_map(model)?;
    let mut doors = BTreeMap::<String, BTreeSet<String>>::new();
    for entry in leaves {
        let namespace = entry
            .get("namespace")
            .and_then(Value::as_str)
            .ok_or_else(|| "carapace-route-namespace-invalid".to_string())?;
        attach_endpoint(
            &mut doors,
            &format!("/api/v1/{namespace}"),
            entry,
            resolution,
        )?;
        for operation in operations(entry)? {
            let method = operation
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("*");
            let path = operation
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or(namespace);
            attach_endpoint(
                &mut doors,
                &format!("{method} {path}"),
                operation,
                resolution,
            )?;
        }
    }

    fn visit(
        id: &str,
        depth: usize,
        features: &serde_json::Map<String, Value>,
        resolution: &Resolution,
        doors: &BTreeMap<String, BTreeSet<String>>,
        visited: &mut BTreeSet<String>,
        out: &mut String,
    ) -> Result<(), String> {
        if !visited.insert(id.to_owned()) {
            return Ok(());
        }
        let feature = features
            .get(id)
            .ok_or_else(|| format!("carapace-tree-feature-unknown:{id}"))?;
        let lit = if resolution.lit.contains(id) { "lit" } else { "dark" };
        out.push_str(&format!("{}{} [{lit}]\n", "  ".repeat(depth), id));
        if let Some(feature_doors) = doors.get(id) {
            for door in feature_doors {
                out.push_str(&format!("{}{}\n", "  ".repeat(depth + 1), door));
            }
        }
        for child in strings(feature.get("children"))? {
            visit(&child, depth + 1, features, resolution, doors, visited, out)?;
        }
        Ok(())
    }

    let mut out = String::new();
    let profile = model
        .get("profile")
        .and_then(Value::as_str)
        .unwrap_or("resolved");
    out.push_str(&format!("Carapace {profile}\n"));
    let roots = strings(model.get("roots"))?;
    let mut visited = BTreeSet::new();
    for root in roots {
        visit(&root, 0, features, resolution, &doors, &mut visited, &mut out)?;
    }
    for id in features.keys() {
        if !visited.contains(id) {
            visit(id, 0, features, resolution, &doors, &mut visited, &mut out)?;
        }
    }
    Ok(out)
}

pub fn show_tree<F>(profile: &str, tree_for: F) -> i32
where
    F: Fn(&str) -> Option<&'static str>,
{
    match tree_for(profile) {
        Some(tree) => {
            print!("{tree}");
            0
        }
        None => {
            eprintln!("caduceus-profile-unknown:{profile}");
            2
        }
    }
}
