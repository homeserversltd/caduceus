use super::{observation, Refusal, Result};
use serde_json::Value;
use std::ffi::CString;

pub fn declaration(id: &str) -> Result<&'static Value> {
    crate::routes::leaf_schema::declaration(id).ok_or_else(|| {
        observation(
            "schema",
            id,
            format!("xenia-schema-desync: startup seat {id} absent"),
        )
    })
}

fn matches_type(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "string" => value.is_string(),
        "object" => value.is_object(),
        "array" => value.is_array(),
        "boolean" => value.is_boolean(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        _ => true,
    }
}

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

struct Pattern(Box<libc::regex_t>);
// regcomp owns its allocation, no pointers borrow Rust data. All regexec calls
// are serialized by PATTERNS; the compiled expression is never mutated or moved.
unsafe impl Send for Pattern {}
impl Drop for Pattern {
    fn drop(&mut self) {
        unsafe {
            libc::regfree(self.0.as_mut());
        }
    }
}
type Patterns = BTreeMap<String, std::result::Result<Pattern, String>>;
static PATTERNS: OnceLock<Mutex<Patterns>> = OnceLock::new();
static STARTUP: OnceLock<std::result::Result<(), String>> = OnceLock::new();

fn compile(pattern: &str) -> std::result::Result<Pattern, String> {
    let text = CString::new(pattern).map_err(|_| "schema-pattern-NUL")?;
    let mut storage = Box::<libc::regex_t>::new_uninit();
    let code = unsafe {
        libc::regcomp(
            storage.as_mut_ptr(),
            text.as_ptr(),
            libc::REG_EXTENDED | libc::REG_NOSUB,
        )
    };
    if code != 0 {
        return Err(format!(
            "schema-pattern-desync: pattern={pattern} regcomp={code}"
        ));
    }
    Ok(Pattern(unsafe { storage.assume_init() }))
}

fn collect(rule: &Value, patterns: &mut Patterns) {
    match rule {
        Value::Object(fields) => {
            if let Some(pattern) = fields.get("pattern").and_then(Value::as_str) {
                if !patterns.contains_key(pattern) {
                    patterns.insert(pattern.into(), compile(pattern));
                }
            }
            for value in fields.values() {
                collect(value, patterns);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect(value, patterns);
            }
        }
        _ => {}
    }
}

pub fn startup() -> std::result::Result<(), String> {
    STARTUP
        .get_or_init(|| {
            let mut patterns = BTreeMap::new();
            let mut errors = Vec::new();
            for id in [
                super::XENIA,
                super::VERDICT,
                "estate.release-flag.v1",
                "coronatio.face-surface.v1",
            ] {
                match crate::routes::leaf_schema::declaration(id) {
                    Some(seat) => collect(seat, &mut patterns),
                    None => errors.push(format!("xenia-schema-desync: startup seat {id} absent")),
                }
            }
            for value in patterns.values() {
                if let Err(error) = value {
                    errors.push(error.clone());
                }
            }
            let _ = PATTERNS.set(Mutex::new(patterns));
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        })
        .clone()
}

fn pattern_matches(pattern: &str, text: &str) -> std::result::Result<bool, String> {
    let text = CString::new(text).map_err(|_| "value-pattern-NUL")?;
    let patterns = PATTERNS
        .get()
        .ok_or("schema-pattern-startup-absent")?
        .lock()
        .map_err(|_| "schema-pattern-lock-poisoned")?;
    let compiled = patterns
        .get(pattern)
        .ok_or("schema-pattern-seat-desync")?
        .as_ref()
        .map_err(Clone::clone)?;
    let code = unsafe {
        libc::regexec(
            compiled.0.as_ref(),
            text.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    if code == 0 {
        Ok(true)
    } else if code == libc::REG_NOMATCH {
        Ok(false)
    } else {
        Err(format!("schema-pattern-observation-failed: regexec={code}"))
    }
}

fn fault(check: &str, path: &str, message: impl Into<String>) -> Refusal {
    Refusal::new(
        check,
        path,
        message,
        "Supply the value declared by the loaded public seat.",
    )
}

pub fn node(rule: &Value, value: &Value, check: &str, path: &str) -> Result<()> {
    if let Some(id) = rule.get("schema_ref").and_then(Value::as_str) {
        form(
            id,
            rule.get("form").and_then(Value::as_str),
            value,
            check,
            path,
        )?;
    }
    if let Some(kind) = rule.get("type") {
        let allowed = match kind {
            Value::String(kind) => matches_type(kind, value),
            Value::Array(kinds) => kinds
                .iter()
                .filter_map(Value::as_str)
                .any(|kind| matches_type(kind, value)),
            _ => return Err(observation(check, path, "schema-type-declaration-desync")),
        };
        if !allowed {
            return Err(fault(check, path, "declared-type-mismatch"));
        }
    }
    if let Some(expected) = rule.get("const") {
        if value != expected {
            return Err(fault(check, path, "declared-constant-mismatch"));
        }
    }
    if let Some(allowed) = rule.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            return Err(fault(check, path, "declared-vocabulary-mismatch"));
        }
    }
    if let Some(text) = value.as_str() {
        let length = text.chars().count() as u64;
        if rule
            .get("minLength")
            .and_then(Value::as_u64)
            .is_some_and(|min| length < min)
            || rule
                .get("maxLength")
                .and_then(Value::as_u64)
                .is_some_and(|max| length > max)
        {
            return Err(fault(check, path, "declared-length-mismatch"));
        }
        if let Some(pattern) = rule.get("pattern").and_then(Value::as_str) {
            if !pattern_matches(pattern, text).map_err(|error| observation(check, path, error))? {
                return Err(fault(check, path, "declared-pattern-mismatch"));
            }
        }
    }
    if let Some(number) = value.as_f64() {
        if rule
            .get("minimum")
            .and_then(Value::as_f64)
            .is_some_and(|min| number < min)
            || rule
                .get("maximum")
                .and_then(Value::as_f64)
                .is_some_and(|max| number > max)
        {
            return Err(fault(check, path, "declared-range-mismatch"));
        }
    }
    if let Some(fields) = rule.get("required").and_then(Value::as_array) {
        for name in fields.iter().filter_map(Value::as_str) {
            if value.get(name).is_none() {
                return Err(fault(
                    check,
                    &format!("{path}.{name}"),
                    "missing-frozen-kernel",
                ));
            }
        }
    }
    if let Some(fields) = rule.get("forbidden").and_then(Value::as_array) {
        for name in fields.iter().filter_map(Value::as_str) {
            if value.get(name).is_some() {
                return Err(fault(
                    check,
                    &format!("{path}.{name}"),
                    "forbidden-owned-state",
                ));
            }
        }
    }
    if let Some(fields) = rule.get("fields").and_then(Value::as_object) {
        for (name, field) in fields {
            if let Some(value) = value.get(name) {
                node(field, value, check, &format!("{path}.{name}"))?;
            }
        }
    }
    if let (Some(items), Some(values)) = (rule.get("items"), value.as_array()) {
        for (i, value) in values.iter().enumerate() {
            node(items, value, check, &format!("{path}[{i}]"))?;
        }
    }
    if let (Some(items), Some(values)) = (rule.get("values"), value.as_object()) {
        for (key, value) in values {
            node(items, value, check, &format!("{path}.{key}"))?;
        }
    }
    Ok(())
}

pub fn kernel(id: &str, name: Option<&str>, value: &Value, check: &str, path: &str) -> Result<()> {
    let seat = declaration(id)?;
    if value.get("schema").and_then(Value::as_str) != Some(id) {
        return Err(fault(
            check,
            &format!("{path}.schema"),
            format!("foreign-schema-id: expected={id}"),
        ));
    }
    for scope in std::iter::once(seat).chain(name.map(|name| &seat["forms"][name])) {
        let required = scope
            .get("required")
            .and_then(Value::as_array)
            .ok_or_else(|| observation(check, path, "schema-kernel-desync"))?;
        for key in required.iter().filter_map(Value::as_str) {
            if value.get(key).is_none() {
                return Err(fault(
                    check,
                    &format!("{path}.{key}"),
                    "missing-frozen-kernel",
                ));
            }
        }
        if let Some(keys) = scope.get("forbidden").and_then(Value::as_array) {
            for key in keys.iter().filter_map(Value::as_str) {
                if value.get(key).is_some() {
                    return Err(fault(
                        check,
                        &format!("{path}.{key}"),
                        "forbidden-owned-state",
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn form(id: &str, name: Option<&str>, value: &Value, check: &str, path: &str) -> Result<()> {
    kernel(id, name, value, check, path)?;
    node(declaration(id)?, value, check, path)
}

pub fn field(id: &str, key: &str, value: &Value, check: &str, path: &str) -> Result<()> {
    let rule = declaration(id)?
        .get("fields")
        .and_then(|fields| fields.get(key))
        .ok_or_else(|| observation(check, path, format!("schema-field-desync: {id}.{key}")))?;
    node(rule, value, check, path)
}
