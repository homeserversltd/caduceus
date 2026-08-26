use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::process::Command;

const DECLARATION: &str = include_str!("../../dependents.json");

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Dependent {
    pub service: String,
    pub action: String,
}

#[derive(Deserialize)]
struct Declaration {
    dependents: Vec<Dependent>,
}

pub fn declared_dependents() -> Result<Vec<Dependent>, String> {
    serde_json::from_str::<Declaration>(DECLARATION)
        .map(|declaration| declaration.dependents)
        .map_err(|_| "caduceus-cert-dependent-reload-declaration-invalid".to_string())
}

fn could_change(dependents: &[Dependent]) -> Value {
    Value::Array(
        dependents
            .iter()
            .map(|dependent| json!({"service": dependent.service, "action": dependent.action}))
            .collect(),
    )
}

fn base_receipt(dependents: &[Dependent], observed_material_changed: bool) -> Map<String, Value> {
    let mut receipt = Map::new();
    receipt.insert("schema".into(), json!("caduceus.cert.dependent_reload.v1"));
    receipt.insert("ok".into(), json!(true));
    receipt.insert(
        "observedMaterialChanged".into(),
        json!(observed_material_changed),
    );
    receipt.insert("couldChangeDependents".into(), could_change(dependents));
    receipt
}

/// Returns the complete dependent shape without invoking systemctl.
pub fn dry_form() -> Result<Value, String> {
    let dependents = declared_dependents()?;
    let attempts = dependents
        .iter()
        .map(|dependent| {
            json!({
                "service": dependent.service,
                "action": dependent.action,
                "status": "planned",
                "result": "not-attempted",
                "mutationPerformed": false
            })
        })
        .collect::<Vec<_>>();
    let mut receipt = base_receipt(&dependents, false);
    receipt.insert(
        "observedMaterial".into(),
        json!({"material": "none", "changed": false}),
    );
    receipt.insert("attempts".into(), json!(attempts));
    receipt.insert("final".into(), json!("planned"));
    receipt.insert("mutationPerformed".into(), json!(false));
    Ok(Value::Object(receipt))
}

fn absent_output(output: &std::process::Output) -> bool {
    let text = format!(
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .to_ascii_lowercase();
    [
        "not found",
        "could not be found",
        "no such file",
        "not-found",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

#[derive(Debug, PartialEq, Eq)]
enum CommandResult {
    Succeeded,
    Absent,
    Failed,
}

fn execute_with<F>(dependents: &[Dependent], mut run: F) -> Value
where
    F: FnMut(&Dependent) -> CommandResult,
{
    let mut attempts = Vec::with_capacity(dependents.len());
    let mut failed = false;
    let mut mutated = false;
    for dependent in dependents {
        let row = match run(dependent) {
            CommandResult::Succeeded => {
                mutated = true;
                json!({
                    "service": dependent.service,
                    "action": dependent.action,
                    "status": "attempted",
                    "result": "succeeded",
                    "mutationPerformed": true
                })
            }
            CommandResult::Absent => json!({
                "service": dependent.service,
                "action": dependent.action,
                "status": "absent-on-this-body",
                "result": "absent",
                "mutationPerformed": false
            }),
            CommandResult::Failed => {
                failed = true;
                json!({
                    "service": dependent.service,
                    "action": dependent.action,
                    "status": "attempted",
                    "result": "failed",
                    "mutationPerformed": false
                })
            }
        };
        attempts.push(row);
    }
    json!({
        "attempts": attempts,
        "final": if failed { "failed" } else { "completed" },
        "ok": !failed,
        "mutationPerformed": mutated
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn changed_receipt() -> Value {
        json!({"ok": true, "changed": true})
    }

    #[test]
    fn injected_runner_keeps_absent_rows_ordered() {
        let dependents = declared_dependents().unwrap();
        let mut results = [CommandResult::Absent, CommandResult::Succeeded].into_iter();
        let receipt = after_material_lands_with_runner(
            changed_receipt(),
            &dependents,
            json!({"material": "root", "scope": "household-root", "changed": true}),
            |_| results.next().unwrap(),
        )
        .unwrap();
        let rows = receipt["dependentReload"]["attempts"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["service"], "forgejo.service");
        assert_eq!(rows[0]["status"], "absent-on-this-body");
        assert_eq!(rows[0]["mutationPerformed"], false);
        assert_eq!(rows[1]["service"], "nginx.service");
    }

    #[test]
    fn injected_runner_failure_fails_closed() {
        let dependents = declared_dependents().unwrap();
        let receipt = after_material_lands_with_runner(
            changed_receipt(),
            &dependents,
            json!({"material": "root", "scope": "household-root", "changed": true}),
            |_| CommandResult::Failed,
        )
        .unwrap();
        assert_eq!(receipt["ok"], false);
        assert_eq!(receipt["dependentReload"]["final"], "failed");
        assert_eq!(
            receipt["firstMissingSignal"],
            "caduceus-cert-dependent-reload-failed"
        );
    }

    #[test]
    fn unrelated_leaf_is_not_run_and_keeps_rows() {
        let dependents = declared_dependents().unwrap();
        let mut calls = 0;
        let receipt = after_material_lands_with_runner(
            json!({"ok": true, "changed": true}),
            &dependents,
            json!({"material": "leaf", "identity": "other.example", "sans": ["other.example"], "changed": true}),
            |_| {
                calls += 1;
                CommandResult::Failed
            },
        ).unwrap();
        assert_eq!(calls, 0);
        assert_eq!(
            receipt["dependentReload"]["observedMaterial"]["identity"],
            "other.example"
        );
        assert_eq!(
            receipt["dependentReload"]["attempts"][0]["status"],
            "not-applicable"
        );
        assert_eq!(receipt["dependentReload"]["final"], "not-applicable");
    }
}

fn after_material_lands_with_runner<F>(
    mut receipt: Value,
    dependents: &[Dependent],
    observed_material: Value,
    run: F,
) -> Result<Value, String>
where
    F: FnMut(&Dependent) -> CommandResult,
{
    let observed = observed_material
        .get("changed")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let applicable = material_applies_to_household(&observed_material);
    let mut dependent_receipt = base_receipt(dependents, observed);
    dependent_receipt.insert("observedMaterial".into(), observed_material);
    if observed && applicable {
        if let Value::Object(executed) = execute_with(dependents, run) {
            for (key, value) in executed {
                dependent_receipt.insert(key, value);
            }
        }
    } else {
        let (status, result) = if !applicable {
            ("not-applicable", "outside-home.arpa")
        } else {
            ("not-needed", "material-unchanged")
        };
        let attempts = dependents
            .iter()
            .map(|dependent| json!({"service": dependent.service, "action": dependent.action, "status": status, "result": result, "mutationPerformed": false}))
            .collect::<Vec<_>>();
        dependent_receipt.insert("attempts".into(), json!(attempts));
        dependent_receipt.insert("final".into(), json!(status));
        dependent_receipt.insert("mutationPerformed".into(), json!(false));
    }
    let dependent_failed = dependent_receipt.get("ok").and_then(Value::as_bool) == Some(false);
    if let Value::Object(ref mut object) = receipt {
        object.insert("dependentReload".into(), Value::Object(dependent_receipt));
        if dependent_failed {
            object.insert("ok".into(), json!(false));
            object.insert(
                "firstMissingSignal".into(),
                json!("caduceus-cert-dependent-reload-failed"),
            );
        }
        Ok(receipt)
    } else {
        Err("caduceus-cert-transition-receipt-invalid".to_string())
    }
}

fn home_arpa_identity(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value == "home.arpa" || value.ends_with(".home.arpa") || value == "*.home.arpa"
}

fn material_applies_to_household(material: &Value) -> bool {
    match material.get("material").and_then(Value::as_str) {
        Some("root") => material.get("scope").and_then(Value::as_str) == Some("household-root"),
        Some("leaf") => {
            material
                .get("identity")
                .and_then(Value::as_str)
                .is_some_and(home_arpa_identity)
                || material
                    .get("sans")
                    .and_then(Value::as_array)
                    .is_some_and(|sans| {
                        sans.iter()
                            .filter_map(Value::as_str)
                            .any(home_arpa_identity)
                    })
        }
        Some("applied") => material
            .get("portal")
            .and_then(Value::as_str)
            .is_some_and(home_arpa_identity),
        _ => false,
    }
}

/// Appends the dependent leg to a certificate transition receipt.
pub fn after_material_lands(receipt: Value, observed_material: Value) -> Result<Value, String> {
    let dependents = declared_dependents()?;
    let systemctl =
        std::env::var("CADUCEUS_SYSTEMCTL_BIN").unwrap_or_else(|_| "systemctl".to_string());
    after_material_lands_with_runner(receipt, &dependents, observed_material, |dependent| {
        match Command::new(&systemctl)
            .args([dependent.action.as_str(), dependent.service.as_str()])
            .output()
        {
            Ok(output) if output.status.success() => CommandResult::Succeeded,
            Ok(output) if absent_output(&output) => CommandResult::Absent,
            Ok(_) | Err(_) => CommandResult::Failed,
        }
    })
}
