use serde_json::Value;

#[test]
fn certificate_dependent_reload_declaration_is_ordered_and_primitive() {
    let dependents = caduceus::routes::cert_dependent_reload::declared_dependents().unwrap();
    assert_eq!(dependents.len(), 2);
    assert_eq!(dependents[0].service, "forgejo.service");
    assert_eq!(dependents[0].action, "restart");
    assert_eq!(dependents[1].service, "nginx.service");
    assert_eq!(dependents[1].action, "reload");
}

#[test]
fn certificate_dependent_reload_dry_form_has_one_row_per_dependent() {
    let receipt = caduceus::routes::cert_dependent_reload::dry_form().unwrap();
    assert_eq!(receipt["ok"], true);
    assert_eq!(receipt["mutationPerformed"], false);
    assert_eq!(receipt["final"], "planned");
    assert_eq!(receipt["observedMaterial"]["material"], "none");
    assert_eq!(receipt["observedMaterial"]["changed"], false);
    assert_eq!(receipt["observedMaterialChanged"], false);
    let rows = receipt["attempts"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        receipt["couldChangeDependents"].as_array().unwrap().len()
    );
    assert!(rows.iter().all(|row| {
        row["status"] == Value::String("planned".into())
            && row["mutationPerformed"] == Value::Bool(false)
    }));
}
