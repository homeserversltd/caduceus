//! The single registry seam for GUI-originated actions.
//!
//! Slice 0 deliberately registers one real Coronatio action as unavailable rather
//! than claiming that an admission response performed a mutation. Later slices
//! replace the unavailable executor with the declared native or staff entry point.

use serde_json::{json, Value};

#[derive(Clone, Copy)]
pub struct LegacyAlias {
    pub method: &'static str,
    pub route: &'static str,
}

#[derive(Clone, Copy)]
pub struct ActionDefinition {
    pub id: &'static str,
    pub gui_label: &'static str,
    pub canonical_cli: &'static [&'static str],
    pub http_method: &'static str,
    pub http_route: &'static str,
    pub request_schema: &'static str,
    pub legacy_aliases: &'static [LegacyAlias],
    pub actuator_class: &'static str,
    pub actuator_entry_point: &'static str,
    pub target_allowlist: &'static [&'static str],
    pub profile_admission: &'static str,
    pub mutation_class: &'static str,
    pub preflight: &'static str,
    pub confirmation: &'static str,
    pub rollback: &'static str,
    pub readback: &'static str,
    pub receipt_schema: &'static str,
    pub job_schema: Option<&'static str>,
    pub status: &'static str,
}

const RESTART_WEBSITE_ALIASES: &[LegacyAlias] = &[LegacyAlias {
    method: "POST",
    route: "/api/admin/services/hard-reset",
}];

const ACTIONS: &[ActionDefinition] = &[ActionDefinition {
    id: "restart-website",
    gui_label: "Restart Website",
    canonical_cli: &["service", "restart", "coronatio"],
    http_method: "POST",
    http_route: "/api/v1/service/coronatio/restart",
    request_schema: "caduceus.service.restart.request.v1 ({})",
    legacy_aliases: RESTART_WEBSITE_ALIASES,
    actuator_class: "native-rust",
    actuator_entry_point: "bands::service::restart_coronatio (Slice 1)",
    target_allowlist: &["coronatio.service"],
    profile_admission: "homeserver service-control allowlist",
    mutation_class: "immediate",
    preflight: "unit exists and is permitted; service manager is reachable",
    confirmation: "Coronatio operator admission; no additional confirmation declared",
    rollback: "restart prior unit definition; no configuration mutation",
    readback: "systemctl is-active coronatio.service plus HTTP readiness",
    receipt_schema: "caduceus.service.restart.receipt.v1",
    job_schema: None,
    status: "intentionally-unavailable",
}];

pub fn by_id(id: &str) -> Option<&'static ActionDefinition> {
    ACTIONS.iter().find(|action| action.id == id)
}

pub fn by_cli(parts: &[String]) -> Option<&'static ActionDefinition> {
    ACTIONS.iter().find(|action| {
        action.canonical_cli.len() == parts.len()
            && action
                .canonical_cli
                .iter()
                .zip(parts)
                .all(|(left, right)| left == right)
    })
}

pub fn by_http(method: &str, route: &str) -> Option<&'static ActionDefinition> {
    ACTIONS
        .iter()
        .find(|action| action.http_method == method && action.http_route == route)
}

pub fn by_legacy(method: &str, route: &str) -> Option<&'static ActionDefinition> {
    ACTIONS.iter().find(|action| {
        action
            .legacy_aliases
            .iter()
            .any(|alias| alias.method == method && alias.route == route)
    })
}

pub fn definition_json(action: &ActionDefinition) -> Value {
    json!({
        "schema": "caduceus.action.definition.v1",
        "actionId": action.id,
        "gui": { "actionId": action.id, "label": action.gui_label },
        "canonicalCli": action.canonical_cli,
        "http": { "method": action.http_method, "route": action.http_route, "requestSchema": action.request_schema },
        "legacyAliases": action.legacy_aliases.iter().map(|alias| json!({"method": alias.method, "route": alias.route})).collect::<Vec<_>>(),
        "actuator": { "class": action.actuator_class, "entryPoint": action.actuator_entry_point },
        "admission": { "targets": action.target_allowlist, "profile": action.profile_admission },
        "operation": { "class": action.mutation_class, "preflight": action.preflight, "confirmation": action.confirmation, "rollback": action.rollback, "readback": action.readback },
        "receiptSchema": action.receipt_schema,
        "jobSchema": action.job_schema,
        "status": action.status,
    })
}

pub fn unavailable_receipt(action: &ActionDefinition, source: &str) -> Value {
    json!({
        "schema": "caduceus.action.receipt.v1",
        "ok": false,
        "code": "caduceus-action-intentionally-unavailable",
        "actionId": action.id,
        "source": source,
        "status": action.status,
        "mutationPerformed": false,
        "receiptSchema": action.receipt_schema,
        "nextBoundary": "Slice 1 wires the declared actuator and readback contract"
    })
}

pub fn command(parts: &[String]) -> i32 {
    match by_cli(parts) {
        Some(action) => {
            println!("{}", unavailable_receipt(action, "cli"));
            3
        }
        None => {
            eprintln!("caduceus-action-unmapped");
            2
        }
    }
}
