//! Enumerable C2 Rust serve primitive registry.
// Names are concrete leaf operations, never generic router façades.
pub static RUST_PRIMITIVES: &[&str] = &[
    "appliance/household-config/read-the-household-config-device-path-and-profile",
    "appliance/household-config/read-the-whole-public-household-config",
    "appliance/household-config/read-one-public-household-config-value-by-its-path",
    "appliance/exousia-attendance/read-exousia-posture-bound-or-unbound",
    "appliance/appliance-stats-sampler/list-the-appliance-stats-history-samples-by-tier-and-time-window",
    "appliance/caduceus-pid2-routines/hold-one-routine-by-its-routine-id",
    "appliance/caduceus-pid2-routines/status-one-routine-by-its-routine-id",
    "appliance/caduceus-doors/read-the-door-route-list-of-the-active-profile",
    "face_meter_read",
    "health",
    "identity",
    "profile",
    "admittance",
    "attendance",
    "staff",
    "discovery",
    "caduceus_staff_receipt",
    "keyman_crown",
    "network_wifi_scan_read",
    "network_wifi_status_read",
    "network_wifi_saved_read",
    "network_wifi_connect_mutate",
    "network_wifi_disconnect_mutate",
    "network_wifi_forget_mutate",
    "network_wifi_ipv4_mutate",
    "network_wifi_radio_mutate",
    "network_device_connect_mutate",
    "network_device_disconnect_mutate",
    "network_device_ipv4_mutate",
    "appliance_report_read",
    "appliance_stats_read",
    "bandwidth_measure_read",
    "log_receipts_read",
    "log_reflect_mutate",
    "log_write_mutate",
    "projector_power_mutate",
    "projector_products_read",
    "projector_scan_mutate",
    "settings_appearance_read_mutate",
    "settings_datetime_read_mutate",
    "settings_default_apps_read_mutate",
    "settings_display_read_mutate",
    "settings_input_read_mutate",
    "settings_notifications_read_mutate",
    "settings_sound_read_mutate",
    "appliance_service_control",
    "python_library_list",
    "python_library_status",
    "network_device_claim_witness",
    "network_device_claim_public_shape",
    "network_dns_route_action_witness",
    "network_dns_public_receipt_shape",
    "network_firewall_policy_input_witness",
    "network_firewall_status_refusal_shape",
    "storage_vault_unlock_witness",
    "storage_vault_unlock_public_shape",
];
pub fn contains(name: &str) -> bool {
    RUST_PRIMITIVES.contains(&name)
}

enum NativeCommand {
    ConfigPath,
    ConfigShow,
    ConfigGet,
    ExousiaPosture,
    #[cfg(leaf_face_meter)]
    FaceMeter,
    DoorsList,
    StatsHistory,
    #[cfg(leaf_pid2)]
    RoutineStatus,
    #[cfg(leaf_pid2)]
    RoutineHold,
}

fn command(name: &str) -> Option<NativeCommand> {
    match name {
        "appliance/household-config/read-the-household-config-device-path-and-profile" => Some(NativeCommand::ConfigPath),
        "appliance/household-config/read-the-whole-public-household-config" => Some(NativeCommand::ConfigShow),
        "appliance/household-config/read-one-public-household-config-value-by-its-path" => Some(NativeCommand::ConfigGet),
        "appliance/exousia-attendance/read-exousia-posture-bound-or-unbound" => Some(NativeCommand::ExousiaPosture),
        #[cfg(leaf_face_meter)]
        "face_meter_read" => Some(NativeCommand::FaceMeter),
        "appliance/caduceus-doors/read-the-door-route-list-of-the-active-profile" => Some(NativeCommand::DoorsList),
        "appliance/appliance-stats-sampler/list-the-appliance-stats-history-samples-by-tier-and-time-window" => Some(NativeCommand::StatsHistory),
        #[cfg(leaf_pid2)]
        "appliance/caduceus-pid2-routines/status-one-routine-by-its-routine-id" => Some(NativeCommand::RoutineStatus),
        #[cfg(leaf_pid2)]
        "appliance/caduceus-pid2-routines/hold-one-routine-by-its-routine-id" => Some(NativeCommand::RoutineHold),
        _ => None,
    }
}

pub(crate) fn has_command(name: &str) -> bool {
    command(name).is_some()
}

pub async fn execute(name: &str, envelope: &serde_json::Value) -> Result<serde_json::Value, String> {
    match command(name) {
        Some(NativeCommand::ConfigPath | NativeCommand::ConfigShow | NativeCommand::ConfigGet) => {
            let result = match command(name) {
                Some(NativeCommand::ConfigPath) => crate::shared::config::path_json(),
                Some(NativeCommand::ConfigShow) => crate::shared::config::show_public_json(),
                Some(NativeCommand::ConfigGet) => envelope.get("payload")
                    .and_then(|payload| payload.get("path"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| "caduceus-household-config-path-invalid".to_string())
                    .and_then(crate::shared::config::get_public_json),
                _ => unreachable!(),
            };
            match result {
                Ok(value) => Ok(value),
                Err(signal) => {
                    let outcome = if signal == "caduceus-household-config-path-invalid" { "request-invalid" } else { "refused" };
                    let mut value = serde_json::json!({"ok": false, "firstMissingSignal": signal, "outcome": outcome});
                    crate::shared::load_trace::enrich_json(&mut value);
                    Ok(value)
                }
            }
        }
        Some(NativeCommand::ExousiaPosture) => {
            let mut value = crate::shared::attendance::posture_json()?;
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        #[cfg(leaf_face_meter)]
        Some(NativeCommand::FaceMeter) => Ok(crate::shared::face_meter_native::read_meter(envelope).await),
        Some(NativeCommand::DoorsList) => Ok(crate::gate::doors_readback()),
        Some(NativeCommand::StatsHistory) => {
            let payload = envelope.get("payload").cloned().unwrap_or_else(|| serde_json::json!({}));
            let has_null_field = ["tier", "since", "until", "limit"].iter().any(|field| payload.get(*field).is_some_and(serde_json::Value::is_null));
            let query = serde_json::from_value::<crate::stats::HistoryQuery>(payload);
            let query = match query {
                Ok(_) if has_null_field => {
                    let mut value = serde_json::json!({"ok": false, "firstMissingSignal": "caduceus-request-query-invalid", "outcome": "request-invalid"});
                    crate::shared::load_trace::enrich_json(&mut value);
                    return Ok(value);
                }
                Ok(query) => query,
                Err(_) => {
                    let mut value = serde_json::json!({"ok": false, "firstMissingSignal": "caduceus-request-query-invalid", "outcome": "request-invalid"});
                    crate::shared::load_trace::enrich_json(&mut value);
                    return Ok(value);
                }
            };
            match crate::routes::leaf_appliance_stats::history_read(query).await {
                Ok(Ok(body)) => {
                    let mut value: serde_json::Value = serde_json::from_str(&body).map_err(|_| "caduceus-stats-history-invalid-json".to_owned())?;
                    if let Some(object) = value.as_object_mut() { object.entry("ok").or_insert(serde_json::Value::Bool(true)); }
                    Ok(value)
                }
                Ok(Err(error)) => {
                    let mut value = serde_json::json!({"ok": false, "firstMissingSignal": crate::gate::missing_signal(&error)});
                    crate::shared::load_trace::enrich_json(&mut value);
                    Ok(value)
                }
                Err(_) => Err("caduceus-blocking-task-join-failed".into()),
            }
        }
        #[cfg(leaf_pid2)]
        Some(NativeCommand::RoutineStatus) => {
            let noun = "appliance/caduceus-pid2-routines";
            let verb = "status-one-routine-by-its-routine-id";
            let route = "POST /api/v1/appliance/caduceus-pid2-routines/status-one-routine-by-its-routine-id";
            let id = envelope.get("payload").and_then(|payload| payload.get("id")).and_then(serde_json::Value::as_str).filter(|id| !id.is_empty());
            let Some(id) = id else {
                let (_, axum::Json(mut receipt)) = crate::routes::leaf_pid2::refusal("caduceus-one-name-path-field-missing".into(), noun, verb, route, Some(false));
                receipt["outcome"] = serde_json::json!("request-invalid");
                return Ok(receipt);
            };
            let receipt = match crate::routes::leaf_pid2::status_read(id.to_owned(), noun, verb, route).await {
                Ok(axum::Json(receipt)) | Err((_, axum::Json(receipt))) => receipt,
            };
            Ok(receipt)
        }
        #[cfg(leaf_pid2)]
        Some(NativeCommand::RoutineHold) => {
            let noun = "appliance/caduceus-pid2-routines";
            let verb = "hold-one-routine-by-its-routine-id";
            let route = "POST /api/v1/appliance/caduceus-pid2-routines/hold-one-routine-by-its-routine-id";
            let payload = envelope.get("payload").cloned().unwrap_or(serde_json::Value::Null);
            let receipt = match crate::routes::leaf_pid2::command_payload("hold".to_owned(), payload, envelope.clone(), noun, verb, route).await {
                Ok(axum::Json(receipt)) | Err((_, axum::Json(receipt))) => receipt,
            };
            Ok(receipt)
        }
        None => Err("caduceus-serve-rust-primitive-unavailable".to_string()),
    }
}
