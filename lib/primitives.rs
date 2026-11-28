//! Enumerable C2 Rust serve primitive registry.
// Names are concrete leaf operations, never generic router façades.
pub static RUST_PRIMITIVES: &[&str] = &[
    "appliance/appliance-stats-sampler/ask-the-stats-sampler-to-verify-model-lanes-on-its-next-tick",
    "appliance/appliance-identity/read-the-appliance-identity-from-its-profile-file",
    "appliance/appliance-health-report/read-the-appliance-health-report-of-profile-presence",
    "appliance/agathodaimon-staff-library/list-every-staff-library-band-for-the-active-profile",
    "appliance/agathodaimon-staff-library/read-the-staff-library-status-and-one-band-by-its-band-path",
    "appliance/local-ai-runtime/status-the-llama-binaries-route-and-receipt",
    "network/networkmanager-wifi/list-the-saved-wifi-connections-by-name-uuid-and-type",
    "network/networkmanager-wifi/list-the-visible-wifi-networks-from-a-radio-scan",
    "network/networkmanager-wifi/status-the-wifi-link-of-this-seat",
    "network/transmission-vpn-tunnel/status-the-openvpn-and-transmission-processes-and-the-vpn-unit-enabled-flag",
    "network/lan-device-notes/read-the-free-text-notes-of-network-devices-from-the-state-file",
    "network/kea-dhcp/list-the-dhcp-doorways-from-the-kea-configuration",
    "network/kea-dhcp/list-the-dhcp-leases-from-the-kea-lease-file",
    "network/kea-dhcp/list-the-dhcp-reservations-from-the-kea-configuration",
    "appliance/harmonia-update-engine/verify-whether-a-harmonia-update-is-available-and-record-the-check",
    "appliance/harmonia-update-engine/converge-this-appliance-to-the-latest-harmonia-sources-now",
    "appliance/harmonia-pending-interactables/list-every-pending-harmonia-interactable",
    "appliance/harmonia-pending-interactables/run-one-pending-harmonia-interactable-by-its-id",
    "appliance/harmonia-pending-interactables/set-one-harmonia-interactable-silenced-on-by-its-id",
    "appliance/harmonia-pending-interactables/set-one-harmonia-interactable-silenced-off-by-its-id",
    "appliance/harmonia-update-engine/list-every-harmonia-update-history-entry",
    "appliance/harmonia-module-profile/list-all-modules-with-enabled-state-and-metadata",
    "appliance/household-config/read-the-household-config-device-path-and-profile",
    "appliance/household-config/read-the-whole-public-household-config",
    "appliance/household-config/read-one-public-household-config-value-by-its-path",
    "appliance/exousia-attendance/read-exousia-posture-bound-or-unbound",
    "appliance/appliance-stats-sampler/list-the-appliance-stats-history-samples-by-tier-and-time-window",
    "appliance/harmonia-update-engine/read-the-harmonia-update-profile-state-and-route-presence",
    "appliance/appliance-stats-sampler/read-the-latest-appliance-stats-sample-with-model-lanes-and-last-update-check",
    "network/seat-tunnels/status-whether-the-openvpn-port-forwarding-and-tailscale-tunnels-are-up-on-this-seat",
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
    ModelLanePulse,
    ApplianceIdentity,
    ApplianceHealth,
    StaffLibraryList,
    StaffLibraryStatus,
    LlamaRuntimeStatus,
    #[cfg(leaf_network_device_wifi_saved)]
    WifiSaved,
    #[cfg(leaf_network_device_wifi_scan)]
    WifiScan,
    #[cfg(leaf_network_device_wifi_status)]
    WifiStatus,
    TransmissionVpnStatus,
    NetworkNotesRead,
    KeaDoorways,
    KeaLeases,
    KeaReservations,
    UpdateCheck,
    UpdateNow,
    InteractableList,
    InteractableRun,
    InteractableSilence,
    InteractableUnsilence,
    UpdateHistory,
    ModulesList,
    ConfigPath,
    ConfigShow,
    ConfigGet,
    ExousiaPosture,
    #[cfg(leaf_face_meter)]
    FaceMeter,
    DoorsList,
    StatsHistory,
    UpdateState,
    StatsLatest,
    SeatTunnels,
    #[cfg(leaf_pid2)]
    RoutineStatus,
    #[cfg(leaf_pid2)]
    RoutineHold,
}

fn command(name: &str) -> Option<NativeCommand> {
    match name {
        "appliance/appliance-stats-sampler/ask-the-stats-sampler-to-verify-model-lanes-on-its-next-tick" => Some(NativeCommand::ModelLanePulse),
        "appliance/appliance-identity/read-the-appliance-identity-from-its-profile-file" => Some(NativeCommand::ApplianceIdentity),
        "appliance/appliance-health-report/read-the-appliance-health-report-of-profile-presence" => Some(NativeCommand::ApplianceHealth),
        "appliance/agathodaimon-staff-library/list-every-staff-library-band-for-the-active-profile" => Some(NativeCommand::StaffLibraryList),
        "appliance/agathodaimon-staff-library/read-the-staff-library-status-and-one-band-by-its-band-path" => Some(NativeCommand::StaffLibraryStatus),
        "appliance/local-ai-runtime/status-the-llama-binaries-route-and-receipt" => Some(NativeCommand::LlamaRuntimeStatus),
        #[cfg(leaf_network_device_wifi_saved)]
        "network/networkmanager-wifi/list-the-saved-wifi-connections-by-name-uuid-and-type" => Some(NativeCommand::WifiSaved),
        #[cfg(leaf_network_device_wifi_scan)]
        "network/networkmanager-wifi/list-the-visible-wifi-networks-from-a-radio-scan" => Some(NativeCommand::WifiScan),
        #[cfg(leaf_network_device_wifi_status)]
        "network/networkmanager-wifi/status-the-wifi-link-of-this-seat" => Some(NativeCommand::WifiStatus),
        "network/transmission-vpn-tunnel/status-the-openvpn-and-transmission-processes-and-the-vpn-unit-enabled-flag" => Some(NativeCommand::TransmissionVpnStatus),
        "network/lan-device-notes/read-the-free-text-notes-of-network-devices-from-the-state-file" => Some(NativeCommand::NetworkNotesRead),
        "network/kea-dhcp/list-the-dhcp-doorways-from-the-kea-configuration" => Some(NativeCommand::KeaDoorways),
        "network/kea-dhcp/list-the-dhcp-leases-from-the-kea-lease-file" => Some(NativeCommand::KeaLeases),
        "network/kea-dhcp/list-the-dhcp-reservations-from-the-kea-configuration" => Some(NativeCommand::KeaReservations),
        "appliance/harmonia-update-engine/verify-whether-a-harmonia-update-is-available-and-record-the-check" => Some(NativeCommand::UpdateCheck),
        "appliance/harmonia-update-engine/converge-this-appliance-to-the-latest-harmonia-sources-now" => Some(NativeCommand::UpdateNow),
        "appliance/harmonia-pending-interactables/list-every-pending-harmonia-interactable" => Some(NativeCommand::InteractableList),
        "appliance/harmonia-pending-interactables/run-one-pending-harmonia-interactable-by-its-id" => Some(NativeCommand::InteractableRun),
        "appliance/harmonia-pending-interactables/set-one-harmonia-interactable-silenced-on-by-its-id" => Some(NativeCommand::InteractableSilence),
        "appliance/harmonia-pending-interactables/set-one-harmonia-interactable-silenced-off-by-its-id" => Some(NativeCommand::InteractableUnsilence),
        "appliance/harmonia-update-engine/list-every-harmonia-update-history-entry" => Some(NativeCommand::UpdateHistory),
        "appliance/harmonia-module-profile/list-all-modules-with-enabled-state-and-metadata" => Some(NativeCommand::ModulesList),
        "appliance/household-config/read-the-household-config-device-path-and-profile" => Some(NativeCommand::ConfigPath),
        "appliance/household-config/read-the-whole-public-household-config" => Some(NativeCommand::ConfigShow),
        "appliance/household-config/read-one-public-household-config-value-by-its-path" => Some(NativeCommand::ConfigGet),
        "appliance/exousia-attendance/read-exousia-posture-bound-or-unbound" => Some(NativeCommand::ExousiaPosture),
        #[cfg(leaf_face_meter)]
        "face_meter_read" => Some(NativeCommand::FaceMeter),
        "appliance/caduceus-doors/read-the-door-route-list-of-the-active-profile" => Some(NativeCommand::DoorsList),
        "appliance/appliance-stats-sampler/list-the-appliance-stats-history-samples-by-tier-and-time-window" => Some(NativeCommand::StatsHistory),
        "appliance/harmonia-update-engine/read-the-harmonia-update-profile-state-and-route-presence" => Some(NativeCommand::UpdateState),
        "appliance/appliance-stats-sampler/read-the-latest-appliance-stats-sample-with-model-lanes-and-last-update-check" => Some(NativeCommand::StatsLatest),
        "network/seat-tunnels/status-whether-the-openvpn-port-forwarding-and-tailscale-tunnels-are-up-on-this-seat" => Some(NativeCommand::SeatTunnels),
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

fn native_read_failure(error: &str) -> serde_json::Value {
    serde_json::json!({"ok": false, "firstMissingSignal": crate::gate::missing_signal(error), "outcome": "failed"})
}

fn kea_read_answer(mut value: serde_json::Value) -> Result<serde_json::Value, String> {
    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
        value["outcome"] = serde_json::json!(if crate::routes::network_read::is_not_the_gateway_refusal(&value) {
            "not-the-gateway"
        } else {
            "failed"
        });
    }
    crate::shared::load_trace::enrich_json(&mut value);
    Ok(value)
}

pub async fn execute(name: &str, envelope: &serde_json::Value) -> Result<serde_json::Value, String> {
    match command(name) {
        Some(NativeCommand::ModelLanePulse) => {
            let mut value = match crate::stats::request_model_lane_pulse() {
                Ok(result) => serde_json::json!({"ok": true, "result": result}),
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        Some(NativeCommand::ApplianceIdentity) => {
            let mut value = match crate::routes::report_identity::read_json() {
                Ok(serde_json::Value::Object(mut object)) => {
                    if object.get("ok").and_then(serde_json::Value::as_bool).is_none() {
                        object.insert("ok".into(), serde_json::Value::Bool(true));
                    }
                    if object.get("ok").and_then(serde_json::Value::as_bool) == Some(false) {
                        object.insert("outcome".into(), serde_json::json!("identity-says-not-ok"));
                    }
                    serde_json::Value::Object(object)
                }
                Ok(_) => native_read_failure("caduceus-identity-profile-invalid"),
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        Some(NativeCommand::ApplianceHealth) => {
            let mut value = match crate::routes::leaf_appliance_report::read_json() {
                Ok(mut value) => {
                    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                        value["outcome"] = serde_json::json!("profile-absent");
                    }
                    value
                }
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        Some(NativeCommand::StaffLibraryList) => match crate::gate::snake::list() {
            Ok(value) => Ok(value),
            Err(signal) => Ok(serde_json::json!({"ok": false, "firstMissingSignal": signal, "outcome": "failed"})),
        },
        Some(NativeCommand::StaffLibraryStatus) => {
            let band = envelope.get("payload").and_then(|payload| payload.get("bandPath")).and_then(serde_json::Value::as_str);
            Ok(crate::gate::snake::status(band))
        }
        Some(NativeCommand::LlamaRuntimeStatus) => {
            let mut value = match crate::routes::leaf_local_ai_query::runtime_status_json() {
                Ok(mut value) => {
                    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                        value["outcome"] = serde_json::json!("runtime-not-ready");
                    }
                    value
                }
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        #[cfg(leaf_network_device_wifi_saved)]
        Some(NativeCommand::WifiSaved) => {
            let (status, axum::Json(mut value)) = match crate::routes::leaf_network_device_wifi_saved::route().await { Ok(answer) | Err(answer) => answer };
            if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                value["outcome"] = serde_json::json!(if status == axum::http::StatusCode::FORBIDDEN { "refused" } else { "failed" });
            }
            Ok(value)
        }
        #[cfg(leaf_network_device_wifi_scan)]
        Some(NativeCommand::WifiScan) => {
            let (status, axum::Json(mut value)) = match crate::routes::leaf_network_device_wifi_scan::route().await { Ok(answer) | Err(answer) => answer };
            if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                value["outcome"] = serde_json::json!(if status == axum::http::StatusCode::FORBIDDEN { "refused" } else { "failed" });
            }
            Ok(value)
        }
        #[cfg(leaf_network_device_wifi_status)]
        Some(NativeCommand::WifiStatus) => {
            let (status, axum::Json(mut value)) = match crate::routes::leaf_network_device_wifi_status::route().await { Ok(answer) | Err(answer) => answer };
            if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                value["outcome"] = serde_json::json!(if status == axum::http::StatusCode::FORBIDDEN { "refused" } else { "failed" });
            }
            Ok(value)
        }
        Some(NativeCommand::TransmissionVpnStatus) => {
            let mut value = match crate::routes::leaf_network_vpn::status_json() {
                Ok(mut value) => {
                    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                        value["outcome"] = serde_json::json!("stopped");
                    }
                    value
                }
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        Some(NativeCommand::NetworkNotesRead) => {
            let mut value = match crate::routes::leaf_network_device_annotate::read_json() {
                Ok(value) => value,
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        Some(NativeCommand::KeaDoorways) => kea_read_answer(crate::routes::native_kea_read::response(crate::routes::native_kea_read::DOORWAYS_COMMAND)),
        Some(NativeCommand::KeaLeases) => kea_read_answer(crate::routes::native_kea_read::response(crate::routes::native_kea_read::LEASE_COMMAND)),
        Some(NativeCommand::KeaReservations) => kea_read_answer(crate::routes::native_kea_read::response(crate::routes::native_kea_read::RESERVATION_COMMAND)),
        Some(NativeCommand::UpdateNow) => Ok(crate::routes::update_appliance::invoke_now_json(&[])),
        Some(NativeCommand::UpdateCheck) => {
            let mut value = crate::stats::run_update_check();
            if let Some(object) = value.as_object_mut() {
                if object.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                    object.insert("outcome".into(), serde_json::json!("failed"));
                }
            }
            Ok(value)
        }
        Some(NativeCommand::InteractableList) => {
            let (code, body) = crate::shared::harmonia::invoke("interactable_list", &[], false);
            let parsed = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body);
            match (code, parsed) {
                (0, Ok(mut object)) => {
                    object.entry("ok").or_insert(serde_json::Value::Bool(true));
                    if object.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                        object.insert("outcome".into(), serde_json::json!("answered"));
                    }
                    Ok(serde_json::Value::Object(object))
                }
                _ => Ok(serde_json::json!({"ok": false, "firstMissingSignal": "caduceus-harmonia-command-failed", "outcome": "refused"})),
            }
        }
        Some(act @ (NativeCommand::InteractableRun | NativeCommand::InteractableSilence | NativeCommand::InteractableUnsilence)) => {
            let Some(id) = envelope.get("payload").and_then(|payload| payload.get("id")).and_then(serde_json::Value::as_str) else {
                return Ok(serde_json::json!({"ok": false, "firstMissingSignal": "caduceus-request-payload-invalid", "outcome": "request-invalid"}));
            };
            let route = match act {
                NativeCommand::InteractableRun => "interactable_run",
                NativeCommand::InteractableSilence => "interactable_silence",
                NativeCommand::InteractableUnsilence => "interactable_unsilence",
                _ => unreachable!(),
            };
            let (code, body) = crate::shared::harmonia::invoke(route, &[id.to_owned()], false);
            if matches!(act, NativeCommand::InteractableRun) {
                let mut value = crate::shared::harmonia::invoke_body_to_json(route, code, &body);
                if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                    value["outcome"] = serde_json::json!("failed");
                }
                Ok(value)
            } else {
                let parsed = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body);
                match (code, parsed) {
                    (0, Ok(mut object)) => {
                        if object.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                            object.insert("outcome".into(), serde_json::json!("answered"));
                        }
                        Ok(serde_json::Value::Object(object))
                    }
                    _ => Ok(serde_json::json!({"ok": false, "firstMissingSignal": "caduceus-harmonia-command-failed", "outcome": "refused"})),
                }
            }
        }
        Some(NativeCommand::UpdateState) => {
            let mut value = match crate::routes::update_appliance::read_json() {
                Ok(mut value) => {
                    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                        value["outcome"] = serde_json::json!("not-ready");
                    }
                    value
                }
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        Some(NativeCommand::SeatTunnels) => {
            let mut value = match crate::routes::network::status_json() {
                Ok(mut value) => {
                    if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                        value["outcome"] = serde_json::json!("tunnel-down");
                    }
                    value
                }
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        Some(NativeCommand::StatsLatest) => {
            let result = crate::stats::current().and_then(|body| {
                serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body)
                    .map_err(|error| error.to_string())
            });
            let mut value = match result {
                Ok(mut object) => {
                    object.entry("ok").or_insert(serde_json::Value::Bool(true));
                    serde_json::Value::Object(object)
                }
                Err(error) => native_read_failure(&error),
            };
            crate::shared::load_trace::enrich_json(&mut value);
            Ok(value)
        }
        Some(NativeCommand::UpdateHistory) => {
            let mut value = crate::routes::leaf_update_history::history_json();
            if value.get("ok").and_then(serde_json::Value::as_bool) != Some(true) {
                value["outcome"] = serde_json::json!("log-unreadable");
            }
            Ok(value)
        }
        Some(NativeCommand::ModulesList) => match crate::routes::leaf_update_modules::modules_json() {
            Ok(value) => Ok(value),
            Err(signal) => {
                let mut value = serde_json::json!({"ok": false, "firstMissingSignal": signal, "outcome": "refused"});
                crate::shared::load_trace::enrich_json(&mut value);
                Ok(value)
            }
        },
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
