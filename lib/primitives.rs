//! Enumerable C2 Rust serve primitive registry.
// Names are concrete leaf operations, never generic router façades.
pub static RUST_PRIMITIVES: &[&str] = &[
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
    #[cfg(leaf_face_meter)]
    FaceMeter,
    DoorsList,
}

fn command(name: &str) -> Option<NativeCommand> {
    match name {
        #[cfg(leaf_face_meter)]
        "face_meter_read" => Some(NativeCommand::FaceMeter),
        "appliance/caduceus-doors/read-the-door-route-list-of-the-active-profile" => Some(NativeCommand::DoorsList),
        _ => None,
    }
}

pub(crate) fn has_command(name: &str) -> bool {
    command(name).is_some()
}

pub async fn execute(name: &str, envelope: &serde_json::Value) -> Result<serde_json::Value, String> {
    match command(name) {
        #[cfg(leaf_face_meter)]
        Some(NativeCommand::FaceMeter) => Ok(crate::shared::face_meter_native::read_meter(envelope).await),
        Some(NativeCommand::DoorsList) => Ok(crate::gate::doors_readback()),
        None => Err("caduceus-serve-rust-primitive-unavailable".to_string()),
    }
}
