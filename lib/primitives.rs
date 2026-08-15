//! Enumerable C2 Rust serve primitive registry.
// Names are concrete leaf operations, never generic router façades.
pub static RUST_PRIMITIVES: &[&str] = &[
    "health",
    "identity",
    "profile",
    "admittance",
    "attendance",
    "staff",
    "discovery",
    "appliance_report_read",
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
];
pub fn contains(name: &str) -> bool {
    RUST_PRIMITIVES.contains(&name)
}
