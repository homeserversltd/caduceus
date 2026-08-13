#[path = "inspect_disks/index.rs"]
pub mod inspect_disks;
#[path = "measure_bandwidth/index.rs"]
pub mod measure_bandwidth;
#[path = "query_local_ai/index.rs"]
pub mod query_local_ai;
#[path = "read_appliance_log/index.rs"]
pub mod read_appliance_log;
#[path = "read_logs/index.rs"]
pub mod read_logs;
#[path = "read_receipts/index.rs"]
pub mod read_receipts;
#[path = "report_health/index.rs"]
pub mod report_health;
#[path = "report_identity/index.rs"]
pub mod report_identity;
#[path = "report_links/index.rs"]
pub mod report_links;
#[path = "report_profile/index.rs"]
pub mod report_profile;
#[path = "report_sources/index.rs"]
pub mod report_sources;
#[path = "test_drive/index.rs"]
pub mod test_drive;
#[path = "write_appliance_log/index.rs"]
pub mod write_appliance_log;

#[path = "manage_child_device/index.rs"]
pub mod manage_child_device;
#[path = "pin_device_address/index.rs"]
pub mod pin_device_address;
#[path = "whitelist_device/index.rs"]
pub mod whitelist_device;

#[path = "admit_portal/index.rs"]
pub mod admit_portal;
#[path = "change_pin/index.rs"]
pub mod change_pin;
#[path = "install_trust/index.rs"]
pub mod install_trust;
#[path = "issue_certificate/index.rs"]
pub mod issue_certificate;
#[path = "open_vault/index.rs"]
pub mod open_vault;

#[path = "annotate_device/index.rs"]
pub mod annotate_device;
#[path = "claim_device_identity/index.rs"]
pub mod claim_device_identity;
#[path = "control_resolver/index.rs"]
pub mod control_resolver;
#[path = "list_network_devices/index.rs"]
pub mod list_network_devices;
#[path = "name_device/index.rs"]
pub mod name_device;

#[path = "manage_tailnet/index.rs"]
pub mod manage_tailnet;
#[path = "manage_vpn/index.rs"]
pub mod manage_vpn;
#[path = "set_time/index.rs"]
pub mod set_time;
#[path = "wake_device/index.rs"]
pub mod wake_device;

#[path = "admit_cartridge/index.rs"]
pub mod admit_cartridge;
#[path = "cartridges_shared.rs"]
pub mod cartridges_shared;
#[path = "control_service/index.rs"]
pub mod control_service;
#[path = "list_cartridges/index.rs"]
pub mod list_cartridges;
#[path = "rebuild_crown/index.rs"]
pub mod rebuild_crown;
#[path = "remove_cartridge/index.rs"]
pub mod remove_cartridge;
#[path = "sync_sources/index.rs"]
pub mod sync_sources;
#[path = "toggle_harmonia_module/index.rs"]
pub mod toggle_harmonia_module;
#[path = "update_appliance/index.rs"]
pub mod update_appliance;

#[path = "control_projector/index.rs"]
pub mod control_projector;
#[path = "open_settings_pane/index.rs"]
pub mod open_settings_pane;

#[path = "change_appearance/index.rs"]
pub mod change_appearance;

#[path = "change_sound/index.rs"]
pub mod change_sound;

#[path = "change_display/index.rs"]
pub mod change_display;

#[path = "change_input/index.rs"]
pub mod change_input;

#[path = "change_datetime/index.rs"]
pub mod change_datetime;

#[path = "change_default_apps/index.rs"]
pub mod change_default_apps;

#[path = "change_notifications/index.rs"]
pub mod change_notifications;

#[path = "expose_ssh/index.rs"]
pub mod expose_ssh;

pub use annotate_device as network_notes;
pub use claim_device_identity as network_identity;
pub use control_resolver as dns_control;
pub use inspect_disks as disk;
pub use list_network_devices as network;
pub use list_network_devices as network_read;
pub use manage_child_device as child_device;
pub use measure_bandwidth as speedtest;
pub use name_device as dns;
pub use pin_device_address as dhcp;
pub use query_local_ai as local_ai;
pub use read_logs as logs;
pub use read_receipts as receipts;
pub use report_health as health;
pub use report_identity as identity;
pub use report_links as linker;
pub use report_profile as profile;
pub use report_sources as source_map;
pub use test_drive as drive_test;
pub use whitelist_device as firewall;
pub use write_appliance_log as hyalos;

pub use crate::trigger_gate_receipts as staff;

pub use crate::trigger_gate_index as help;
pub use crate::trigger_gate_routes as serve;
pub mod legacy_sbin {
    pub use crate::trigger_gate_discovery::{
        legacy_sbin_list_json as list_json, legacy_sbin_show_json as show_json,
    };
    pub fn list() -> i32 {
        crate::trigger_gate_discovery::cli("legacy-sbin", None)
    }
    pub fn show(id: &str) -> i32 {
        crate::trigger_gate_discovery::cli("legacy-sbin", Some(id))
    }
}
pub mod homeserver_sbin {
    pub use crate::trigger_gate_discovery::{
        homeserver_sbin_list_json as list_json, homeserver_sbin_show_json as show_json,
    };
    pub fn list() -> i32 {
        crate::trigger_gate_discovery::cli("homeserver-sbin", None)
    }
    pub fn show(id: &str) -> i32 {
        crate::trigger_gate_discovery::cli("homeserver-sbin", Some(id))
    }
}
