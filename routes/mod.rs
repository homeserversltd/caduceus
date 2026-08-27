// C2 root route canopy.
#[path = "../lib/primitives.rs"]
pub mod primitives;
pub use crate::stats;
pub mod profile_routes {
    include!(concat!(env!("OUT_DIR"), "/profile_routes.rs"));
}
include!(concat!(env!("OUT_DIR"), "/selected_leaves.rs"));
#[cfg(leaf_cartridges_admit)]
pub use leaf_cartridges_admit as admit_cartridge;
#[cfg(leaf_network_device_annotate)]
pub use leaf_network_device_annotate as annotate_device;
#[cfg(leaf_portals_admit)]
pub use leaf_portals_admit as admit_portal;
#[cfg(any(leaf_cartridges_admit, leaf_cartridges_list, leaf_cartridges_remove))]
#[path = "cartridges/support/cartridges_shared.rs"]
pub mod cartridges_shared;
#[cfg(leaf_admin_admittance_change_pin)]
pub use leaf_admin_admittance_change_pin as change_pin;
#[cfg(leaf_network_device_claim)]
pub use leaf_network_device_claim as claim_device_identity;
#[cfg(leaf_settings_appearance)]
pub use leaf_settings_appearance as change_appearance;
#[cfg(leaf_settings_datetime)]
pub use leaf_settings_datetime as change_datetime;
#[cfg(leaf_settings_default_apps)]
pub use leaf_settings_default_apps as change_default_apps;
#[cfg(leaf_settings_display)]
pub use leaf_settings_display as change_display;
#[cfg(leaf_settings_input)]
pub use leaf_settings_input as change_input;
#[cfg(leaf_settings_notifications)]
pub use leaf_settings_notifications as change_notifications;
#[cfg(leaf_settings_sound)]
pub use leaf_settings_sound as change_sound;
#[path = "cli.rs"]
pub mod cli;
#[cfg(any(
    leaf_display_projector_power,
    leaf_display_projector_products,
    leaf_display_projector_scan
))]
#[path = "display/projector/index.rs"]
pub mod control_projector;
#[cfg(leaf_network_dns_status)]
pub use leaf_network_dns_status as control_resolver;
#[path = "appliance/service/support/control_service/index.rs"]
pub mod control_service;
#[path = "discovery.rs"]
pub mod discovery;
#[cfg(leaf_settings_ssh)]
pub use leaf_settings_ssh as expose_ssh;
#[path = "admin-admittance/support.rs"]
pub(crate) mod admin_admittance_support;
#[path = "appliance/support.rs"]
pub(crate) mod appliance_support;
#[cfg(any(leaf_cartridges_admit, leaf_cartridges_list, leaf_cartridges_remove))]
#[path = "cartridges/support/routes.rs"]
pub(crate) mod cartridges_route_support;
pub use crate::gate;
#[cfg(leaf_settings_appearance)]
#[path = "settings/support/config.rs"]
pub(crate) mod config_support;
#[path = "receipts.rs"]
pub mod gate_receipts;
#[path = "log/support.rs"]
pub(crate) mod log_support;
#[path = "storage/support.rs"]
pub(crate) mod storage_support;
#[path = "update/support.rs"]
pub(crate) mod update_support;
#[cfg(leaf_network_cert_trust)]
pub use leaf_network_cert_trust as install_trust;
#[cfg(leaf_storage_disk_census)]
pub use leaf_storage_disk_census as inspect_disks;
#[path = "network/cert/support/dependent_reload/index.rs"]
pub mod cert_dependent_reload;
#[path = "network/cert/support/issue_certificate/index.rs"]
pub mod issue_certificate;
#[cfg(leaf_appliance_name)]
pub use leaf_appliance_name as name_device;
#[cfg(leaf_cartridges_list)]
pub use leaf_cartridges_list as list_cartridges;
#[cfg(leaf_network_bandwidth_measure)]
pub use leaf_network_bandwidth_measure as measure_bandwidth;
#[cfg(leaf_network_device_list)]
pub use leaf_network_device_list as list_network_devices;
#[cfg(leaf_network_tailnet)]
pub use leaf_network_tailnet as manage_tailnet;
#[cfg(leaf_network_vpn)]
pub use leaf_network_vpn as manage_vpn;
#[cfg(leaf_settings_child_device)]
pub use leaf_settings_child_device as manage_child_device;
#[cfg(any(
    leaf_settings_appearance,
    leaf_settings_child_device,
    leaf_settings_datetime,
    leaf_settings_default_apps,
    leaf_settings_display,
    leaf_settings_input,
    leaf_settings_notifications,
    leaf_settings_pin,
    leaf_settings_sound,
    leaf_settings_ssh
))]
#[path = "settings/support/open_settings_pane/index.rs"]
pub mod open_settings_pane;
#[cfg(leaf_local_ai_query)]
pub use leaf_local_ai_query as query_local_ai;
#[cfg(leaf_log_read)]
pub use leaf_log_read as read_appliance_log;
#[cfg(leaf_network_device_pin_address)]
pub use leaf_network_device_pin_address as pin_device_address;
#[cfg(leaf_storage_vault_unlock)]
pub use leaf_storage_vault_unlock as open_vault;
#[path = "log/read/support/read_logs/index.rs"]
pub mod read_logs;
#[cfg(leaf_log_receipts)]
pub use leaf_log_receipts as read_receipts;
#[path = "appliance/report/support/rebuild_crown/index.rs"]
pub mod rebuild_crown;
#[cfg(leaf_appliance_report)]
pub use leaf_appliance_report as report_health;
#[cfg(leaf_cartridges_remove)]
pub use leaf_cartridges_remove as remove_cartridge;
#[path = "appliance/report/support/report_identity/index.rs"]
pub mod report_identity;
#[cfg(leaf_portals_deploy)]
#[path = "portals/deploy/support/report_links/index.rs"]
pub mod report_links;
#[path = "appliance/report/support/report_profile/index.rs"]
pub mod report_profile;
#[path = "appliance/report/support/report_sources/index.rs"]
pub mod report_sources;
#[cfg(leaf_network_status)]
pub use leaf_network_status as set_time;
#[cfg(leaf_storage_disk_test)]
pub use leaf_storage_disk_test as test_drive;
#[cfg(leaf_update_now)]
pub use leaf_update_now as sync_sources;
#[cfg(leaf_update_status)]
pub use leaf_update_status as toggle_harmonia_module;
#[path = "update/now/support/update_appliance/index.rs"]
pub mod update_appliance;
#[cfg(leaf_log_write)]
pub use leaf_log_write as write_appliance_log;
#[cfg(leaf_network_device_wake)]
pub use leaf_network_device_wake as wake_device;
#[cfg(leaf_network_device_whitelist)]
pub use leaf_network_device_whitelist as whitelist_device;

pub use crate::gate as serve;
pub use cli as help;
pub use gate_receipts as staff;

#[cfg(leaf_network_device_annotate)]
pub use annotate_device as network_notes;
#[cfg(leaf_network_device_claim)]
pub use claim_device_identity as network_identity;
#[cfg(leaf_network_dns_status)]
pub use control_resolver as dns_control;
#[cfg(leaf_storage_disk_census)]
pub use inspect_disks as disk;
#[cfg(leaf_network_dhcp_status)]
pub(crate) use leaf_network_dhcp_status::network_read_route;
#[cfg(leaf_network_device_list)]
pub use list_network_devices as network;
#[cfg(leaf_network_device_list)]
pub use list_network_devices as network_read;
#[cfg(leaf_settings_child_device)]
pub use manage_child_device as child_device;
#[cfg(leaf_network_bandwidth_measure)]
pub use measure_bandwidth as speedtest;
#[cfg(leaf_appliance_name)]
pub use name_device as dns;
#[cfg(leaf_network_device_pin_address)]
pub use pin_device_address as dhcp;
#[cfg(leaf_local_ai_query)]
pub use query_local_ai as local_ai;
pub use read_logs as logs;
#[cfg(leaf_log_receipts)]
pub use read_receipts as receipts;
#[cfg(leaf_appliance_report)]
pub use report_health as health;
pub use report_identity as identity;
#[cfg(leaf_portals_deploy)]
pub use report_links as linker;
pub use report_profile as profile;
pub use report_sources as source_map;
#[cfg(leaf_storage_disk_test)]
pub use test_drive as drive_test;
#[cfg(leaf_network_device_whitelist)]
pub use whitelist_device as firewall;
#[cfg(leaf_log_write)]
pub use write_appliance_log as hyalos;

pub mod legacy_sbin {
    pub use crate::routes::discovery::{
        legacy_sbin_list_json as list_json, legacy_sbin_show_json as show_json,
    };
    pub fn list() -> i32 {
        crate::routes::discovery::cli("legacy-sbin", None)
    }
    pub fn show(id: &str) -> i32 {
        crate::routes::discovery::cli("legacy-sbin", Some(id))
    }
}
pub mod homeserver_sbin {
    pub use crate::routes::discovery::{
        homeserver_sbin_list_json as list_json, homeserver_sbin_show_json as show_json,
    };
    pub fn list() -> i32 {
        crate::routes::discovery::cli("homeserver-sbin", None)
    }
    pub fn show(id: &str) -> i32 {
        crate::routes::discovery::cli("homeserver-sbin", Some(id))
    }
}

// Small CLI compatibility adapters retained at the leaf boundary.

#[path = "canopy.rs"]
pub(crate) mod canopy;
