// C2 root route canopy.
#[path = "../lib/primitives.rs"]
pub mod primitives;
pub use crate::stats;
pub mod profile_routes {
    include!(concat!(env!("OUT_DIR"), "/profile_routes.rs"));
}
include!(concat!(env!("OUT_DIR"), "/selected_leaves.rs"));
pub use leaf_cartridges_admit as admit_cartridge;
pub use leaf_network_device_annotate as annotate_device;
pub use leaf_portals_admit as admit_portal;
#[path = "cartridges/support/cartridges_shared.rs"]
pub mod cartridges_shared;
pub use leaf_admin_admittance_change_pin as change_pin;
pub use leaf_network_device_claim as claim_device_identity;
pub use leaf_settings_appearance as change_appearance;
pub use leaf_settings_datetime as change_datetime;
pub use leaf_settings_default_apps as change_default_apps;
pub use leaf_settings_display as change_display;
pub use leaf_settings_input as change_input;
pub use leaf_settings_notifications as change_notifications;
pub use leaf_settings_sound as change_sound;
#[path = "cli.rs"]
pub mod cli;
#[path = "display/projector/index.rs"]
pub mod control_projector;
pub use leaf_network_dns_status as control_resolver;
#[path = "appliance/service/support/control_service/index.rs"]
pub mod control_service;
#[path = "discovery.rs"]
pub mod discovery;
pub use leaf_settings_ssh as expose_ssh;
#[path = "admin-admittance/support.rs"]
pub(crate) mod admin_admittance_support;
#[path = "appliance/support.rs"]
pub(crate) mod appliance_support;
#[path = "cartridges/support/routes.rs"]
pub(crate) mod cartridges_route_support;
pub use crate::gate;
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
pub use leaf_network_cert_trust as install_trust;
pub use leaf_storage_disk_census as inspect_disks;
#[path = "network/cert/support/dependent_reload/index.rs"]
pub mod cert_dependent_reload;
#[path = "network/cert/support/issue_certificate/index.rs"]
pub mod issue_certificate;
pub use leaf_appliance_name as name_device;
pub use leaf_cartridges_list as list_cartridges;
pub use leaf_network_bandwidth_measure as measure_bandwidth;
pub use leaf_network_device_list as list_network_devices;
pub use leaf_network_tailnet as manage_tailnet;
pub use leaf_network_vpn as manage_vpn;
pub use leaf_settings_child_device as manage_child_device;
#[path = "settings/support/open_settings_pane/index.rs"]
pub mod open_settings_pane;
pub use leaf_local_ai_query as query_local_ai;
pub use leaf_log_read as read_appliance_log;
pub use leaf_network_device_pin_address as pin_device_address;
pub use leaf_storage_vault_unlock as open_vault;
#[path = "log/read/support/read_logs/index.rs"]
pub mod read_logs;
pub use leaf_log_receipts as read_receipts;
#[path = "appliance/report/support/rebuild_crown/index.rs"]
pub mod rebuild_crown;
pub use leaf_appliance_report as report_health;
pub use leaf_cartridges_remove as remove_cartridge;
#[path = "appliance/report/support/report_identity/index.rs"]
pub mod report_identity;
#[path = "portals/deploy/support/report_links/index.rs"]
pub mod report_links;
#[path = "appliance/report/support/report_profile/index.rs"]
pub mod report_profile;
#[path = "appliance/report/support/report_sources/index.rs"]
pub mod report_sources;
pub use leaf_network_status as set_time;
pub use leaf_storage_disk_test as test_drive;
pub use leaf_update_now as sync_sources;
pub use leaf_update_status as toggle_harmonia_module;
#[path = "update/now/support/update_appliance/index.rs"]
pub mod update_appliance;
pub use leaf_log_write as write_appliance_log;
pub use leaf_network_device_wake as wake_device;
pub use leaf_network_device_whitelist as whitelist_device;

pub use crate::gate as serve;
pub use cli as help;
pub use gate_receipts as staff;

pub use annotate_device as network_notes;
pub use claim_device_identity as network_identity;
pub use control_resolver as dns_control;
pub use inspect_disks as disk;
pub(crate) use leaf_network_dhcp_status::network_read_route;
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
