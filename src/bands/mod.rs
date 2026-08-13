pub use crate::staff_commands::annotate_device as network_notes;
pub use crate::staff_commands::claim_device_identity as network_identity;
pub use crate::staff_commands::control_resolver as dns_control;
pub use crate::staff_commands::inspect_disks as disk;
pub use crate::staff_commands::list_network_devices as network;
pub use crate::staff_commands::list_network_devices as network_read;
pub use crate::staff_commands::manage_child_device as child_device;
pub use crate::staff_commands::measure_bandwidth as speedtest;
pub use crate::staff_commands::name_device as dns;
pub use crate::staff_commands::pin_device_address as dhcp;
pub use crate::staff_commands::report_health as health;
pub use crate::staff_commands::test_drive as drive_test;
pub use crate::staff_commands::whitelist_device as firewall;
pub mod help;
pub use crate::staff_commands::query_local_ai as local_ai;
pub use crate::staff_commands::read_logs as logs;
pub use crate::staff_commands::read_receipts as receipts;
pub use crate::staff_commands::report_identity as identity;
pub use crate::staff_commands::report_links as linker;
pub use crate::staff_commands::report_profile as profile;
pub use crate::staff_commands::write_appliance_log as hyalos;
pub mod serve;
pub use crate::staff_commands::report_sources as source_map;
pub mod staff;

pub mod homeserver_sbin {
    pub use crate::trigger_gate::discovery::{
        homeserver_sbin_list_json as list_json, homeserver_sbin_show_json as show_json,
    };
    pub fn list() -> i32 {
        crate::trigger_gate::discovery::cli("homeserver-sbin", None)
    }
    pub fn show(id: &str) -> i32 {
        crate::trigger_gate::discovery::cli("homeserver-sbin", Some(id))
    }
}
pub mod legacy_sbin {
    pub use crate::trigger_gate::discovery::{
        legacy_sbin_list_json as list_json, legacy_sbin_show_json as show_json,
    };
    pub fn list() -> i32 {
        crate::trigger_gate::discovery::cli("legacy-sbin", None)
    }
    pub fn show(id: &str) -> i32 {
        crate::trigger_gate::discovery::cli("legacy-sbin", Some(id))
    }
}
