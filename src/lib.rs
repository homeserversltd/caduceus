pub mod bands;
#[path = "lib/mod.rs"]
pub mod shared;
pub mod staff_commands;
pub mod trigger_gate;
#[doc(hidden)]
pub use shared as tools;
pub use trigger_gate::run;
