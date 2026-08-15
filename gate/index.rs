#[path = "admittance/index.rs"]
pub mod admittance;
#[path = "discovery/index.rs"]
pub mod discovery;
#[path = "receipts/index.rs"]
pub mod receipts;

use crate::protocol::Envelope;
use serde_json::Value;

pub fn receive(
    raw: Value,
    route_set: &[Value],
    band_declaration: &Value,
    attendance_witness: bool,
) -> Result<Value, String> {
    let envelope = Envelope::parse(raw)?;
    let admittance = admittance::check_declared_admittance(band_declaration)?;
    let _walked = discovery::walk_compiled_route_set(route_set)?;
    Ok(receipts::append_stamp(
        &envelope,
        admittance,
        attendance_witness,
        true,
        true,
        None,
    ))
}
