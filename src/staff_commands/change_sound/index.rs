pub const PANE: &str = "sound";
pub fn read_json() -> Result<serde_json::Value, String> {
    crate::shared::settings::read_json(PANE)
}
pub fn mutate_json(body: serde_json::Value) -> Result<serde_json::Value, String> {
    crate::shared::settings::mutate_json(PANE, body)
}
