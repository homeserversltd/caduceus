#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandReceipt {
    pub ok: bool,
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}
