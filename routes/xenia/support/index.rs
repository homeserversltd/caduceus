use serde_json::{json, Value};

pub mod seat {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/routes/xenia/support/seat.rs"
    ));
}
pub mod store {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/routes/xenia/support/store.rs"
    ));
}
pub mod observe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/routes/xenia/support/observe.rs"
    ));
}
pub mod remote {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/routes/xenia/support/remote.rs"
    ));
}
pub mod validation {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/routes/xenia/support/validation.rs"
    ));
}
pub mod doors {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/routes/xenia/support/doors.rs"
    ));
}

pub const XENIA: &str = "appliance.xenia.v1";
pub const VERDICT: &str = "caduceus.xenia.verdict.v1";

#[derive(Debug)]
pub struct Refusal {
    pub check: String,
    pub field: String,
    pub message: String,
    pub suggestion: String,
}
pub type Result<T> = std::result::Result<T, Refusal>;

impl Refusal {
    pub fn new(check: &str, field: &str, message: impl Into<String>, suggestion: &str) -> Self {
        Self {
            check: check.into(),
            field: field.into(),
            message: message.into(),
            suggestion: suggestion.into(),
        }
    }
    pub fn value(&self) -> Value {
        json!({"schema": VERDICT, "ok": false, "verdict": "refused", "check": self.check,
            "field": self.field, "message": self.message, "suggestion": self.suggestion})
    }
}

pub fn observation(check: &str, field: &str, error: impl Into<String>) -> Refusal {
    Refusal::new(
        check,
        field,
        error,
        "Restore the named observation and repeat this door call.",
    )
}

pub fn startup() {
    // Retain startup failure for a named door refusal, not a router panic.
    let _ = seat::startup();
}
