/// C2 route leaf.
pub const NAMESPACE: &str = "access/gate";

use axum::Json;
use serde_json::{json, Value};

async fn access_gate_route() -> Json<Value> {
    let (vault_readable, present, mounted, auto_decrypt_enabled) =
        match crate::routes::open_vault::gate_posture_read() {
            Ok(Some(posture)) => (
                true,
                posture.present,
                posture.mounted,
                posture.auto_decrypt_enabled,
            ),
            Ok(None) => (true, false, false, false),
            Err(_) => (false, false, false, false),
        };
    let unlock_required = present && !mounted && !auto_decrypt_enabled;
    let (pin_required, pin_readable) = match crate::shared::attendance::pin_mode_read() {
        Ok(pin_required) => (pin_required, true),
        Err(_) => (false, false),
    };

    Json(json!({
        "ok": true,
        "vault": {
            "present": present,
            "mounted": mounted,
            "auto_decrypt_enabled": auto_decrypt_enabled,
            "unlock_required": unlock_required,
            "readable": vault_readable,
        },
        "pin": {
            "pin_required": pin_required,
            "readable": pin_readable,
        },
    }))
}

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router.route(
        "/api/v1/access/gate",
        axum::routing::get(access_gate_route),
    )
}
