pub use crate::shared::attendance::{
    change_pin_access_json, change_pin_json, reset_default_pin_json, set_pin_mode_json,
};

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/admin-admittance/change-pin",
            axum::routing::post(crate::routes::admin_admittance_support::attendance_route),
        )
}
