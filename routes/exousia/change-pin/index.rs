pub use crate::shared::attendance::{
    change_pin_access_json, change_pin_json, reset_default_pin_json, set_pin_mode_json,
};

/// Canonical registration seam for this leaf.
pub fn register(router: axum::Router) -> axum::Router {
    router
        .route(
            "/api/v1/exousia/change-pin",
            axum::routing::post(crate::routes::exousia_support::attendance_route),
        )
        .route(
            "/api/v1/attendance/change-pin",
            axum::routing::post(crate::routes::exousia_support::attendance_route),
        )
        .route(
            "/api/v1/access/pin/mode",
            axum::routing::get(crate::routes::exousia_support::pin_mode_read_route)
                .post(crate::routes::exousia_support::pin_mode_route),
        )
        .route(
            "/api/v1/access/pin/reset-default",
            axum::routing::post(crate::routes::exousia_support::pin_reset_default_route),
        )
        .route(
            "/api/v1/access/pin/change",
            axum::routing::post(crate::routes::exousia_support::attendance_route),
        )
}
