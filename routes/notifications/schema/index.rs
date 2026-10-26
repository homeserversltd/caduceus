use axum::response::{IntoResponse, Response};
use serde_json::Value;
use std::sync::OnceLock;

const BYTES: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/schema/caduceus.notifications.v1.json"
));

pub(super) fn declaration() -> &'static Value {
    static SEAT: OnceLock<Value> = OnceLock::new();
    SEAT.get_or_init(|| {
        let seat: Value = serde_json::from_str(BYTES).expect("link-up-schema-desync");
        assert_eq!(
            seat["schema"], "caduceus.notifications.v1",
            "link-up-schema-desync"
        );
        assert!(seat["required"].is_array(), "link-up-schema-kernel-missing");
        seat
    })
}

async fn schema() -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        BYTES,
    )
        .into_response()
}

pub fn register(router: axum::Router) -> axum::Router {
    let _ = declaration();
    router.route(
        "/api/v1/schema/caduceus.notifications.v1",
        axum::routing::get(schema),
    )
}
