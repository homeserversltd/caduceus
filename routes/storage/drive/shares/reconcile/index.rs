use axum::{extract::Json, http::StatusCode, Router};
use serde_json::{json, Value};

const COMMAND: &str = "staff intent";

async fn reconcile_route(
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<crate::gate::ApiErrorBody>)> {
    match policy::allows_command(COMMAND) {
        Ok(true) => {}
        Ok(false) => return Err(api_error(COMMAND)),
        Err(_) => {
            return Err(api_error_signal(
                COMMAND,
                "caduceus-carapace-desync",
            ));
        }
    }

    let context = crate::shared::load_trace::current();
    let crossed = gate::blocking_task(COMMAND, move || {
        crate::shared::load_trace::with_blocking_context(context, || {
            crate::gate::snake::crossing_path_receipt(
                "storage/drive/shares/rebuild",
                &json!({}),
            )
        })
    })
    .await?;
    let receipt = crossed.map_err(|signal| crate::gate::service_unavailable(COMMAND, &signal))?;
    let status = mutation_status(&receipt);
    Ok((status, Json(receipt)))
}

pub fn register(router: Router) -> Router {
    router.route(
        "/api/v1/storage/drive/shares/reconcile",
        axum::routing::post(reconcile_route),
    )
}
