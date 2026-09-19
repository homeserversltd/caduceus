use crate::gate::{api_error, api_error_signal, ApiErrorBody};
use crate::shared::{harmonia, policy};
use axum::{http::StatusCode, Json};
use serde_json::{json, Value};

pub const NAMESPACE: &str = "update/module";
const COMMAND: &str = "update module";

fn module_request(raw: &Value) -> Result<(&str, bool), String> {
    let module = raw
        .get("target")
        .and_then(Value::as_object)
        .and_then(|target| target.get("module"))
        .and_then(Value::as_str)
        .ok_or_else(|| "caduceus-update-module-target-missing".to_string())?;
    let apply = raw
        .get("flags")
        .and_then(Value::as_object)
        .and_then(|flags| flags.get("apply"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    Ok((module, apply))
}

fn declaration() -> Result<(Value, Vec<Value>), String> {
    let source = crate::routes::selected_declaration(NAMESPACE)
        .ok_or_else(|| "caduceus-update-module-declaration-missing".to_string())?;
    let declaration: Value = serde_json::from_str(source)
        .map_err(|_| "caduceus-update-module-declaration-invalid".to_string())?;
    let serve = declaration
        .get("serve")
        .and_then(Value::as_array)
        .cloned()
        .ok_or_else(|| "caduceus-update-module-serve-missing".to_string())?;
    Ok((declaration, serve))
}

pub fn execute_envelope(raw: Value) -> Result<Value, String> {
    let (module, apply) = module_request(&raw)?;
    let module = module.to_owned();
    let (declaration, serve) = declaration()?;
    let mut response = crate::gate::receive(raw, &serve, &declaration, false)?;
    let (exit_code, stdout) = harmonia::invoke_update_module(&module, apply);
    let parsed_receipt = serde_json::from_str::<Value>(stdout.trim())
        .unwrap_or_else(|_| Value::String(stdout.clone()));
    let child = harmonia::invoke_body_to_json("update_module", exit_code, &stdout);
    let child_ok = parsed_receipt
        .get("ok")
        .and_then(Value::as_bool)
        .unwrap_or(exit_code == 0);
    let ok = exit_code == 0 && child_ok;
    let first_missing_signal = parsed_receipt
        .get("first_missing_signal")
        .and_then(Value::as_str)
        .unwrap_or(if ok { "none" } else { "caduceus-harmonia-command-failed" });
    response["ok"] = Value::Bool(ok);
    response["exitCode"] = json!(exit_code);
    response["receiptPayload"] = parsed_receipt.clone();
    response["rawChildStdout"] = Value::String(stdout);
    response["harmoniaReceipt"] = child;
    response["first_missing_signal"] = Value::String(first_missing_signal.to_string());
    Ok(response)
}

pub(crate) async fn route(
    Json(raw): Json<Value>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<ApiErrorBody>)> {
    match policy::allows_command(COMMAND) {
        Ok(true) => match execute_envelope(raw) {
            Ok(value) => Ok((crate::gate::mutation_status(&value), Json(value))),
            Err(error) => Err(api_error_signal(COMMAND, &error)),
        },
        Ok(false) => Err(api_error(COMMAND)),
        Err(_) => Err(api_error_signal(COMMAND, "caduceus-profile-missing")),
    }
}

pub fn cli(rest: &[String]) -> i32 {
    let Some(module) = rest.iter().find(|arg| !arg.starts_with('-')) else {
        eprintln!("caduceus-update-module-target-missing");
        return 2;
    };
    let raw = json!({
        "schema": crate::protocol::SCHEMA_ID,
        "intent_id": format!("cli:{NAMESPACE}"),
        "transition": "update.module",
        "version": "1",
        "timestamp": "0",
        "origin_of_intent": "near",
        "target": {"module": module},
        "flags": {"apply": rest.iter().any(|arg| arg == "--apply")}
    });
    match execute_envelope(raw) {
        Ok(value) => {
            println!("{value}");
            if value.get("ok").and_then(Value::as_bool) == Some(true) {
                0
            } else {
                1
            }
        }
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/update/module", axum::routing::post(route))
}
