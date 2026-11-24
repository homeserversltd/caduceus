use axum::{
    extract::rejection::JsonRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::{json, Value};
use std::{process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

const STOP: &str = "keyman/secret/put";
const VALUE_LIMIT: usize = 511;
const ABOUT_LIMIT: usize = 200;
const STDOUT_LIMIT: usize = 64 * 1024;
const REQUEST_INVALID: &str = "keyman-secret-request-invalid";
const NAME_INVALID: &str = "keyman-secret-name-invalid";
const ABOUT_INVALID: &str = "keyman-secret-about-invalid";
const VALUE_INVALID: &str = "keyman-secret-value-invalid";
const REPLY_INVALID: &str = "keyman-secret-reply-invalid";

// Wipe the owned value, serialized stdin and untrusted stdout on every exit.
struct Secret(Vec<u8>);

impl Secret {
    fn is_in(&self, bytes: &[u8]) -> bool {
        bytes.windows(self.0.len()).any(|window| window == self.0)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
    }
}

fn request(mut body: Value) -> Result<(Secret, Secret), &'static str> {
    let object = body.as_object_mut().ok_or(REQUEST_INVALID)?;
    // Own the value before checking the other fields, including on refusal.
    let value = match object.remove("value") {
        Some(Value::String(value)) => Some(Secret(value.into_bytes())),
        _ => None,
    };
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| {
            (1..=64).contains(&name.len())
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
        .ok_or(NAME_INVALID)?;
    let about = match object.get("about") {
        None | Some(Value::Null) => None,
        Some(Value::String(about))
            if about.chars().count() <= ABOUT_LIMIT && !about.chars().any(char::is_control) =>
        {
            Some(about.as_str())
        }
        _ => return Err(ABOUT_INVALID),
    };
    let value = value
        .filter(|value| {
            (1..=VALUE_LIMIT).contains(&value.0.len())
                && !value
                    .0
                    .iter()
                    .any(|b| matches!(b, 0 | b'\r' | b'\n' | b'"'))
        })
        .ok_or(VALUE_INVALID)?;

    let payload = json!({"name": name, "about": about});
    let envelope = crate::gate::snake::crossing_envelope(STOP, &payload);
    let (mut envelope, raw) = crate::gate::snake::prepare_envelope(&envelope)
        .map_err(|_| REQUEST_INVALID)?;
    let fields = envelope.as_object_mut().ok_or(REQUEST_INVALID)?;
    let payload = fields.remove("payload").ok_or(REQUEST_INVALID)?;
    let payload = payload.as_object().ok_or(REQUEST_INVALID)?;
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        #[serde(flatten)]
        fields: &'a serde_json::Map<String, Value>,
        value: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Envelope<'a> {
        #[serde(flatten)]
        fields: &'a serde_json::Map<String, Value>,
        payload: Payload<'a>,
    }
    // raw already includes name and about. Reserve six bytes per value byte
    // plus the value key and JSON punctuation before writing any secret.
    let mut input = Secret(Vec::with_capacity(raw.len() + value.0.len() * 6 + 13));
    let payload = Payload {
        fields: payload,
        value: std::str::from_utf8(&value.0).map_err(|_| VALUE_INVALID)?,
    };
    serde_json::to_writer(&mut input.0, &Envelope { fields, payload })
        .map_err(|_| REQUEST_INVALID)?;
    Ok((value, input))
}

fn reply_contains_value(bytes: &[u8], value: &Secret) -> Result<bool, &'static str> {
    if value.is_in(bytes) {
        return Ok(true);
    }
    // Check escaped strings too, including keys and repeated members a map
    // would discard. Let serde decode each escaped token, and wipe that copy.
    let mut wire = bytes.iter().enumerate();
    while let Some((start, _)) = wire.find(|(_, byte)| **byte == b'"') {
        let mut escaped = false;
        let end = loop {
            match wire.next() {
                Some((end, b'"')) => break end,
                Some((_, b'\\')) => {
                    escaped = true;
                    wire.next().ok_or(REPLY_INVALID)?;
                }
                Some(_) => {}
                None => return Err(REPLY_INVALID),
            }
        };
        if escaped {
            let decoded: String =
                serde_json::from_slice(&bytes[start..=end]).map_err(|_| REPLY_INVALID)?;
            if value.is_in(&Secret(decoded.into_bytes()).0) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn reply_status(bytes: &[u8], value: &Secret, exited_ok: bool) -> Result<StatusCode, &'static str> {
    if reply_contains_value(bytes, value)? {
        return Err(REPLY_INVALID);
    }
    let receipt: Value = serde_json::from_slice(bytes).map_err(|_| REPLY_INVALID)?;
    if !leaf_schema::bound(&receipt, STOP) {
        return Err(REPLY_INVALID);
    }
    let ok = receipt["ok"].as_bool().ok_or(REPLY_INVALID)?;
    let signal = receipt["firstMissingSignal"]
        .as_str()
        .ok_or(REPLY_INVALID)?;
    match (ok, signal) {
        (true, "none") if exited_ok && receipt["converged"].as_bool() != Some(false) => {
            Ok(StatusCode::OK)
        }
        (
            false,
            REQUEST_INVALID
            | NAME_INVALID
            | ABOUT_INVALID
            | VALUE_INVALID
            | "keyman-secret-name-builtin"
            | "keyman-secret-name-held",
        ) => Ok(StatusCode::BAD_REQUEST),
        (false, signal)
            if signal
                .strip_prefix("keyman-secret-")
                .is_some_and(|tail| !tail.is_empty()) =>
        {
            Ok(StatusCode::SERVICE_UNAVAILABLE)
        }
        _ => Err(REPLY_INVALID),
    }
}

async fn invoke(value: Secret, input: Secret) -> Result<(StatusCode, Secret), &'static str> {
    let cli = crate::gate::snake::cli_path();
    let mut command = if std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some() {
        Command::new(&cli)
    } else {
        let mut command = Command::new("/usr/bin/sudo");
        command.arg("-n").arg(&cli);
        command
    };
    let mut child = command
        .arg(STOP)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "keyman-secret-staff-unavailable")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or("keyman-secret-staff-stdin-failed")?;
    let mut stdout = child.stdout.take().ok_or(REPLY_INVALID)?;
    let read = async move {
        let mut bytes = Secret(vec![0; STDOUT_LIMIT + 1]);
        let mut len = 0;
        loop {
            let count = stdout
                .read(&mut bytes.0[len..])
                .await
                .map_err(|_| REPLY_INVALID)?;
            if count == 0 {
                bytes.0.truncate(len);
                return Ok(bytes);
            }
            len += count;
            if len > STDOUT_LIMIT {
                return Err("keyman-secret-staff-output-too-large");
            }
        }
    };
    let exchange = async {
        tokio::try_join!(
            async move { Ok(stdin.write_all(&input.0).await) },
            read,
            async {
                child
                    .wait()
                    .await
                    .map_err(|_| "keyman-secret-staff-wait-failed")
            },
        )
    };
    let result = tokio::time::timeout(Duration::from_secs(60), exchange)
        .await
        .unwrap_or(Err("keyman-secret-staff-timeout"));
    if result.is_err() {
        let _ = child.kill().await;
    }
    let (written, bytes, exit) = result?;
    let status = reply_status(&bytes.0, &value, exit.success())?;
    if written.is_err() && status == StatusCode::OK {
        return Err("keyman-secret-staff-stdin-failed");
    }
    Ok((status, bytes))
}

fn refusal(status: StatusCode, signal: &'static str) -> Response {
    // Only fixed signals leave the door. There is no accepted staff receipt
    // on this path, and a post-dispatch error does not prove no mutation.
    let attempt = if status == StatusCode::BAD_REQUEST {
        json!({"attempted": false})
    } else {
        Value::Null
    };
    let reply = json!({
        "schema": "caduceus.staff.receipt.v1",
        "stop": {"noun": "keyman/secret", "verb": "post"},
        "ok": false,
        "firstMissingSignal": signal,
        "observed": null,
        "could_change_to": null,
        "attempt": attempt,
        "final_receipt": {"ok": false, "firstMissingSignal": signal},
    });
    (status, Json(reply)).into_response()
}

async fn put(body: Result<Json<Value>, JsonRejection>) -> Response {
    let body = match body {
        Ok(Json(body)) => body,
        Err(_) => return refusal(StatusCode::BAD_REQUEST, REQUEST_INVALID),
    };
    let (value, input) = match request(body) {
        Ok(request) => request,
        Err(signal) => return refusal(StatusCode::BAD_REQUEST, signal),
    };
    // Once dispatched, let the bounded crossing finish even if the caller leaves.
    match tokio::spawn(invoke(value, input)).await {
        Ok(Ok((status, mut reply))) => (
            status,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            std::mem::take(&mut reply.0),
        )
            .into_response(),
        Ok(Err(signal)) => refusal(StatusCode::SERVICE_UNAVAILABLE, signal),
        Err(_) => refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "keyman-secret-staff-task-failed",
        ),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/keyman/secret", axum::routing::post(put))
}
