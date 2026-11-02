//! In-process route invocation for PID 2. The response body is transient.
use axum::{body::{to_bytes, Body}, http::Request};
use serde_json::{Map, Value};
use tower::ServiceExt;

pub(crate) struct Projection {
    pub status: u16,
    pub ok: Option<bool>,
    pub signal: Option<String>,
    pub kept: String,
    pub fresh_until: Option<f64>,
}

fn refused(status:u16, signal:&str)->Projection {
    Projection{status,ok:Some(false),signal:Some(signal.to_owned()),kept:"{}".into(),fresh_until:None}
}

fn forbidden(value:&Value)->bool {
    match value {
        Value::Object(fields)=>fields.iter().any(|(key,value)|matches!(key.as_str(),"envelope"|"receiptPayload"|"rawEnvelope"|"rawChildStdout"|"rawChildStderr"|"raw_envelope"|"stamped_envelope") || forbidden(value)),
        Value::Array(items)=>items.iter().any(forbidden),
        _=>false,
    }
}

pub(crate) fn call(namespace: &str, payload: Option<&Value>, keep: &[String], seconds: u64) -> Result<Projection,String> {
    if !(1..=600).contains(&seconds) { return Err("pid2-route-deadline-out-of-range".into()); }
    let declaration: Value = serde_json::from_str(crate::routes::selected_declaration(namespace).ok_or("pid2-route-unselected")?).map_err(|_|"pid2-route-declaration-invalid")?;
    let path=declaration.get("http_path").and_then(Value::as_str).map(str::to_owned).unwrap_or_else(||format!("/api/v1/{namespace}"));
    let method=declaration.get("http_method").and_then(Value::as_str);
    if declaration.get("administrative").and_then(Value::as_bool)==Some(true) || super::administrative_routes_match(method,&path).map_err(|_|"pid2-route-classification-unavailable")? {return Err("pid2-route-administrative-refused".into());}
    if method!=Some("GET") || declaration.get("mutation_allowed").and_then(Value::as_bool)!=Some(false) {return Err("pid2-route-not-a-read".into());}
    let router=super::router();
    let body=payload.map(serde_json::to_vec).transpose().map_err(|_|"pid2-route-payload-invalid")?.unwrap_or_default();
    let request=Request::builder().method(method.unwrap_or("GET")).uri(&path).header("content-type","application/json").body(Body::from(body)).map_err(|_|"pid2-route-request-invalid")?;
    let runtime=tokio::runtime::Handle::try_current().map_err(|_|"pid2-route-runtime-unavailable")?;
    runtime.block_on(async move {
        tokio::time::timeout(std::time::Duration::from_secs(seconds),async move {
            let response=router.oneshot(request).await.map_err(|_|"pid2-route-dispatch-failed")?;
            let status=response.status().as_u16();
            let bytes=match to_bytes(response.into_body(),2*1024*1024).await {
                Ok(bytes)=>bytes,
                Err(_) if status>=400=>return Ok(refused(status,"pid2-route-response-unavailable")),
                Err(_)=>return Err("pid2-route-response-unavailable".into()),
            };
            let answer:Value=match serde_json::from_slice::<Value>(&bytes) {
                Ok(answer) if answer.is_object()=>answer,
                _ if status>=400=>return Ok(refused(status,"pid2-route-answer-invalid")),
                _=>return Err("pid2-route-answer-invalid".into()),
            };
            let ok=answer.get("ok").and_then(Value::as_bool);
            let signal=match answer.get("firstMissingSignal").and_then(Value::as_str) {
                Some(value) if value.len()>256 && status>=400 =>return Ok(refused(status,"pid2-route-signal-too-large")),
                Some(value) if value.len()>256 =>return Err("pid2-route-signal-too-large".into()),
                Some(value)=>Some(value.to_owned()),
                None=>None,
            };
            if answer.get("schema").and_then(Value::as_str)==Some("caduceus.api.error.v1") || (status>=400 && ok!=Some(false)) {
                return Ok(refused(status,signal.as_deref().unwrap_or("pid2-route-refused")));
            }
            let fresh_until=answer.get("freshUntil").and_then(Value::as_f64);
            let mut kept=Map::new();
            for key in keep {
                if matches!(key.as_str(),"receiptPayload"|"rawEnvelope"|"rawChildStdout"|"rawChildStderr"|"raw_envelope"|"stamped_envelope") {return Err("pid2-route-keep-forbidden".into());}
                kept.insert(key.clone(),answer.get(key).cloned().unwrap_or(Value::Null));
            }
            if forbidden(&Value::Object(kept.clone())) {return Err("pid2-route-keep-forbidden".into());}
            if Value::Object(kept.clone())==answer {return Err("pid2-route-keep-whole-body".into());}
            let kept=serde_json::to_string(&kept).map_err(|_|"pid2-route-projection-invalid")?;
            if kept.len()>1024 {return Err("pid2-route-keep-too-large".into());}
            Ok(Projection{status,ok,signal,kept,fresh_until})
        }).await.map_err(|_|"pid2-route-timeout".to_owned())?
    })
}
