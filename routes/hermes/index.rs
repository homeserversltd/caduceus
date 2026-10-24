use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::json;
use std::fs::{self, File};
use std::io::{self, Read};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SCHEMA: &str = "caduceus.hermes.alive.v1";
const TTL: Duration = Duration::from_secs(3);
const CMDLINE_PREFIX: u64 = 64 * 1024;

// Recomputable scalar observation only: no PID list, request or reply survives.
struct Observation {
    alive: u64,
    observed_at: DateTime<Utc>,
    refreshed: Instant,
}
static CACHE: Mutex<Option<Observation>> = Mutex::new(None);

fn hermes_entry(args: &[&[u8]]) -> bool {
    let Some(program) = args.first() else {
        return false;
    };
    if *program == b"/opt/hermes/venv/bin/hermes" {
        return true;
    }
    // Both launchers belong to the declared HomeSI venv. A same-named binary
    // elsewhere, or system Python running a similarly named module, is not it.
    let Some(version) = program.strip_prefix(b"/opt/hermes/venv/bin/python") else {
        return false;
    };
    if !version
        .iter()
        .all(|byte| byte.is_ascii_digit() || *byte == b'.')
    {
        return false;
    }
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        match *argument {
            b"-I" | b"-B" | b"-u" | b"-s" | b"-E" | b"-S" | b"-O" | b"-OO" => index += 1,
            b"-c" => {
                // The gateway service's isolated bootstrap ends with this
                // entry call and carries the explicit gateway/run argv. Its
                // stop-mark and cgroup-cleanup helpers cannot match either.
                let gateway_run = args.get(index + 2).copied() == Some(b"gateway".as_slice())
                    && args.get(index + 3).copied() == Some(b"run".as_slice());
                return gateway_run
                    && args.get(index + 1).is_some_and(|script| {
                        let script = String::from_utf8_lossy(script);
                        script.trim_end().ends_with(
                        "runpy.run_module('hermes_cli.main', run_name='__main__', alter_sys=True)",
                    )
                    });
            }
            script => return script == b"/opt/hermes/venv/bin/hermes",
        }
    }
    false
}

fn disappeared(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH)
}

fn count_alive() -> Result<u64, &'static str> {
    let entries = fs::read_dir("/proc").map_err(|_| "caduceus-hermes-proc-unavailable")?;
    let mut alive = 0u64;
    for entry in entries {
        let entry = entry.map_err(|_| "caduceus-hermes-proc-unavailable")?;
        let name = entry.file_name();
        let Some(pid) = name.to_str() else {
            continue;
        };
        if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        // Only top-level PIDs, never /proc/<pid>/task threads. Zombies expose
        // an empty cmdline and cannot contribute to the count.
        let file = match File::open(entry.path().join("cmdline")) {
            Ok(file) => file,
            Err(error) if disappeared(&error) => continue,
            Err(_) => return Err("caduceus-hermes-cmdline-unavailable"),
        };
        let mut bytes = Vec::new();
        match file.take(CMDLINE_PREFIX).read_to_end(&mut bytes) {
            Ok(_) => {}
            Err(error) if disappeared(&error) => continue,
            Err(_) => return Err("caduceus-hermes-cmdline-unavailable"),
        }
        let args = bytes
            .split(|byte| *byte == 0)
            .filter(|argument| !argument.is_empty())
            .collect::<Vec<_>>();
        if hermes_entry(&args) {
            alive += 1;
        }
    }
    Ok(alive)
}

fn observation() -> Result<serde_json::Value, &'static str> {
    let mut cache = CACHE
        .lock()
        .map_err(|_| "caduceus-hermes-cache-unavailable")?;
    if cache
        .as_ref()
        .map_or(true, |sample| sample.refreshed.elapsed() >= TTL)
    {
        let alive = count_alive()?;
        *cache = Some(Observation {
            alive,
            observed_at: Utc::now(),
            refreshed: Instant::now(),
        });
    }
    let sample = cache
        .as_ref()
        .ok_or("caduceus-hermes-observation-unavailable")?;
    let value = json!({
        "schema": SCHEMA,
        "ok": true,
        "alive": sample.alive,
        "observed_at": sample.observed_at.to_rfc3339_opts(SecondsFormat::Millis, true),
    });
    if !crate::routes::leaf_schema::accepts(SCHEMA, &value) {
        return Err("caduceus-hermes-schema-desync");
    }
    Ok(value)
}

async fn alive() -> Response {
    match crate::gate::blocking_task("hermes alive", observation).await {
        Ok(Ok(value)) => Json(value).into_response(),
        Ok(Err(signal)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"schema":"caduceus.api.error.v1", "ok":false,
                "command":"hermes alive", "firstMissingSignal":signal})),
        )
            .into_response(),
        Err(error) => error.into_response(),
    }
}

pub fn register(router: axum::Router) -> axum::Router {
    router.route("/api/v1/hermes/alive", axum::routing::get(alive))
}
