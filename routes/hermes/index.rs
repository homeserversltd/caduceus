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
    // Two anchors only. The declared HomeSI venv (/opt/hermes/venv) launches
    // the gateway; hermes_bootstrap then re-execs it into the runtime Hermes
    // manages under the hermes account's HERMES_HOME, /home/hermes/.hermes/tools.
    // From that runtime a process counts when its -c script is the last
    // argument, carries the relaunch markers (sys._hermes_relaunched = True and
    // the gateway/run argv assignment) and ends with the exec'd runpy entry, the
    // same tail test the venv form uses. A
    // same-named binary elsewhere, another account's home, or system Python
    // running a similarly named module is not it
    // (pali:si-homesi-website-portals-and-hermes-count-20261024 organ HermesIdentity).
    let venv = venv_python(program);
    if !venv && !relaunch_python(program) {
        return false;
    }
    let mut index = 1;
    while let Some(argument) = args.get(index) {
        match *argument {
            b"-I" | b"-B" | b"-u" | b"-s" | b"-E" | b"-S" | b"-O" | b"-OO" => index += 1,
            b"-c" => {
                let Some(script) = args.get(index + 1) else {
                    return false;
                };
                let script = String::from_utf8_lossy(script);
                let script = script.trim_end();
                if !venv {
                    // The relaunch carries gateway/run inside its own argv
                    // assignment and execs the venv bootstrap verbatim.
                    return args.len() == index + 2
                        && script.contains("sys._hermes_relaunched = True")
                        && script.contains("sys.argv = ['-c', 'gateway', 'run']")
                        && script.ends_with(
                            "runpy.run_module('hermes_cli.main', run_name='__main__', alter_sys=True)\")",
                        );
                }
                // The gateway service's isolated bootstrap ends with this
                // entry call and carries the explicit gateway/run argv. Its
                // stop-mark and cgroup-cleanup helpers cannot match either.
                let gateway_run = args.get(index + 2).copied() == Some(b"gateway".as_slice())
                    && args.get(index + 3).copied() == Some(b"run".as_slice());
                return gateway_run
                    && script.ends_with(
                        "runpy.run_module('hermes_cli.main', run_name='__main__', alter_sys=True)",
                    );
            }
            script => return venv && script == b"/opt/hermes/venv/bin/hermes",
        }
    }
    false
}

fn venv_python(program: &[u8]) -> bool {
    program
        .strip_prefix(b"/opt/hermes/venv/bin/python")
        .is_some_and(|version| version.iter().all(|byte| byte.is_ascii_digit() || *byte == b'.'))
}

// /home/hermes/.hermes/tools/python-<build>/bin/python3[.N]: the runtime under
// the hermes account's own HERMES_HOME, nobody else's.
fn relaunch_python(program: &[u8]) -> bool {
    let Some(rest) = program.strip_prefix(b"/home/hermes/.hermes/tools/python-") else {
        return false;
    };
    let Some(build_end) = rest.iter().position(|byte| *byte == b'/') else {
        return false;
    };
    let (build, rest) = rest.split_at(build_end);
    let Some(version) = rest.strip_prefix(b"/bin/python3") else {
        return false;
    };
    !build.is_empty()
        && build != b"."
        && build != b".."
        && version.iter().all(|byte| byte.is_ascii_digit() || *byte == b'.')
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
