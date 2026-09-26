use caduceus::shared::policy;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct RootEnv(Option<OsString>);

impl RootEnv {
    fn set(root: &Path) -> Self {
        let previous = std::env::var_os("CADUCEUS_ROOT");
        std::env::set_var("CADUCEUS_ROOT", root);
        Self(previous)
    }
}

impl Drop for RootEnv {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => std::env::set_var("CADUCEUS_ROOT", value),
            None => std::env::remove_var("CADUCEUS_ROOT"),
        }
    }
}

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "caduceus-probe-policy-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn birth(root: &Path, profile: &str) {
    let appliance = root.join("etc/appliance");
    fs::create_dir_all(&appliance).unwrap();
    fs::write(
        appliance.join("profile.json"),
        format!(r#"{{"name":"chia-farmer-01","profile":"{profile}"}}"#),
    )
    .unwrap();
}

const NARROW_COMMANDS: [&str; 10] = [
    "network status",
    "site-local command",
    "site-local command two",
    "site-local command three",
    "site-local command four",
    "site-local command five",
    "site-local command six",
    "site-local command seven",
    "site-local command eight",
    "site-local command nine",
];

fn profile_yaml(root: &Path, commands: &[&str]) {
    let dir = root.join("etc/caduceus");
    fs::create_dir_all(&dir).unwrap();
    let mut text = String::from("commands:\n");
    for command in commands {
        text.push_str(&format!("- {command}\n"));
    }
    fs::write(dir.join("profile.yaml"), text).unwrap();
}

#[test]
fn probe_compiled_command_floor_and_original_file_fallback_are_preserved() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = root();
    birth(&root, "chia-farmer-01");
    let _root_env = RootEnv::set(&root);

    // Unknown immutable birth identities normalize to the probe profile.
    assert_eq!(
        caduceus::shared::config::resolved_profile().unwrap(),
        "probe"
    );

    // The immutable probe grammar admits its read floor without a mutable policy file.
    assert!(policy::allows_command("appliance stats read").unwrap());
    assert!(policy::allows_command("doors read").unwrap());
    // Policy admission only: never dispatch or execute this destructive command.
    assert!(policy::allows_command("disk wipe").unwrap());

    // A narrower household file cannot remove commands in the compiled probe floor.
    profile_yaml(&root, &NARROW_COMMANDS);
    let narrowed: serde_yaml::Value =
        serde_yaml::from_str(&fs::read_to_string(root.join("etc/caduceus/profile.yaml")).unwrap())
            .unwrap();
    let narrowed_commands = narrowed["commands"].as_sequence().unwrap();
    assert_eq!(narrowed_commands.len(), 10);
    assert!(!narrowed_commands
        .iter()
        .any(|command| command.as_str() == Some("appliance stats read")));
    assert!(policy::allows_command("appliance stats read").unwrap());

    // Commands beyond the compiled floor still use the original file gate.
    assert!(policy::allows_command("site-local command").unwrap());
    assert!(!policy::allows_command("not compiled or configured").unwrap());

    // Sold profiles retain the existing file-only command policy.
    birth(&root, "homeconsole");
    profile_yaml(&root, &["network status"]);
    assert!(!policy::allows_command("appliance stats read").unwrap());
    assert!(policy::allows_command("network status").unwrap());

    // An unresolved birth profile still reaches the original file-gate behavior.
    fs::remove_file(root.join("etc/appliance/profile.json")).unwrap();
    profile_yaml(&root, &["appliance stats read"]);
    assert!(policy::allows_command("appliance stats read").unwrap());

    drop(_root_env);
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn probe_stats_http_body_and_profile_refusals_are_real() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let root = root();
    birth(&root, "chia-farmer-01");
    let _root_env = RootEnv::set(&root);

    // Start the real collector and wait only within a fixed budget for its first sample.
    caduceus::stats::start();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut last_error = None;
    while Instant::now() < deadline {
        match caduceus::stats::current() {
            Ok(_) => {
                last_error = None;
                break;
            }
            Err(error) => {
                last_error = Some(error);
                std::thread::sleep(Duration::from_millis(25));
            }
        }
    }
    assert!(
        last_error.is_none(),
        "real stats collector did not produce a sample: {last_error:?}"
    );

    let stats = caduceus::routes::serve::router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/appliance/stats")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(stats.status(), axum::http::StatusCode::OK);
    let stats: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(stats.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(stats["schema"], "caduceus.appliance.stats.sample.v1");
    assert!(stats["ts"].is_i64());
    assert!(stats["cpu"].is_object());
    assert!(stats["memory"].is_object());

    // The immutable probe grammar admits the doors read without a mutable policy file.
    let doors = caduceus::routes::serve::router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/doors")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(doors.status(), axum::http::StatusCode::OK);

    // The declared tv policy omits stats; admission must refuse before reading data.
    birth(&root, "tv");
    profile_yaml(&root, &["network status"]);
    let refused = caduceus::routes::serve::router()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/v1/appliance/stats")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refused.status(), axum::http::StatusCode::FORBIDDEN);

    drop(_root_env);
    fs::remove_dir_all(root).unwrap();
}
