use axum::{
    body::Body,
    extract::connect_info::ConnectInfo,
    http::{Request, StatusCode},
};
use caduceus::gate::{self, ConnectionInfo};
use std::thread;
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
    time::Duration,
};
use tower::ServiceExt;

static ENV_LOCK: Mutex<()> = Mutex::new(());
static SOCKET_COUNTER: AtomicU64 = AtomicU64::new(0);

fn remove_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        let _ = fs::remove_dir(parent);
    }
}

fn socket_path(test: &str) -> PathBuf {
    let counter = SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed);
    let parent = std::env::temp_dir().join(format!("cdu-{}-{counter}", std::process::id()));
    fs::create_dir(&parent).unwrap();
    let mut perms = fs::metadata(&parent).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&parent, perms).unwrap();
    let cparent = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { chown(cparent.as_ptr(), geteuid(), getegid()) }, 0);
    parent.join(format!("{test}.sock"))
}

#[tokio::test]
async fn tcp_and_uds_share_health_and_route_shape() {
    let app = gate::router();
    let tcp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let mut uds_request = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();
    uds_request
        .extensions_mut()
        .insert(ConnectInfo(ConnectionInfo::Unix {
            uid: 1,
            gid: 1,
            pid: 1,
        }));
    let uds = app.oneshot(uds_request).await.unwrap();
    assert_eq!(tcp.status(), StatusCode::OK);
    assert_eq!(uds.status(), StatusCode::OK);
    assert_eq!(
        axum::body::to_bytes(tcp.into_body(), usize::MAX)
            .await
            .unwrap(),
        axum::body::to_bytes(uds.into_body(), usize::MAX)
            .await
            .unwrap()
    );
    let missing = gate::router()
        .oneshot(
            Request::builder()
                .uri("/not-a-route")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "current_thread")]
async fn socket_is_owned_by_current_uid_with_exact_staff_mode() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = socket_path("metadata");
    let _ = fs::remove_file(&path);
    std::env::set_var("CADUCEUS_STAFF_GROUP", unsafe { getegid() }.to_string());
    let (_listener, identity) = gate::prepare_staff_socket(&path).unwrap();
    let meta = fs::metadata(&path).unwrap();
    assert_eq!(meta.permissions().mode() & 0o777, 0o660);
    assert_eq!(meta.uid(), unsafe { geteuid() });
    assert_eq!(meta.gid(), unsafe { getegid() });
    let parent = fs::symlink_metadata(path.parent().unwrap()).unwrap();
    assert_eq!(parent.permissions().mode() & 0o777, 0o755);
    assert_eq!(parent.uid(), unsafe { geteuid() });
    assert_eq!(parent.gid(), unsafe { getegid() });
    gate::cleanup_staff_socket(&path, &identity).unwrap();
    assert!(!path.exists());
    remove_parent(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn collisions_are_refused_and_live_socket_is_never_unlinked() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let symlink = socket_path("symlink");
    let regular = socket_path("regular");
    let live = socket_path("live");
    let _ = fs::remove_file(&symlink);
    let _ = fs::remove_file(&regular);
    let _ = fs::remove_file(&live);
    fs::write(&regular, b"not a socket").unwrap();
    std::os::unix::fs::symlink(&regular, &symlink).unwrap();
    assert!(gate::prepare_staff_socket(&symlink).is_err());
    assert!(gate::prepare_staff_socket(&regular).is_err());
    std::env::set_var("CADUCEUS_STAFF_GROUP", unsafe { getegid() }.to_string());
    let (listener, identity) = gate::prepare_staff_socket(&live).unwrap();
    assert!(gate::prepare_staff_socket(&live).is_err());
    gate::cleanup_staff_socket(&live, &identity).unwrap();
    drop(listener);
    let _ = fs::remove_file(&symlink);
    let _ = fs::remove_file(&regular);
    remove_parent(&symlink);
    remove_parent(&regular);
    remove_parent(&live);
}

#[tokio::test(flavor = "current_thread")]
async fn stale_socket_is_replaced() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let path = socket_path("stale");
    let _ = fs::remove_file(&path);
    std::env::set_var("CADUCEUS_STAFF_GROUP", unsafe { getegid() }.to_string());
    let old = std::os::unix::net::UnixListener::bind(&path).unwrap();
    drop(old);
    let (_listener, identity) = gate::prepare_staff_socket(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().ino(), identity.ino);
    gate::cleanup_staff_socket(&path, &identity).unwrap();
    remove_parent(&path);
}

#[tokio::test(flavor = "current_thread")]
async fn unsafe_socket_parents_are_refused_without_touching_target() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let target = socket_path("unsafe");
    let parent = target.parent().unwrap().to_owned();
    let target_file = std::env::temp_dir().join(format!(
        "cdu-target-{}",
        SOCKET_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::write(&target_file, b"collision").unwrap();
    fs::remove_dir(&parent).unwrap();
    std::os::unix::fs::symlink(&target_file, &parent).unwrap();
    let socket = parent.join("staff.sock");
    let err = gate::prepare_staff_socket(&socket).unwrap_err();
    assert_eq!(err, "staff-socket-parent-symlink");
    assert_eq!(fs::read(&target_file).unwrap(), b"collision");
    fs::remove_file(&parent).unwrap();
    fs::create_dir(&parent).unwrap();
    let mut perms = fs::metadata(&parent).unwrap().permissions();
    perms.set_mode(0o775);
    fs::set_permissions(&parent, perms).unwrap();
    let err = gate::prepare_staff_socket(&socket).unwrap_err();
    assert_eq!(err, "staff-socket-parent-mode-mismatch");
    assert_eq!(fs::read(&target_file).unwrap(), b"collision");
    fs::remove_dir(&parent).unwrap();
    fs::remove_file(target_file).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn cleanup_refuses_pathname_substitution() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let path = socket_path("substitution");
    std::env::set_var("CADUCEUS_STAFF_GROUP", unsafe { getegid() }.to_string());
    let (listener, identity) = gate::prepare_staff_socket(&path).unwrap();
    drop(listener);
    fs::remove_file(&path).unwrap();
    let replacement = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let err = gate::cleanup_staff_socket(&path, &identity).unwrap_err();
    assert_eq!(err, "staff-socket-cleanup-identity-mismatch");
    assert!(path.exists());
    drop(replacement);
    fs::remove_file(&path).unwrap();
    fs::remove_dir(path.parent().unwrap()).unwrap();
}

unsafe extern "C" {
    fn chown(path: *const i8, uid: u32, gid: u32) -> i32;
    fn getegid() -> u32;
    fn geteuid() -> u32;
    fn kill(pid: i32, signal: i32) -> i32;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_one_one_over_unix_socket_uses_same_router() {
    let path = socket_path("http1");
    let _ = fs::remove_file(&path);
    std::env::set_var("CADUCEUS_STAFF_GROUP", unsafe { getegid() }.to_string());
    let (listener, identity) = gate::prepare_staff_socket(&path).unwrap();
    let app = gate::router();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        gate::serve_staff_connection(stream, app).await.unwrap();
    });
    let mut client = UnixStream::connect(&path).unwrap();
    client
        .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("caduceus.liveness.v1"));
    task.await.unwrap();
    gate::cleanup_staff_socket(&path, &identity).unwrap();
    remove_parent(&path);
}

struct ChildFixture {
    child: std::process::Child,
    socket: PathBuf,
}
impl Drop for ChildFixture {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            let _ = unsafe { kill(self.child.id() as i32, 15) };
            let _ = self.child.wait();
        }
        let _ = fs::remove_file(&self.socket);
        if let Some(parent) = self.socket.parent() {
            let _ = fs::remove_dir(parent);
        }
    }
}

fn free_tcp_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn raw_get_tcp(port: u16, path: &str) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}
fn raw_get_unix(pathname: &Path, path: &str) -> String {
    let mut stream = UnixStream::connect(pathname).unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}
fn raw_http(
    mut stream: impl Read,
    mut writer: impl Write,
    method: &str,
    path: &str,
    body: &str,
) -> String {
    write!(writer, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}
fn start_server(port: u16, socket: &Path) -> ChildFixture {
    let _ = fs::remove_file(socket);
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_caduceus"))
        .arg("serve")
        .env("CADUCEUS_BIND", format!("127.0.0.1:{port}"))
        .env("CADUCEUS_STAFF_SOCKET", socket)
        .env("CADUCEUS_STAFF_GROUP", unsafe { getegid() }.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            let _ = stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            let mut response = String::new();
            let _ = stream.read_to_string(&mut response);
            if response.starts_with("HTTP/1.1 200") && socket.exists() {
                return ChildFixture {
                    child,
                    socket: socket.to_owned(),
                };
            }
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            panic!("server exited before readiness ({status}): {stderr}");
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("server readiness timeout");
}

#[test]
fn process_tcp_and_uds_http_logs_peers_and_sigterm_removes_socket() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let port = free_tcp_port();
    let socket = socket_path("process-contract");
    let mut fixture = start_server(port, &socket);
    let mut tcp = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    let mut tcp_writer = tcp.try_clone().unwrap();
    let tcp_response = raw_http(
        &mut tcp,
        &mut tcp_writer,
        "POST",
        "/api/v1/exousia/open",
        "{}",
    );
    let tcp_health = raw_get_tcp(port, "/health");
    let uds_health = raw_get_unix(&socket, "/health");
    assert_eq!(tcp_health.lines().next(), Some("HTTP/1.1 200 OK"));
    assert_eq!(uds_health.lines().next(), Some("HTTP/1.1 200 OK"));
    assert_eq!(
        tcp_health.split_once("\r\n\r\n").unwrap().1,
        uds_health.split_once("\r\n\r\n").unwrap().1
    );
    let tcp_missing = raw_get_tcp(port, "/not-a-route");
    let uds_missing = raw_get_unix(&socket, "/not-a-route");
    assert_eq!(tcp_missing.lines().next(), Some("HTTP/1.1 404 Not Found"));
    assert_eq!(uds_missing.lines().next(), Some("HTTP/1.1 404 Not Found"));
    assert_eq!(
        tcp_missing.split_once("\r\n\r\n").unwrap().1,
        uds_missing.split_once("\r\n\r\n").unwrap().1
    );
    let mut uds = UnixStream::connect(&socket).unwrap();
    let mut uds_writer = uds.try_clone().unwrap();
    let uds_response = raw_http(
        &mut uds,
        &mut uds_writer,
        "POST",
        "/api/v1/exousia/open",
        "{}",
    );
    assert_eq!(tcp_response.lines().next(), Some("HTTP/1.1 403 Forbidden"));
    assert_eq!(uds_response.lines().next(), Some("HTTP/1.1 403 Forbidden"));
    assert_eq!(unsafe { kill(fixture.child.id() as i32, 15) }, 0);
    let status = fixture.child.wait().unwrap();
    assert!(status.success());
    let mut stderr = String::new();
    fixture
        .child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(stderr.contains("127.0.0.1:"));
    assert!(stderr.contains(&format!(
        "unix(uid={},gid={},pid=",
        unsafe { geteuid() },
        unsafe { getegid() }
    )));
    assert!(!socket.exists());
}

#[test]
fn regular_uds_collision_prevents_tcp_only_start() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let port = free_tcp_port();
    let socket = socket_path("startup-collision");
    let _ = fs::remove_file(&socket);
    fs::write(&socket, b"collision").unwrap();
    let status = std::process::Command::new(env!("CARGO_BIN_EXE_caduceus"))
        .arg("serve")
        .env("CADUCEUS_BIND", format!("127.0.0.1:{port}"))
        .env("CADUCEUS_STAFF_SOCKET", &socket)
        .env("CADUCEUS_STAFF_GROUP", unsafe { getegid() }.to_string())
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(socket.exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", port)).is_err());
    let _ = fs::remove_file(socket);
}
