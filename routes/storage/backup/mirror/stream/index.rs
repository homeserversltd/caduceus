use axum::{body::Body, http::Request, response::{IntoResponse, Response}, routing::post, Json, Router};
use axum::http::StatusCode;
use std::{io, pin::Pin, process::Stdio, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}}, task::{Context, Poll}, time::{Duration, Instant}};
use tokio::{io::{AsyncReadExt, AsyncWrite, AsyncWriteExt}, process::Command};

static STREAM_ACTIVE: AtomicBool = AtomicBool::new(false);
struct Lease;
impl Drop for Lease { fn drop(&mut self) { STREAM_ACTIVE.store(false, Ordering::Release); } }

fn refusal(status: StatusCode, signal: &str) -> Response {
    (status, Json(serde_json::json!({"ok": false, "signal": signal}))).into_response()
}

struct Counted<W> { inner: W, count: Arc<AtomicU64> }
impl<W: AsyncWrite + Unpin> AsyncWrite for Counted<W> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => { self.count.fetch_add(n as u64, Ordering::Relaxed); Poll::Ready(Ok(n)) }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_flush(cx) }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> { Pin::new(&mut self.inner).poll_shutdown(cx) }
}

async fn route(mut request: Request<Body>) -> Response {
    let headers = request.headers();
    let mac = headers.get("x-caduceus-pair-mac").and_then(|v| v.to_str().ok()).unwrap_or("");
    let credential = headers.get("x-caduceus-pair-credential").and_then(|v| v.to_str().ok()).unwrap_or("");
    let pair_mac = mac.to_owned();
    let pair_credential = credential.to_owned();
    match tokio::task::spawn_blocking(move || crate::routes::leaf_storage_backup_pair::admitted(&pair_mac, &pair_credential)).await {
        Ok(true) => {},
        Ok(false) => return refusal(StatusCode::UNAUTHORIZED, "backup-pair-unknown"),
        Err(_) => return refusal(StatusCode::SERVICE_UNAVAILABLE, "backup-pair-unavailable"),
    }
    let mac = mac.to_owned();
    let upgrade = headers.get("upgrade").and_then(|v| v.to_str().ok()).is_some_and(|v| v.eq_ignore_ascii_case("caduceus-rsync"));
    let connection = headers.get("connection").and_then(|v| v.to_str().ok()).is_some_and(|v| v.split(',').any(|s| s.trim().eq_ignore_ascii_case("upgrade")));
    if !upgrade || !connection { return refusal(StatusCode::BAD_REQUEST, "backup-mirror-upgrade-required"); }
    if STREAM_ACTIVE.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() { return refusal(StatusCode::CONFLICT, "backup-mirror-busy"); }
    let lease = Lease;
    let started = Instant::now();
    let path = crate::gate::snake::cli_path();
    let mut command = if std::env::var_os("CADUCEUS_AGATHODAIMON_CLI").is_some() {
        Command::new(path)
    } else {
        let mut c = Command::new("/usr/bin/sudo"); c.arg("-n").arg(path); c
    };
    command.arg("storage/backup/mirror/serve").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).kill_on_drop(true);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return refusal(StatusCode::INTERNAL_SERVER_ERROR, "backup-mirror-spawn-failed"),
    };
    // Keep stdin open across the early-exit wait; Child::wait otherwise closes it.
    let child_stdin = child.stdin.take().expect("piped stdin");
    let child_stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let stderr_task = tokio::spawn(async move {
        let mut captured = Vec::new(); let mut buffer = [0u8; 4096];
        loop { match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => break,
            Ok(n) => { let available = (64 * 1024usize).saturating_sub(captured.len()); captured.extend_from_slice(&buffer[..n.min(available)]); }
        }}
        captured
    });
    let early_deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    match tokio::time::timeout_at(early_deadline, child.wait()).await {
        Ok(Ok(_status)) => {
            let captured = tokio::time::timeout_at(early_deadline, stderr_task).await.ok().and_then(Result::ok).unwrap_or_default();
            let signal = captured.split(|byte| *byte == b'\n').next()
                .and_then(|line| serde_json::from_slice::<serde_json::Value>(line).ok())
                .and_then(|json| json.get("signal").and_then(|value| value.as_str()).map(str::to_owned))
                .filter(|signal| signal.len() <= 128 && !signal.is_empty() && !credential.is_empty() && !signal.contains(credential)
                    && signal.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'))
                .unwrap_or_else(|| "backup-mirror-child-failed".to_owned());
            // An early child exit is a pre-upgrade conflict; never echo raw stderr.
            return refusal(StatusCode::CONFLICT, &signal);
        }
        Ok(Err(_)) => { stderr_task.abort(); return refusal(StatusCode::INTERNAL_SERVER_ERROR, "backup-mirror-child-failed"); }
        Err(_) => {}
    }
    let on_upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let _lease = lease;
        let input_bytes = Arc::new(AtomicU64::new(0));
        let output_bytes = Arc::new(AtomicU64::new(0));
        let mut exited = None;
        if let Ok(upgraded) = on_upgrade.await {
            let stream = hyper_util::rt::TokioIo::new(upgraded);
            let (mut reader, writer) = tokio::io::split(stream);
            let mut stdin = Counted { inner: child_stdin, count: input_bytes.clone() };
            let mut stdout = child_stdout;
            let mut writer = Counted { inner: writer, count: output_bytes.clone() };
            let sender = tokio::io::copy(&mut stdout, &mut writer);
            tokio::pin!(sender);
            tokio::select! {
                received = tokio::io::copy(&mut reader, &mut stdin) => {
                    let _ = stdin.shutdown().await;
                    if received.is_ok() { let _ = sender.await; }
                },
                _ = &mut sender => {},
            }
            let _ = stdin.shutdown().await;
        }
        if exited.is_none() {
            // SIGTERM lets sudo forward termination to its privileged child.
            if let Some(pid) = child.id() { unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM); } }
            exited = child.wait().await.ok();
        }
        stderr_task.abort();
        eprintln!("verb=backup-mirror-stream mac={} bytes_in={} bytes_out={} exit={} duration_ms={}", mac, input_bytes.load(Ordering::Relaxed), output_bytes.load(Ordering::Relaxed), exited.map(|s| s.to_string()).unwrap_or_else(|| "unknown".into()), started.elapsed().as_millis());
    });
    Response::builder().status(StatusCode::SWITCHING_PROTOCOLS).header("connection", "Upgrade").header("upgrade", "caduceus-rsync").body(Body::empty()).expect("upgrade response")
}

pub fn register(router: Router) -> Router { router.route("/api/v1/storage/backup/mirror/stream", post(route)) }
