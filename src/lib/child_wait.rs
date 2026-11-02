use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// Wait until the original deadline; a timeout leaves the child unreaped.
pub fn until(child: &mut Child, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id(), 0) };
    if raw < 0 {
        return fallback(child.id(), deadline);
    }
    // SAFETY: pidfd_open returned a new owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let mut pollfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        // Round up, so a sub-millisecond remainder cannot expire early.
        let millis = remaining.as_millis().saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
        let timeout = millis.min(i32::MAX as u128) as i32;
        let ready = unsafe { libc::poll(&mut pollfd, 1, timeout) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted { continue; }
            return Err(error);
        }
        if ready == 0 {
            if Instant::now() >= deadline { return Ok(None); }
            continue;
        }
        if pollfd.revents & libc::POLLIN != 0 {
            return child.wait().map(Some);
        }
        return Err(io::Error::new(io::ErrorKind::Other, "child pidfd poll failed"));
    }
}

/// A separately named bounded grace uses the same absolute-deadline wait.
pub fn grace(child: &mut Child, duration: Duration) -> io::Result<Option<ExitStatus>> {
    until(child, Instant::now() + duration)
}

// The waiter first observes without reaping. It may reap only after the caller
// acknowledges the observation: a timed-out caller retains exclusive cleanup.
fn fallback(pid: u32, deadline: Instant) -> io::Result<Option<ExitStatus>> {
    let (observed_tx, observed_rx) = std::sync::mpsc::sync_channel(1);
    let (reap_tx, reap_rx) = std::sync::mpsc::sync_channel(1);
    let (status_tx, status_rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new().name("child-wait".into()).spawn(move || {
        let result = loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::waitid(libc::P_PID, pid, &mut info, libc::WEXITED | libc::WNOWAIT) };
            if rc == 0 { break Ok(()); }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted { break Err(error); }
        };
        if observed_tx.send(result).is_err() || reap_rx.recv().is_err() { return; }
        let result = loop {
            let mut status = 0;
            let rc = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, 0) };
            if rc >= 0 { break Ok(ExitStatus::from_raw(status)); }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted { break Err(error); }
        };
        let _ = status_tx.send(result);
    })?;
    match observed_rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(Ok(())) => {
            reap_tx.send(()).map_err(|_| io::Error::new(io::ErrorKind::Other, "child waiter disconnected"))?;
            status_rx.recv().map_err(|_| io::Error::new(io::ErrorKind::Other, "child waiter disconnected"))?.map(Some)
        }
        Ok(Err(error)) => Err(error),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::new(io::ErrorKind::Other, "child waiter disconnected")),
    }
}
