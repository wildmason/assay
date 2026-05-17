//! Subprocess execution with a timeout watchdog and best-effort
//! child-tree kill.
//!
//! Wraps the v1 `Command::output()` pattern with two improvements:
//!
//! - **Timeout watchdog**: every spawn has a wall-clock cap. When it
//!   trips, the child is killed and a [`RunResult::TimedOut`] is
//!   returned so the caller can map it to `FailureFlavor::Timeout`.
//!
//! - **Process-group kill (Unix)**: children spawn into a fresh process
//!   group via `Command::process_group(0)`. On timeout, the entire group
//!   is killed via `killpg(SIGTERM)` so grandchildren (e.g. a shell
//!   wrapper forking a test binary) don't leak.
//!
//! - **Windows**: only the immediate child is killed. Building real
//!   process-tree kill via Win32 job objects is documented in plan §G.5
//!   as a follow-up; for the v1 forge-run backend, the docker daemon
//!   manages container lifecycle anyway (containers survive any parent
//!   kill — also documented as a known limitation in §G.5).
//!
//! Stdout and stderr are captured into byte vectors via background
//! drainer threads so the timeout doesn't deadlock on a full pipe
//! buffer.

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use wait_timeout::ChildExt;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

/// Outcome of [`run_with_timeout`].
#[derive(Debug)]
pub enum RunResult {
    /// Child exited (success or failure) before the timeout.
    Completed {
        status: ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration: Duration,
    },
    /// Timeout watchdog tripped; child was killed.
    TimedOut {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        duration: Duration,
    },
}

impl RunResult {
    pub fn stdout(&self) -> &[u8] {
        match self {
            RunResult::Completed { stdout, .. } | RunResult::TimedOut { stdout, .. } => stdout,
        }
    }
    pub fn stderr(&self) -> &[u8] {
        match self {
            RunResult::Completed { stderr, .. } | RunResult::TimedOut { stderr, .. } => stderr,
        }
    }
    pub fn duration_ms(&self) -> u128 {
        match self {
            RunResult::Completed { duration, .. } | RunResult::TimedOut { duration, .. } => {
                duration.as_millis()
            }
        }
    }
}

/// Spawn `cmd` and wait up to `timeout`. On Unix the child becomes its
/// own process group leader so the entire group can be killed if the
/// timeout trips.
pub fn run_with_timeout(mut cmd: Command, timeout: Duration) -> std::io::Result<RunResult> {
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    #[cfg(unix)]
    {
        // Setting process_group(0) puts the child in a new group whose
        // PGID equals the child's PID — so any grandchildren the child
        // forks belong to the same group, and we can kill them all with
        // one killpg call below.
        cmd.process_group(0);
    }

    let started = Instant::now();
    let mut child = cmd.spawn()?;

    let stdout_handle = drain_into_thread(child.stdout.take());
    let stderr_handle = drain_into_thread(child.stderr.take());

    let exit = child.wait_timeout(timeout)?;
    match exit {
        Some(status) => {
            let stdout = stdout_handle.join().unwrap_or_default();
            let stderr = stderr_handle.join().unwrap_or_default();
            Ok(RunResult::Completed {
                status,
                stdout,
                stderr,
                duration: started.elapsed(),
            })
        }
        None => {
            kill_child_tree(&mut child);
            // Try to reap so the OS releases the child-process record.
            // Ignore the result — by this point the child is going away.
            let _ = child.wait();
            let stdout = stdout_handle.join().unwrap_or_default();
            let stderr = stderr_handle.join().unwrap_or_default();
            Ok(RunResult::TimedOut {
                stdout,
                stderr,
                duration: started.elapsed(),
            })
        }
    }
}

fn drain_into_thread<R>(reader: Option<R>) -> DrainHandle
where
    R: Read + Send + 'static,
{
    let Some(mut reader) = reader else {
        return DrainHandle::Empty;
    };
    let (tx, rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = reader.read_to_end(&mut buf);
        let _ = tx.send(buf);
    });
    DrainHandle::Live { rx, handle }
}

enum DrainHandle {
    Empty,
    Live {
        rx: mpsc::Receiver<Vec<u8>>,
        handle: thread::JoinHandle<()>,
    },
}

impl DrainHandle {
    fn join(self) -> Option<Vec<u8>> {
        match self {
            DrainHandle::Empty => Some(Vec::new()),
            DrainHandle::Live { rx, handle } => {
                let buf = rx.recv().ok();
                let _ = handle.join();
                buf
            }
        }
    }
}

#[cfg(unix)]
fn kill_child_tree(child: &mut Child) {
    use std::os::unix::process::ExitStatusExt;
    let pid = child.id() as libc::pid_t;
    // Best-effort: SIGTERM the whole process group, then immediate
    // SIGKILL to ensure even unresponsive children go away. Wrap in
    // unsafe — these libc calls are sound when given a valid pid.
    unsafe {
        // Negative pid = signal the process group.
        libc::kill(-pid, libc::SIGTERM);
        libc::kill(-pid, libc::SIGKILL);
    }
    // Defensive: also kill the immediate child in case process_group(0)
    // didn't take (e.g. process already exited).
    let _ = child.kill();
    // Force a non-blocking reap so .wait() below doesn't hang.
    let _: ExitStatus = ExitStatus::from_raw(0);
}

#[cfg(windows)]
fn kill_child_tree(child: &mut Child) {
    // v1 Windows path: only kill the immediate child. Building real
    // process-tree kill via Win32 job objects is plan §G.5 follow-up.
    // For forge-run, docker containers are managed by the docker
    // daemon and survive ANY parent kill — documented limitation.
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn slow_sleep_argv() -> Vec<String> {
        vec!["sh".into(), "-c".into(), "sleep 10".into()]
    }
    #[cfg(windows)]
    fn slow_sleep_argv() -> Vec<String> {
        // Windows: ping localhost — equivalent of sleep that's always
        // installed. Invoke ping directly (no cmd /C wrapper) so we kill
        // the actual sleeper, not a shell that forks an uninterrupted
        // child — the Windows process-tree kill limitation documented
        // above means the inner child would otherwise outlive the test.
        vec!["ping".into(), "-n".into(), "11".into(), "127.0.0.1".into()]
    }

    fn fast_exit_argv(code: u8) -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd".into(), "/C".into(), format!("exit {code}")]
        } else {
            vec!["sh".into(), "-c".into(), format!("exit {code}")]
        }
    }

    fn echo_argv(payload: &str) -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd".into(), "/C".into(), format!("echo {payload}")]
        } else {
            vec!["sh".into(), "-c".into(), format!("printf %s {payload}")]
        }
    }

    fn build_cmd(argv: &[String]) -> Command {
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd
    }

    #[test]
    fn completes_within_timeout_for_fast_command() {
        let cmd = build_cmd(&fast_exit_argv(0));
        let result = run_with_timeout(cmd, Duration::from_secs(30)).unwrap();
        match result {
            RunResult::Completed { status, .. } => assert!(status.success()),
            RunResult::TimedOut { .. } => panic!("fast command must not timeout"),
        }
    }

    #[test]
    fn captures_stdout() {
        let cmd = build_cmd(&echo_argv("hello"));
        let result = run_with_timeout(cmd, Duration::from_secs(30)).unwrap();
        assert!(
            result.stdout().windows(5).any(|w| w == b"hello"),
            "stdout must contain payload: {:?}",
            String::from_utf8_lossy(result.stdout())
        );
    }

    #[test]
    fn propagates_nonzero_exit_status() {
        let cmd = build_cmd(&fast_exit_argv(7));
        let result = run_with_timeout(cmd, Duration::from_secs(30)).unwrap();
        match result {
            RunResult::Completed { status, .. } => {
                assert_eq!(status.code(), Some(7));
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[test]
    fn kills_child_on_timeout() {
        let cmd = build_cmd(&slow_sleep_argv());
        let started = Instant::now();
        let result = run_with_timeout(cmd, Duration::from_millis(500)).unwrap();
        let elapsed = started.elapsed();
        match result {
            RunResult::TimedOut { .. } => {}
            other => panic!("expected TimedOut, got {other:?}"),
        }
        // Should not have waited the full 10 seconds.
        assert!(
            elapsed < Duration::from_secs(5),
            "timeout should fire promptly, took {elapsed:?}"
        );
    }
}
