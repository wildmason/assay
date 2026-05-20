//! Operator-supplied custom gate [`crate::validator::ValidatorBackend`].
//!
//! Picked when the operator passes `--gate-cmd "<shell-line>"` or
//! `--gate-file <script>`. Classification is exit-code-only:
//! zero = `Pass`, non-zero = `Regression`, missing binary = `SetupFailure`.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::process_runner::{RunResult, run_with_timeout};
use crate::verdict_cache::fingerprint_commands;

use super::{
    FailureFlavor, ValidatorBackend, WorkflowOutcome, WorkflowResult, stderr_tail,
};

/// Operator-supplied command / script backend — picked when the operator
/// passes `--gate-cmd "<shell-line>"` or `--gate-file <script>`.
///
/// Runs the supplied argv against the prepared tree once per call.
/// Classification is exit-code-only: zero = `Pass`, non-zero = `Regression`,
/// missing binary = `SetupFailure`. No JSON parsing, no per-flavor
/// distinction beyond regression-vs-setup — users wanting structured
/// classification should use `forge run` or `BuildTestBackend`.
#[derive(Debug, Clone)]
pub struct CustomBackend {
    argv: Vec<String>,
    label: &'static str,
}

impl CustomBackend {
    /// Construct from an explicit argv (program path + args).
    pub fn new(argv: Vec<String>) -> Self {
        Self {
            argv,
            label: "custom",
        }
    }

    /// Build from `--gate-cmd "<shell-line>"`. Splits on whitespace — does
    /// NOT interpret shell metacharacters. Operators wanting shell features
    /// (pipes, redirection, env-var expansion) should write a script and
    /// pass it via `--gate-file`.
    pub fn from_gate_cmd(cmd: &str) -> Self {
        let argv: Vec<String> = cmd.split_whitespace().map(String::from).collect();
        Self::new(argv)
    }

    /// Build from `--gate-file <script-path>`. The script is invoked
    /// directly — must be executable; the script's shebang controls how
    /// it's interpreted.
    pub fn from_gate_file(path: &Path) -> Self {
        Self::new(vec![path.display().to_string()])
    }

    /// Read-only accessor for tests.
    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    fn classify(
        &self,
        workflow: &Path,
        run: std::io::Result<RunResult>,
        duration_ms: u128,
        log_path: &Path,
    ) -> WorkflowOutcome {
        match run {
            Ok(RunResult::Completed { status, stderr, .. }) if status.success() => {
                // Stderr might still hold useful content on a passing
                // gate — preserve a tail for the report.
                let stderr_str = String::from_utf8_lossy(&stderr);
                WorkflowOutcome {
                    workflow: workflow.to_path_buf(),
                    backend: self.label,
                    result: WorkflowResult::Pass,
                    forge_run_id: None,
                    duration_ms,
                    stderr_tail: stderr_tail(&stderr_str, 4096),
                    log_path: log_path.to_path_buf(),
                    cached_at_unix_secs: None,
                }
            }
            Ok(RunResult::Completed { status, stderr, .. }) => {
                let exit_label = status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into());
                let stderr_str = String::from_utf8_lossy(&stderr);
                WorkflowOutcome {
                    workflow: workflow.to_path_buf(),
                    backend: self.label,
                    result: WorkflowResult::Fail(FailureFlavor::Regression {
                        details: format!("custom gate exited {exit_label}"),
                    }),
                    forge_run_id: None,
                    duration_ms,
                    stderr_tail: stderr_tail(&stderr_str, 4096),
                    log_path: log_path.to_path_buf(),
                    cached_at_unix_secs: None,
                }
            }
            Ok(RunResult::TimedOut { stderr, .. }) => {
                let stderr_str = String::from_utf8_lossy(&stderr);
                WorkflowOutcome {
                    workflow: workflow.to_path_buf(),
                    backend: self.label,
                    result: WorkflowResult::Fail(FailureFlavor::Timeout),
                    forge_run_id: None,
                    duration_ms,
                    stderr_tail: stderr_tail(&stderr_str, 4096),
                    log_path: log_path.to_path_buf(),
                    cached_at_unix_secs: None,
                }
            }
            Err(err) => {
                let bin = self.argv.first().map(String::as_str).unwrap_or("(empty)");
                let reason = if err.kind() == std::io::ErrorKind::NotFound {
                    format!("custom gate binary `{bin}` not found on PATH")
                } else {
                    format!("custom gate failed to spawn `{bin}`: {err}")
                };
                WorkflowOutcome {
                    workflow: workflow.to_path_buf(),
                    backend: self.label,
                    result: WorkflowResult::Fail(FailureFlavor::SetupFailure { reason }),
                    forge_run_id: None,
                    duration_ms,
                    stderr_tail: String::new(),
                    log_path: log_path.to_path_buf(),
                    cached_at_unix_secs: None,
                }
            }
        }
    }
}

impl ValidatorBackend for CustomBackend {
    fn name(&self) -> &'static str {
        self.label
    }

    fn needs_workflow_file(&self) -> bool {
        // The gate command is operator-supplied and runs against the
        // tree itself. Workflow paths are irrelevant.
        false
    }

    fn fingerprint(&self) -> String {
        format!(
            "{}:{}",
            self.label,
            fingerprint_commands(std::slice::from_ref(&self.argv))
        )
    }

    fn validate_workflow(
        &self,
        workflow: &Path,
        tree: &Path,
        timeout: Duration,
        log_path: &Path,
    ) -> Result<WorkflowOutcome> {
        if self.argv.is_empty() {
            return Ok(WorkflowOutcome {
                workflow: workflow.to_path_buf(),
                backend: self.label,
                result: WorkflowResult::Fail(FailureFlavor::SetupFailure {
                    reason: "custom backend invoked with empty argv".into(),
                }),
                forge_run_id: None,
                duration_ms: 0,
                stderr_tail: String::new(),
                log_path: log_path.to_path_buf(),
                cached_at_unix_secs: None,
            });
        }
        let started = Instant::now();
        let mut cmd = Command::new(&self.argv[0]);
        cmd.args(&self.argv[1..]).current_dir(tree);
        let result = run_with_timeout(cmd, timeout);

        // Best-effort log write — non-fatal.
        if let Ok(ref run) = result {
            let _ = std::fs::create_dir_all(log_path.parent().unwrap_or(Path::new(".")));
            let header = match run {
                RunResult::Completed { status, .. } => format!(
                    "exit: {}",
                    status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "signal".into())
                ),
                RunResult::TimedOut { .. } => "TIMED OUT".to_string(),
            };
            let _ = std::fs::write(
                log_path,
                format!(
                    "{header}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(run.stdout()),
                    String::from_utf8_lossy(run.stderr()),
                ),
            );
        }

        let duration_ms = started.elapsed().as_millis();
        Ok(self.classify(workflow, result, duration_ms, log_path))
    }
}
