//! `forge run`-backed [`crate::validator::ValidatorBackend`].
//!
//! Shells out to the pinned narrow flag set produced by
//! [`ValidatorCommandBuilder`] and parses the JSON receipt forge emits on
//! stdout. The classifier turns the receipt's `conclusion` field into
//! `Pass` / `Regression`; unparseable output becomes `SetupFailure`; a
//! watchdog-killed run becomes `Timeout`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::error::{Error, Result};
use crate::process_runner::{RunResult, run_with_timeout};

use super::{
    FailureFlavor, ValidatorBackend, ValidatorExecutor, WorkflowOutcome, WorkflowResult,
    stderr_tail,
};

/// `forge run`-backed validator. Shells out to the pinned narrow flag set
/// (see [`ValidatorCommandBuilder::build_argv`]) and parses the JSON
/// receipt forge emits on stdout.
#[derive(Debug, Clone)]
pub struct ForgeRunBackend {
    pub forge_bin: PathBuf,
    pub executor: ValidatorExecutor,
}

impl ForgeRunBackend {
    pub fn new(forge_bin: PathBuf, executor: ValidatorExecutor) -> Self {
        Self {
            forge_bin,
            executor,
        }
    }

    /// Classification helper, separated from subprocess wiring so it's
    /// unit-testable without spawning a real `forge` binary.
    pub(super) fn classify(
        &self,
        workflow: &Path,
        exit_code: Option<i32>,
        stdout: &str,
        stderr: &str,
        duration_ms: u128,
        log_path: &Path,
    ) -> WorkflowOutcome {
        let parsed = parse_forge_run_output(stdout);
        let stderr_tail = stderr_tail(stderr, 4096);
        let (result, forge_run_id) = match parsed {
            Some(summary) => {
                let id = Some(summary.run_id.clone());
                if summary.is_success() {
                    (WorkflowResult::Pass, id)
                } else {
                    (
                        WorkflowResult::Fail(FailureFlavor::Regression {
                            details: format!("conclusion: {}", summary.conclusion),
                        }),
                        id,
                    )
                }
            }
            None => {
                let exit_label = exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into());
                let last_stderr = stderr.lines().last().unwrap_or("").trim();
                (
                    WorkflowResult::Fail(FailureFlavor::SetupFailure {
                        reason: format!(
                            "forge run produced unparseable output (exit {exit_label}); last stderr: {last_stderr}"
                        ),
                    }),
                    None,
                )
            }
        };
        WorkflowOutcome {
            workflow: workflow.to_path_buf(),
            backend: self.name(),
            result,
            forge_run_id,
            duration_ms,
            stderr_tail,
            log_path: log_path.to_path_buf(),
            cached_at_unix_secs: None,
        }
    }
}

impl ValidatorBackend for ForgeRunBackend {
    fn name(&self) -> &'static str {
        "forge-run"
    }

    fn validate_workflow(
        &self,
        workflow: &Path,
        tree: &Path,
        timeout: Duration,
        log_path: &Path,
    ) -> Result<WorkflowOutcome> {
        let argv = ValidatorCommandBuilder::new(&self.forge_bin)
            .workflow(workflow)
            .workspace(tree)
            .event("push")
            .executor(self.executor)
            .build_argv();

        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        command.current_dir(tree);
        let run = run_with_timeout(command, timeout).map_err(|source| Error::Io {
            path: tree.to_path_buf(),
            source,
        })?;
        let stdout = String::from_utf8_lossy(run.stdout()).into_owned();
        let stderr = String::from_utf8_lossy(run.stderr()).into_owned();

        let log_content = format!("=== STDOUT ===\n{stdout}\n=== STDERR ===\n{stderr}");
        let _ = std::fs::create_dir_all(log_path.parent().unwrap_or(Path::new(".")));
        let _ = std::fs::write(log_path, log_content);

        match run {
            RunResult::Completed {
                status, duration, ..
            } => Ok(self.classify(
                workflow,
                status.code(),
                &stdout,
                &stderr,
                duration.as_millis(),
                log_path,
            )),
            RunResult::TimedOut { duration, .. } => Ok(WorkflowOutcome {
                workflow: workflow.to_path_buf(),
                backend: self.name(),
                result: WorkflowResult::Fail(FailureFlavor::Timeout),
                forge_run_id: None,
                duration_ms: duration.as_millis(),
                stderr_tail: stderr_tail(&stderr, 4096),
                log_path: log_path.to_path_buf(),
                cached_at_unix_secs: None,
            }),
        }
    }
}

/// Builder for the `forge run` invocation. Assay depends on this exact
/// narrow flag set; if `forge`'s CLI changes, this is the single place to
/// update. Unit-tested separately from the subprocess wiring.
#[derive(Debug, Clone)]
pub struct ValidatorCommandBuilder<'a> {
    bin: &'a Path,
    workflow: Option<&'a Path>,
    workspace: Option<&'a Path>,
    event: &'a str,
    executor: ValidatorExecutor,
}

impl<'a> ValidatorCommandBuilder<'a> {
    pub fn new(bin: &'a Path) -> Self {
        Self {
            bin,
            workflow: None,
            workspace: None,
            event: "push",
            executor: ValidatorExecutor::Docker,
        }
    }

    pub fn workflow(mut self, path: &'a Path) -> Self {
        self.workflow = Some(path);
        self
    }

    pub fn workspace(mut self, path: &'a Path) -> Self {
        self.workspace = Some(path);
        self
    }

    pub fn event(mut self, event: &'a str) -> Self {
        self.event = event;
        self
    }

    pub fn executor(mut self, executor: ValidatorExecutor) -> Self {
        self.executor = executor;
        self
    }

    /// Construct the argv. The first element is the program path; the
    /// rest are arguments suitable for `Command::new(&argv[0]).args(&argv[1..])`.
    pub fn build_argv(self) -> Vec<String> {
        let mut argv = Vec::with_capacity(12);
        argv.push(self.bin.display().to_string());
        argv.push("run".into());
        if let Some(workflow) = self.workflow {
            argv.push("--workflow".into());
            argv.push(workflow.display().to_string());
        }
        if let Some(workspace) = self.workspace {
            argv.push("--workspace".into());
            argv.push(workspace.display().to_string());
        }
        argv.push("--event".into());
        argv.push(self.event.into());
        argv.push("--executor".into());
        argv.push(self.executor.as_cli_arg().into());
        argv.push("--format".into());
        argv.push("json".into());
        argv
    }
}

/// Parsed shape of `forge run --format json` output that assay cares about.
/// Anything beyond these fields is irrelevant to the validator's verdict —
/// keeping the surface narrow means forge's internal receipt schema can
/// evolve without breaking assay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeRunSummary {
    pub run_id: String,
    pub conclusion: String,
}

impl ForgeRunSummary {
    pub fn is_success(&self) -> bool {
        matches!(self.conclusion.as_str(), "success" | "succeeded")
    }
}

/// Parse the JSON receipt forge emits on stdout. Returns `None` if the
/// output can't be parsed or doesn't contain the minimum fields — the
/// caller surfaces that as a `SetupFailure`.
pub fn parse_forge_run_output(stdout: &str) -> Option<ForgeRunSummary> {
    let value: serde_json::Value = serde_json::from_str(stdout).ok()?;
    let run_id = value.get("run_id").and_then(|v| v.as_str())?.to_string();
    // Prefer top-level `conclusion`; fall back to overall workflow status
    // if a future schema renames it.
    let conclusion = value
        .get("conclusion")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .or_else(|| {
            value
                .get("workflows")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.iter().find_map(|w| w.get("conclusion")))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());
    Some(ForgeRunSummary { run_id, conclusion })
}
