//! Validator stage — runs each `Proposal`'s gate workflows through a
//! `ValidatorBackend` and aggregates per-workflow outcomes into a single
//! [`ValidationOutcome`].
//!
//! Backends (`ForgeRunBackend`, `BuildTestBackend`, `CustomBackend`) own the
//! subprocess wiring AND the classification of raw outputs into
//! [`WorkflowResult`] + [`FailureFlavor`]. Per the plan §C.4.c, this trait
//! shape replaces the original "enum + giant match" so the validator can
//! grow new backends (a future `ForgeLibBackend` for in-process forge use)
//! without touching the dispatch site.
//!
//! v1 keeps the original blocking subprocess pattern (`command.output()`).
//! The `Duration` timeout passed through the trait is honored once Commit J
//! adds proper `wait_timeout` + OS-native process-group kill machinery.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::model::{Classification, Proposal, ValidationOutcome};
use crate::process_runner::{RunResult, run_with_timeout};
use crate::workflow_filter::WorkflowFilter;

// =============================================================================
// Executor and outcome types
// =============================================================================

/// Executor backend the validator asks `forge run` to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatorExecutor {
    /// Trusted host execution (`--executor host`). Bypasses build-script
    /// isolation; only safe for repositories whose entire transitive
    /// dependency graph the operator has audited.
    Host,
    /// Sandboxed Docker execution (`--executor docker`). Default for
    /// ecosystems whose package manager runs upstream build scripts.
    Docker,
}

impl ValidatorExecutor {
    pub fn as_cli_arg(self) -> &'static str {
        match self {
            ValidatorExecutor::Host => "host",
            ValidatorExecutor::Docker => "docker",
        }
    }
}

/// Per-workflow result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowResult {
    /// Workflow ran to success.
    Pass,
    /// Workflow did not pass — see flavor for the reason.
    Fail(FailureFlavor),
}

/// Tags the *kind* of failure so the report distinguishes genuine
/// regressions from environment problems we couldn't tell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FailureFlavor {
    /// Workflow ran to completion AND returned a non-success conclusion.
    /// The upgrade actually broke something.
    Regression { details: String },
    /// Workflow couldn't start, or its output was unparseable.
    /// Distinguishable from `Regression` because we can't conclude the
    /// upgrade is broken — the environment failed us.
    SetupFailure { reason: String },
    /// Watchdog killed the child after exceeding the configured timeout.
    /// Ambiguous between a runaway upgrade and a slow runner.
    Timeout,
}

/// Per-workflow outcome with metadata the Reporter renders.
#[derive(Debug, Clone)]
pub struct WorkflowOutcome {
    pub workflow: PathBuf,
    pub backend: &'static str,
    pub result: WorkflowResult,
    /// `Some` when the backend produced a structured run id (e.g.
    /// `ForgeRunBackend` parsing the JSON receipt). `None` for backends
    /// without that concept (`BuildTestBackend`, `CustomBackend`).
    pub forge_run_id: Option<String>,
    pub duration_ms: u128,
    /// Last few KB of stderr — surfaced in the text report for quick
    /// diagnosis. Full logs are at `log_path`.
    pub stderr_tail: String,
    pub log_path: PathBuf,
}

// =============================================================================
// ValidatorBackend trait
// =============================================================================

/// Strategy for running one workflow against a prepared (sandboxed) tree.
///
/// Three v1 impls live in this module: [`ForgeRunBackend`] (shells out to
/// the ci-forge runner), [`BuildTestBackend`] (manifest-inferred fallback —
/// added in Commit B), and [`CustomBackend`] (`--gate-cmd` / `--gate-file`
/// — added in Commit C).
///
/// Each impl owns its own *classification* of raw subprocess output into
/// `WorkflowResult` + `FailureFlavor`. Putting classification on the trait
/// (rather than in a shared helper) lets backends choose the signals they
/// understand best — `forge run`'s JSON receipt vs `cargo test`'s exit code
/// vs an arbitrary script.
pub trait ValidatorBackend: Send + Sync {
    /// Run one workflow against the prepared `tree`. The backend writes its
    /// captured stdout/stderr to `log_path` and returns a classified
    /// outcome. `timeout` is honored once Commit J adds the watchdog
    /// machinery — for v1 it is plumbed through but unused.
    fn validate_workflow(
        &self,
        workflow: &Path,
        tree: &Path,
        timeout: Duration,
        log_path: &Path,
    ) -> Result<WorkflowOutcome>;

    /// Stable name for receipts / provenance.
    fn name(&self) -> &'static str;

    /// Whether the backend needs a real `.github/workflows/*.yml` file
    /// to validate against. [`ForgeRunBackend`] returns `true` (it runs
    /// the named workflow). [`BuildTestBackend`] and [`CustomBackend`]
    /// return `false` — they validate the tree itself (cargo build/test
    /// or an operator-supplied gate command) and need only one
    /// invocation per proposal.
    ///
    /// Default is `true` so a future workflow-bound backend doesn't
    /// silently elide its workflow requirement by forgetting to
    /// override.
    fn needs_workflow_file(&self) -> bool {
        true
    }
}

// =============================================================================
// ForgeRunBackend
// =============================================================================

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
    fn classify(
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
            }),
        }
    }
}

/// UTF-8-boundary-safe truncation that keeps the last `max_bytes` bytes.
fn stderr_tail(stderr: &str, max_bytes: usize) -> String {
    if stderr.len() <= max_bytes {
        return stderr.to_string();
    }
    let mut start = stderr.len().saturating_sub(max_bytes);
    while start < stderr.len() && !stderr.is_char_boundary(start) {
        start += 1;
    }
    stderr[start..].to_string()
}

// =============================================================================
// ValidatorCommandBuilder + ForgeRunSummary
// =============================================================================

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

// =============================================================================
// BuildTestBackend
// =============================================================================

/// Manifest-inferred build+test backend — the fallback when `forge` is
/// not on PATH or the project has no `.github/workflows/` directory.
///
/// Runs a configured sequence of commands (e.g. `cargo build --workspace`
/// then `cargo test --workspace`). Each command runs sequentially; the
/// first non-success short-circuits to a `Regression` outcome; a missing
/// binary produces a `SetupFailure`.
///
/// v1 limitation: when the `Validator` iterates N workflows with this
/// backend, the configured commands run N times. Commit D's backend
/// selection logic will compensate by passing a single synthetic workflow
/// when this backend is chosen, so the multi-run cost is paid once.
#[derive(Debug, Clone)]
pub struct BuildTestBackend {
    commands: Vec<Vec<String>>,
    label: &'static str,
}

impl BuildTestBackend {
    /// Canonical Cargo invocation: `cargo build --workspace` then
    /// `cargo test --workspace`.
    pub fn cargo() -> Self {
        Self {
            commands: vec![
                vec!["cargo".into(), "build".into(), "--workspace".into()],
                vec!["cargo".into(), "test".into(), "--workspace".into()],
            ],
            label: "build-test-cargo",
        }
    }

    /// Explicit constructor for tests + future ecosystems (npm/pnpm/yarn).
    pub fn with_commands(commands: Vec<Vec<String>>, label: &'static str) -> Self {
        Self { commands, label }
    }

    /// Read-only accessor — useful for tests asserting the inferred command
    /// shape without spawning anything.
    pub fn commands(&self) -> &[Vec<String>] {
        &self.commands
    }

    /// Infer the right command sequence from the project's manifest.
    /// Returns `None` if no supported manifest is present (the operator
    /// should pass `--gate-cmd` or install `forge`).
    pub fn infer(project_root: &Path) -> Option<Self> {
        if project_root.join("Cargo.toml").is_file() {
            return Some(Self::cargo());
        }
        // v2: detect package.json / go.mod / pyproject.toml / Gemfile here
        // and produce the matching test-runner invocation.
        None
    }

    /// Classify a pre-collected sequence of command outputs without
    /// spawning anything. Separated from `validate_workflow` so the
    /// classification logic is unit-testable.
    fn classify(
        &self,
        workflow: &Path,
        results: &[(Vec<String>, BuildTestStepOutcome)],
        duration_ms: u128,
        log_path: &Path,
    ) -> WorkflowOutcome {
        let mut combined_stderr = String::new();
        for (cmd, step) in results {
            match step {
                BuildTestStepOutcome::Ran { status, stderr, .. } => {
                    combined_stderr.push_str(&format!(
                        "=== {} ===\n{}\n",
                        cmd.join(" "),
                        String::from_utf8_lossy(stderr),
                    ));
                    if !status.success() {
                        let exit_label = status
                            .code()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "signal".into());
                        let stderr_tail_str = stderr_tail(&combined_stderr, 4096);
                        return WorkflowOutcome {
                            workflow: workflow.to_path_buf(),
                            backend: self.label,
                            result: WorkflowResult::Fail(FailureFlavor::Regression {
                                details: format!("`{}` exited {exit_label}", cmd.join(" ")),
                            }),
                            forge_run_id: None,
                            duration_ms,
                            stderr_tail: stderr_tail_str,
                            log_path: log_path.to_path_buf(),
                        };
                    }
                }
                BuildTestStepOutcome::TimedOut { stderr, .. } => {
                    let stderr_str = String::from_utf8_lossy(stderr).into_owned();
                    return WorkflowOutcome {
                        workflow: workflow.to_path_buf(),
                        backend: self.label,
                        result: WorkflowResult::Fail(FailureFlavor::Timeout),
                        forge_run_id: None,
                        duration_ms,
                        stderr_tail: stderr_tail(&stderr_str, 4096),
                        log_path: log_path.to_path_buf(),
                    };
                }
                BuildTestStepOutcome::SpawnFailed { error } => {
                    let bin = cmd.first().map(String::as_str).unwrap_or("(empty)");
                    let reason = if error.kind() == std::io::ErrorKind::NotFound {
                        format!("binary `{bin}` not found on PATH")
                    } else {
                        format!("couldn't spawn `{bin}`: {error}")
                    };
                    return WorkflowOutcome {
                        workflow: workflow.to_path_buf(),
                        backend: self.label,
                        result: WorkflowResult::Fail(FailureFlavor::SetupFailure { reason }),
                        forge_run_id: None,
                        duration_ms,
                        stderr_tail: String::new(),
                        log_path: log_path.to_path_buf(),
                    };
                }
            }
        }
        WorkflowOutcome {
            workflow: workflow.to_path_buf(),
            backend: self.label,
            result: WorkflowResult::Pass,
            forge_run_id: None,
            duration_ms,
            stderr_tail: String::new(),
            log_path: log_path.to_path_buf(),
        }
    }
}

impl ValidatorBackend for BuildTestBackend {
    fn name(&self) -> &'static str {
        self.label
    }

    fn needs_workflow_file(&self) -> bool {
        // We validate by running `cargo build` + `cargo test` against
        // the prepared tree — no .github/workflows/*.yml required.
        false
    }

    fn validate_workflow(
        &self,
        workflow: &Path,
        tree: &Path,
        timeout: Duration,
        log_path: &Path,
    ) -> Result<WorkflowOutcome> {
        let started = Instant::now();
        let mut results: Vec<(Vec<String>, BuildTestStepOutcome)> = Vec::new();
        // Total timeout is shared across all commands; track remaining
        // budget and surface a Timeout outcome if it runs out before
        // every command finishes.
        let mut remaining = timeout;
        for cmd in &self.commands {
            if cmd.is_empty() {
                continue;
            }
            let mut command = Command::new(&cmd[0]);
            command
                .args(&cmd[1..])
                .current_dir(tree)
                .env("CARGO_TERM_COLOR", "never");
            let result = run_with_timeout(command, remaining);
            let step = match result {
                Ok(RunResult::Completed {
                    status,
                    stdout,
                    stderr,
                    duration,
                }) => {
                    remaining = remaining.checked_sub(duration).unwrap_or(Duration::ZERO);
                    BuildTestStepOutcome::Ran {
                        status,
                        stdout,
                        stderr,
                    }
                }
                Ok(RunResult::TimedOut {
                    stdout,
                    stderr,
                    duration: _,
                }) => {
                    remaining = Duration::ZERO;
                    BuildTestStepOutcome::TimedOut { stdout, stderr }
                }
                Err(err) => BuildTestStepOutcome::SpawnFailed { error: err },
            };
            let timed_out = matches!(step, BuildTestStepOutcome::TimedOut { .. });
            let bad = matches!(
                step,
                BuildTestStepOutcome::TimedOut { .. } | BuildTestStepOutcome::SpawnFailed { .. }
            ) || matches!(&step, BuildTestStepOutcome::Ran { status, .. } if !status.success());
            results.push((cmd.clone(), step));
            // Short-circuit on first failure or timeout.
            if bad {
                if timed_out {
                    // Persist log + return Timeout immediately so we
                    // don't keep spinning through later commands with
                    // remaining == 0.
                    let log_content = render_build_test_log(&results);
                    let _ = std::fs::create_dir_all(log_path.parent().unwrap_or(Path::new(".")));
                    let _ = std::fs::write(log_path, log_content);
                    let stderr_combined = combined_stderr(&results);
                    return Ok(WorkflowOutcome {
                        workflow: workflow.to_path_buf(),
                        backend: self.label,
                        result: WorkflowResult::Fail(FailureFlavor::Timeout),
                        forge_run_id: None,
                        duration_ms: started.elapsed().as_millis(),
                        stderr_tail: stderr_tail(&stderr_combined, 4096),
                        log_path: log_path.to_path_buf(),
                    });
                }
                break;
            }
        }

        let log_content = render_build_test_log(&results);
        let _ = std::fs::create_dir_all(log_path.parent().unwrap_or(Path::new(".")));
        let _ = std::fs::write(log_path, log_content);

        Ok(self.classify(workflow, &results, started.elapsed().as_millis(), log_path))
    }
}

/// One step outcome inside [`BuildTestBackend::validate_workflow`].
#[derive(Debug)]
pub(crate) enum BuildTestStepOutcome {
    Ran {
        status: std::process::ExitStatus,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    TimedOut {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    },
    SpawnFailed {
        error: std::io::Error,
    },
}

fn render_build_test_log(results: &[(Vec<String>, BuildTestStepOutcome)]) -> String {
    let mut out = String::new();
    for (cmd, step) in results {
        out.push_str(&format!("=== {} ===\n", cmd.join(" ")));
        match step {
            BuildTestStepOutcome::Ran {
                status,
                stdout,
                stderr,
            } => out.push_str(&format!(
                "exit: {}\nstdout:\n{}\nstderr:\n{}\n\n",
                status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "signal".into()),
                String::from_utf8_lossy(stdout),
                String::from_utf8_lossy(stderr),
            )),
            BuildTestStepOutcome::TimedOut { stdout, stderr } => out.push_str(&format!(
                "TIMED OUT\nstdout:\n{}\nstderr:\n{}\n\n",
                String::from_utf8_lossy(stdout),
                String::from_utf8_lossy(stderr),
            )),
            BuildTestStepOutcome::SpawnFailed { error } => {
                out.push_str(&format!("spawn error: {error}\n\n"))
            }
        }
    }
    out
}

fn combined_stderr(results: &[(Vec<String>, BuildTestStepOutcome)]) -> String {
    let mut out = String::new();
    for (cmd, step) in results {
        if let BuildTestStepOutcome::TimedOut { stderr, .. }
        | BuildTestStepOutcome::Ran { stderr, .. } = step
        {
            out.push_str(&format!(
                "=== {} ===\n{}\n",
                cmd.join(" "),
                String::from_utf8_lossy(stderr)
            ));
        }
    }
    out
}

// =============================================================================
// CustomBackend
// =============================================================================

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

// =============================================================================
// Validator (thin orchestrator over backends)
// =============================================================================

/// Default per-workflow timeout. Plumbed through the trait but not yet
/// honored — see module docs.
pub const DEFAULT_WORKFLOW_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Drives a [`ValidatorBackend`] across each workflow in a proposal.
pub struct Validator {
    backend: Box<dyn ValidatorBackend>,
    workflow_timeout: Duration,
    workflow_filter: WorkflowFilter,
}

impl Validator {
    /// Back-compat constructor: builds a [`ForgeRunBackend`] with the
    /// default `forge` binary on PATH and the given executor.
    pub fn new(executor: ValidatorExecutor) -> Self {
        Self::with_backend(Box::new(ForgeRunBackend::new(
            PathBuf::from("forge"),
            executor,
        )))
    }

    /// Construct a `Validator` around an arbitrary backend (typically used
    /// by tests to inject a fixture / mock backend; later commits will
    /// expose backend selection at construction time).
    pub fn with_backend(backend: Box<dyn ValidatorBackend>) -> Self {
        Self {
            backend,
            workflow_timeout: DEFAULT_WORKFLOW_TIMEOUT,
            workflow_filter: WorkflowFilter::pull_request_default(),
        }
    }

    /// Override the per-workflow timeout (default
    /// [`DEFAULT_WORKFLOW_TIMEOUT`] = 30 minutes).
    pub fn with_workflow_timeout(mut self, timeout: Duration) -> Self {
        self.workflow_timeout = timeout;
        self
    }

    /// Override the workflow filter (default
    /// [`WorkflowFilter::pull_request_default`] — keeps only workflows
    /// whose `on:` block declares `pull_request`).
    pub fn with_workflow_filter(mut self, filter: WorkflowFilter) -> Self {
        self.workflow_filter = filter;
        self
    }

    /// Auto-select the right backend for `project_root` (plan §C.4.c
    /// selection logic).
    ///
    /// Picks [`ForgeRunBackend`] when `forge` is on PATH AND the project
    /// has a `.github/workflows/` directory; otherwise falls back to
    /// [`BuildTestBackend::infer`]'s manifest-derived commands. Errors if
    /// neither applies (no `forge` AND no recognized manifest).
    ///
    /// CustomBackend (`--gate-cmd` / `--gate-file`) is selected via an
    /// explicit `Validator::with_backend(...)` in a later commit when that
    /// CLI surface lands; this method ignores gate overrides.
    pub fn auto(project_root: &Path, executor: ValidatorExecutor) -> Result<Self> {
        Self::auto_with(project_root, executor, forge_on_path())
    }

    /// Pure helper: same as [`Self::auto`] but takes the forge-on-PATH
    /// signal as an explicit parameter so the selection logic is
    /// unit-testable without depending on the dev machine's PATH.
    fn auto_with(
        project_root: &Path,
        executor: ValidatorExecutor,
        forge_present: bool,
    ) -> Result<Self> {
        if forge_present && project_root.join(".github").join("workflows").is_dir() {
            return Ok(Self::with_backend(Box::new(ForgeRunBackend::new(
                PathBuf::from("forge"),
                executor,
            ))));
        }
        if let Some(backend) = BuildTestBackend::infer(project_root) {
            return Ok(Self::with_backend(Box::new(backend)));
        }
        Err(Error::other(format!(
            "no validator backend applicable to `{}`: \
             `forge` is not on PATH (or no .github/workflows/ present) AND \
             no recognized build/test manifest (Cargo.toml) was detected. \
             Install `forge`, ship a manifest the BuildTest backend understands, \
             or pass an explicit backend (a future commit will expose `--gate-cmd`).",
            project_root.display(),
        )))
    }

    /// Validate a proposal by running every workflow in `workflow_paths`
    /// against the working tree at `workspace`. Returns a single
    /// `ValidationOutcome` summarizing the union (any failure → failure).
    ///
    /// The configured [`WorkflowFilter`] runs first; any workflow that
    /// doesn't satisfy it is dropped and surfaced in the outcome's
    /// `notes` so the operator can see what was skipped.
    pub fn validate(
        &self,
        proposal: &Proposal,
        workspace: &Path,
        workflow_paths: &[PathBuf],
    ) -> Result<ValidationOutcome> {
        if workflow_paths.is_empty() {
            if !self.backend.needs_workflow_file() {
                // Tree-mode backend (BuildTest / Custom). Run once
                // against the prepared tree using a sentinel workflow
                // path — backends that don't consume the path ignore
                // it; the receipt's validated_workflows reflects the
                // sentinel so the operator can see what was run.
                return self.run_tree_mode_backend(proposal, workspace);
            }
            return Ok(ValidationOutcome {
                proposal_id: proposal.id.clone(),
                conclusion: "unvalidated".to_string(),
                ci_forge_run_ids: Vec::new(),
                validated_workflows: Vec::new(),
                classification: Classification::Stubbed,
                notes: vec![
                    "no affected workflow was identified; bump cannot be validated by execution"
                        .to_string(),
                ],
            });
        }

        let filtered = self.workflow_filter.apply(workflow_paths, workspace);
        if filtered.is_empty() {
            let dropped: Vec<String> = workflow_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect();
            return Ok(ValidationOutcome {
                proposal_id: proposal.id.clone(),
                conclusion: "unvalidated".to_string(),
                ci_forge_run_ids: Vec::new(),
                validated_workflows: Vec::new(),
                classification: Classification::Stubbed,
                notes: vec![format!(
                    "every candidate workflow was excluded by the workflow filter \
                     (default: pull_request triggers only). Excluded: [{}]. \
                     Pass --include-workflow <glob> or --no-workflow-filter to override.",
                    dropped.join(", ")
                )],
            });
        }
        let mut filter_notes = Vec::new();
        if filtered.len() != workflow_paths.len() {
            let dropped: Vec<String> = workflow_paths
                .iter()
                .filter(|p| !filtered.contains(p))
                .map(|p| p.display().to_string())
                .collect();
            filter_notes.push(format!(
                "workflow filter excluded {} candidate(s): [{}]",
                dropped.len(),
                dropped.join(", ")
            ));
        }
        let workflow_paths = &filtered;

        // Per-validator log directory. The receipt-path-aware caller in
        // the new pipeline will instead pass an explicit log directory
        // rooted at `.assay/runs/<id>/logs/<proposal-id>/`; for v1
        // back-compat we use a tempdir.
        let log_dir = tempfile::Builder::new()
            .prefix("assay-validator-")
            .tempdir()
            .map_err(|source| Error::Io {
                path: workspace.to_path_buf(),
                source,
            })?;

        let mut run_ids = Vec::new();
        let mut any_failure = false;
        let mut notes = filter_notes;
        let mut validated = Vec::new();

        for workflow in workflow_paths {
            let stem = workflow_log_stem(workflow);
            let log_path = log_dir.path().join(format!("{stem}.log"));
            let outcome = self.backend.validate_workflow(
                workflow,
                workspace,
                self.workflow_timeout,
                &log_path,
            )?;
            validated.push(workflow.clone());
            if let Some(id) = &outcome.forge_run_id {
                run_ids.push(id.clone());
            }
            match &outcome.result {
                WorkflowResult::Pass => {}
                WorkflowResult::Fail(flavor) => {
                    any_failure = true;
                    let flavor_label = match flavor {
                        FailureFlavor::Regression { details } => format!("REGRESSION ({details})"),
                        FailureFlavor::SetupFailure { reason } => {
                            format!("SETUP-FAILURE ({reason})")
                        }
                        FailureFlavor::Timeout => "TIMEOUT".to_string(),
                    };
                    notes.push(format!(
                        "workflow {} concluded {flavor_label}",
                        workflow.display(),
                    ));
                }
            }
        }

        let (classification, conclusion) = if any_failure {
            (Classification::Unsupported, "failure".to_string())
        } else {
            (Classification::Exact, "success".to_string())
        };

        Ok(ValidationOutcome {
            proposal_id: proposal.id.clone(),
            conclusion,
            ci_forge_run_ids: run_ids,
            validated_workflows: validated,
            classification,
            notes,
        })
    }

    /// Tree-mode dispatch: a backend that doesn't need a workflow file
    /// (BuildTest, Custom) is invoked exactly once against the prepared
    /// tree. The synthetic workflow path is reported in
    /// `validated_workflows` so the receipt names what was run.
    fn run_tree_mode_backend(
        &self,
        proposal: &Proposal,
        workspace: &Path,
    ) -> Result<ValidationOutcome> {
        let log_dir = tempfile::Builder::new()
            .prefix("assay-validator-")
            .tempdir()
            .map_err(|source| Error::Io {
                path: workspace.to_path_buf(),
                source,
            })?;
        let synthetic = PathBuf::from(format!("<tree:{}>", self.backend.name()));
        let stem = "tree-mode";
        let log_path = log_dir.path().join(format!("{stem}.log"));
        let outcome = self.backend.validate_workflow(
            &synthetic,
            workspace,
            self.workflow_timeout,
            &log_path,
        )?;
        let mut notes = Vec::new();
        let (classification, conclusion) = match &outcome.result {
            WorkflowResult::Pass => (Classification::Exact, "success".to_string()),
            WorkflowResult::Fail(flavor) => {
                let flavor_label = match flavor {
                    FailureFlavor::Regression { details } => format!("REGRESSION ({details})"),
                    FailureFlavor::SetupFailure { reason } => format!("SETUP-FAILURE ({reason})"),
                    FailureFlavor::Timeout => "TIMEOUT".to_string(),
                };
                notes.push(format!("tree-mode validation concluded {flavor_label}"));
                (Classification::Unsupported, "failure".to_string())
            }
        };
        Ok(ValidationOutcome {
            proposal_id: proposal.id.clone(),
            conclusion,
            ci_forge_run_ids: outcome.forge_run_id.into_iter().collect(),
            validated_workflows: vec![synthetic],
            classification,
            notes,
        })
    }
}

/// Filesystem-safe workflow filename stem (extension dropped; non-alnum
/// replaced with `-`). For deeply-nested paths this collides, so the
/// pipeline's receipt layer adds a hash suffix — this helper is only used
/// for the temporary back-compat log dir and short filenames suffice.
fn workflow_log_stem(workflow: &Path) -> String {
    let raw = workflow
        .with_extension("")
        .to_string_lossy()
        .replace(['/', '\\', '.'], "-");
    if raw.is_empty() {
        "workflow".to_string()
    } else {
        raw
    }
}

/// Detect whether `forge` is on PATH by spawning `forge --version` and
/// checking that the call succeeded (the binary was found and ran). Any
/// non-Io error from spawn is treated as "not present" since we can't use
/// the binary anyway.
fn forge_on_path() -> bool {
    Command::new("forge").arg("--version").output().is_ok()
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProposalKind;

    fn sample_proposal() -> Proposal {
        Proposal {
            id: "cargo-serde-1-0-215".into(),
            ecosystem: "cargo".into(),
            kind: ProposalKind::Version,
            subject: "serde".into(),
            from: "1.0.200".into(),
            to: "1.0.215".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: crate::model::BumpTier::LockfileOnly,
        }
    }

    // -------------------------------------------------------------------------
    // ValidatorCommandBuilder (unchanged from before the refactor)
    // -------------------------------------------------------------------------

    #[test]
    fn command_builder_pins_narrow_flag_set() {
        let bin = PathBuf::from("forge");
        let workflow = PathBuf::from(".github/workflows/ci.yml");
        let workspace = PathBuf::from("/tmp/clone");
        let argv = ValidatorCommandBuilder::new(&bin)
            .workflow(&workflow)
            .workspace(&workspace)
            .event("push")
            .executor(ValidatorExecutor::Docker)
            .build_argv();
        assert_eq!(
            argv,
            vec![
                "forge".to_string(),
                "run".into(),
                "--workflow".into(),
                workflow.display().to_string(),
                "--workspace".into(),
                workspace.display().to_string(),
                "--event".into(),
                "push".into(),
                "--executor".into(),
                "docker".into(),
                "--format".into(),
                "json".into(),
            ]
        );
    }

    #[test]
    fn command_builder_emits_executor_choice_correctly() {
        let bin = PathBuf::from("forge");
        let workflow = PathBuf::from("ci.yml");
        let workspace = PathBuf::from("/tmp");
        let argv = ValidatorCommandBuilder::new(&bin)
            .workflow(&workflow)
            .workspace(&workspace)
            .executor(ValidatorExecutor::Host)
            .build_argv();
        let executor_idx = argv.iter().position(|a| a == "--executor").unwrap();
        assert_eq!(argv[executor_idx + 1], "host");
    }

    #[test]
    fn command_builder_defaults_event_to_push() {
        let bin = PathBuf::from("forge");
        let workflow = PathBuf::from("ci.yml");
        let workspace = PathBuf::from("/tmp");
        let argv = ValidatorCommandBuilder::new(&bin)
            .workflow(&workflow)
            .workspace(&workspace)
            .build_argv();
        let event_idx = argv.iter().position(|a| a == "--event").unwrap();
        assert_eq!(argv[event_idx + 1], "push");
    }

    // -------------------------------------------------------------------------
    // parse_forge_run_output (unchanged)
    // -------------------------------------------------------------------------

    #[test]
    fn parse_forge_run_output_extracts_run_id_and_conclusion() {
        let json = r#"{
            "schema_version": 1,
            "run_id": "local-1778981984157",
            "conclusion": "success",
            "workflows": []
        }"#;
        let parsed = parse_forge_run_output(json).expect("valid input parses");
        assert_eq!(parsed.run_id, "local-1778981984157");
        assert_eq!(parsed.conclusion, "success");
        assert!(parsed.is_success());
    }

    #[test]
    fn parse_forge_run_output_falls_back_to_workflow_conclusion() {
        let json = r#"{
            "schema_version": 1,
            "run_id": "local-123",
            "workflows": [{ "conclusion": "failure" }]
        }"#;
        let parsed = parse_forge_run_output(json).unwrap();
        assert_eq!(parsed.conclusion, "failure");
        assert!(!parsed.is_success());
    }

    #[test]
    fn parse_forge_run_output_returns_none_on_garbage() {
        assert!(parse_forge_run_output("not json").is_none());
        assert!(parse_forge_run_output("").is_none());
    }

    #[test]
    fn parse_forge_run_output_returns_none_when_run_id_missing() {
        let json = r#"{ "conclusion": "success" }"#;
        assert!(parse_forge_run_output(json).is_none());
    }

    #[test]
    fn parse_forge_run_output_handles_unknown_conclusion_gracefully() {
        let json = r#"{ "run_id": "id-1" }"#;
        let parsed = parse_forge_run_output(json).unwrap();
        assert_eq!(parsed.conclusion, "unknown");
        assert!(!parsed.is_success());
    }

    // -------------------------------------------------------------------------
    // ForgeRunBackend::classify — direct unit tests
    // -------------------------------------------------------------------------

    fn forge_run_backend() -> ForgeRunBackend {
        ForgeRunBackend::new(PathBuf::from("forge"), ValidatorExecutor::Docker)
    }

    #[test]
    fn forge_run_backend_returns_pass_on_success_json() {
        let backend = forge_run_backend();
        let stdout = r#"{
            "schema_version": 1,
            "run_id": "local-abc",
            "conclusion": "success",
            "workflows": []
        }"#;
        let outcome = backend.classify(
            Path::new("ci.yml"),
            Some(0),
            stdout,
            "",
            12,
            Path::new("/tmp/log"),
        );
        assert!(matches!(outcome.result, WorkflowResult::Pass));
        assert_eq!(outcome.forge_run_id.as_deref(), Some("local-abc"));
        assert_eq!(outcome.backend, "forge-run");
    }

    #[test]
    fn forge_run_backend_returns_regression_on_failure_json() {
        let backend = forge_run_backend();
        let stdout = r#"{
            "schema_version": 1,
            "run_id": "local-def",
            "conclusion": "failure",
            "workflows": []
        }"#;
        let outcome = backend.classify(
            Path::new("ci.yml"),
            Some(1),
            stdout,
            "some stderr",
            45,
            Path::new("/tmp/log"),
        );
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::Regression { details }) => {
                assert!(
                    details.contains("failure"),
                    "regression details should include the conclusion: {details}"
                );
            }
            other => panic!("expected Regression, got {other:?}"),
        }
        assert_eq!(outcome.forge_run_id.as_deref(), Some("local-def"));
    }

    #[test]
    fn forge_run_backend_returns_setup_failure_on_unparseable_output() {
        let backend = forge_run_backend();
        let outcome = backend.classify(
            Path::new("ci.yml"),
            Some(127),
            "not json at all",
            "forge: command not found",
            5,
            Path::new("/tmp/log"),
        );
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::SetupFailure { reason }) => {
                assert!(
                    reason.contains("unparseable"),
                    "setup-failure reason should explain the parse failure: {reason}"
                );
                assert!(
                    reason.contains("127"),
                    "setup-failure should include the exit code: {reason}"
                );
            }
            other => panic!("expected SetupFailure, got {other:?}"),
        }
        assert!(outcome.forge_run_id.is_none());
    }

    #[test]
    fn forge_run_backend_returns_setup_failure_when_run_id_missing() {
        let backend = forge_run_backend();
        let outcome = backend.classify(
            Path::new("ci.yml"),
            Some(0),
            r#"{ "conclusion": "success" }"#,
            "",
            5,
            Path::new("/tmp/log"),
        );
        // parse_forge_run_output returns None when run_id is missing,
        // so this is a SetupFailure not a Pass.
        assert!(matches!(
            outcome.result,
            WorkflowResult::Fail(FailureFlavor::SetupFailure { .. })
        ));
    }

    #[test]
    fn stderr_tail_truncates_to_byte_budget() {
        let big = "x".repeat(10_000);
        let tail = stderr_tail(&big, 4096);
        assert_eq!(tail.len(), 4096);
    }

    #[test]
    fn stderr_tail_passes_through_short_input() {
        let tail = stderr_tail("short", 4096);
        assert_eq!(tail, "short");
    }

    #[test]
    fn stderr_tail_respects_utf8_boundaries() {
        // Four-byte emoji at the cutoff — the tail must not slice into it.
        let mut s = "a".repeat(4094);
        s.push('🦀'); // 4 bytes
        s.push_str("post");
        let tail = stderr_tail(&s, 8);
        // Should be valid UTF-8 (parsing back to &str works).
        assert!(std::str::from_utf8(tail.as_bytes()).is_ok());
        assert!(tail.contains("post"));
    }

    // -------------------------------------------------------------------------
    // Validator (back-compat aggregation)
    // -------------------------------------------------------------------------

    #[test]
    fn validate_with_no_workflows_returns_stubbed_unvalidated() {
        let validator = Validator::new(ValidatorExecutor::Docker);
        let tmp = tempfile::tempdir().unwrap();
        let outcome = validator
            .validate(&sample_proposal(), tmp.path(), &[])
            .unwrap();
        assert_eq!(outcome.conclusion, "unvalidated");
        assert!(matches!(outcome.classification, Classification::Stubbed));
        assert!(outcome.ci_forge_run_ids.is_empty());
        assert!(!outcome.notes.is_empty(), "expected an explanatory note");
    }

    #[test]
    fn validate_propagates_missing_binary_as_io_error() {
        // Inject a backend that points at a binary that cannot exist on
        // PATH; the underlying spawn should fail.
        let bad_backend = ForgeRunBackend::new(
            PathBuf::from("nonexistent-forge-binary-zzz-12345"),
            ValidatorExecutor::Docker,
        );
        let validator = Validator::with_backend(Box::new(bad_backend));
        let tmp = tempfile::tempdir().unwrap();
        let workflow = PathBuf::from("ci.yml");
        let result = validator.validate(&sample_proposal(), tmp.path(), &[workflow]);
        match result {
            Err(Error::Io { .. }) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Trait-level test with a mock backend (proves dispatch works)
    // -------------------------------------------------------------------------

    struct MockBackend {
        result: WorkflowResult,
    }

    impl ValidatorBackend for MockBackend {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn validate_workflow(
            &self,
            workflow: &Path,
            _tree: &Path,
            _timeout: Duration,
            log_path: &Path,
        ) -> Result<WorkflowOutcome> {
            Ok(WorkflowOutcome {
                workflow: workflow.to_path_buf(),
                backend: self.name(),
                result: self.result.clone(),
                forge_run_id: None,
                duration_ms: 1,
                stderr_tail: String::new(),
                log_path: log_path.to_path_buf(),
            })
        }
    }

    #[test]
    fn validate_aggregates_workflow_outcomes_via_backend_trait() {
        // Two workflows: one passes, one is a regression. Aggregation
        // must collapse to failure, with a note describing the regression.
        let mock = MockBackend {
            result: WorkflowResult::Fail(FailureFlavor::Regression {
                details: "conclusion: failure".into(),
            }),
        };
        let validator = Validator::with_backend(Box::new(mock));
        let tmp = tempfile::tempdir().unwrap();
        let workflows = vec![PathBuf::from("a.yml"), PathBuf::from("b.yml")];
        let outcome = validator
            .validate(&sample_proposal(), tmp.path(), &workflows)
            .unwrap();
        assert_eq!(outcome.conclusion, "failure");
        assert!(matches!(
            outcome.classification,
            Classification::Unsupported
        ));
        assert_eq!(
            outcome.notes.len(),
            2,
            "both workflows should produce notes"
        );
        assert!(
            outcome.notes.iter().all(|n| n.contains("REGRESSION")),
            "regression flavor should surface in notes: {:?}",
            outcome.notes
        );
    }

    #[test]
    fn validate_returns_success_when_all_workflows_pass() {
        let mock = MockBackend {
            result: WorkflowResult::Pass,
        };
        let validator = Validator::with_backend(Box::new(mock));
        let tmp = tempfile::tempdir().unwrap();
        let workflows = vec![PathBuf::from("a.yml")];
        let outcome = validator
            .validate(&sample_proposal(), tmp.path(), &workflows)
            .unwrap();
        assert_eq!(outcome.conclusion, "success");
        assert!(matches!(outcome.classification, Classification::Exact));
        assert!(outcome.notes.is_empty(), "passing run should have no notes");
    }

    // -------------------------------------------------------------------------
    // BuildTestBackend
    // -------------------------------------------------------------------------

    /// Platform-portable "exit with code" argv (cmd /C on Windows, sh -c on Unix).
    fn shell_exit_argv(code: u8) -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd".into(), "/C".into(), format!("exit {code}")]
        } else {
            vec!["sh".into(), "-c".into(), format!("exit {code}")]
        }
    }

    #[test]
    fn build_test_backend_cargo_command_sequence_is_canonical() {
        let backend = BuildTestBackend::cargo();
        let commands = backend.commands();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0], vec!["cargo", "build", "--workspace"]);
        assert_eq!(commands[1], vec!["cargo", "test", "--workspace"]);
        assert_eq!(backend.name(), "build-test-cargo");
    }

    #[test]
    fn build_test_backend_infer_detects_cargo_root() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        let backend = BuildTestBackend::infer(tmp.path()).expect("Cargo.toml should be detected");
        assert_eq!(backend.name(), "build-test-cargo");
    }

    #[test]
    fn build_test_backend_infer_returns_none_for_empty_project() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(BuildTestBackend::infer(tmp.path()).is_none());
    }

    #[test]
    fn build_test_backend_validates_pass_when_all_commands_succeed() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = BuildTestBackend::with_commands(
            vec![shell_exit_argv(0), shell_exit_argv(0)],
            "test-pass",
        );
        let outcome = backend
            .validate_workflow(
                Path::new("ci.yml"),
                tmp.path(),
                Duration::from_secs(30),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        assert!(matches!(outcome.result, WorkflowResult::Pass));
        assert_eq!(outcome.backend, "test-pass");
        assert!(outcome.forge_run_id.is_none());
    }

    #[test]
    fn build_test_backend_validates_regression_on_nonzero_exit() {
        let tmp = tempfile::tempdir().unwrap();
        // First command succeeds; second fails. Short-circuits to a
        // Regression pinned to the failing command.
        let backend = BuildTestBackend::with_commands(
            vec![shell_exit_argv(0), shell_exit_argv(101)],
            "test-fail",
        );
        let outcome = backend
            .validate_workflow(
                Path::new("ci.yml"),
                tmp.path(),
                Duration::from_secs(30),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::Regression { details }) => {
                assert!(
                    details.contains("101"),
                    "regression details should include the exit code: {details}"
                );
            }
            other => panic!("expected Regression, got {other:?}"),
        }
    }

    #[test]
    fn build_test_backend_validates_setup_failure_on_missing_binary() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = BuildTestBackend::with_commands(
            vec![vec!["nonexistent-binary-zzz-assay-test-12345".into()]],
            "test-missing",
        );
        let outcome = backend
            .validate_workflow(
                Path::new("ci.yml"),
                tmp.path(),
                Duration::from_secs(30),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::SetupFailure { reason }) => {
                assert!(
                    reason.contains("nonexistent-binary"),
                    "reason should name the missing binary: {reason}"
                );
                assert!(
                    reason.contains("not found"),
                    "reason should indicate missing-binary: {reason}"
                );
            }
            other => panic!("expected SetupFailure, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Validator::auto backend selection (plan §C.4.c)
    // -------------------------------------------------------------------------

    #[test]
    fn auto_with_picks_forge_run_when_present_and_workflows_exist() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".github").join("workflows")).unwrap();
        let validator = Validator::auto_with(tmp.path(), ValidatorExecutor::Docker, true)
            .expect("backend should be selectable");
        assert_eq!(validator.backend.name(), "forge-run");
    }

    #[test]
    fn auto_with_falls_back_to_build_test_when_forge_missing() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        let validator = Validator::auto_with(tmp.path(), ValidatorExecutor::Docker, false)
            .expect("BuildTest fallback should apply");
        assert_eq!(validator.backend.name(), "build-test-cargo");
    }

    #[test]
    fn auto_with_falls_back_to_build_test_when_workflows_dir_missing() {
        // forge_present=true but no .github/workflows/ — the first branch
        // fails its second condition, so the BuildTest fallback wins.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        let validator = Validator::auto_with(tmp.path(), ValidatorExecutor::Docker, true)
            .expect("BuildTest fallback should apply when no workflows dir");
        assert_eq!(validator.backend.name(), "build-test-cargo");
    }

    // -------------------------------------------------------------------------
    // CustomBackend
    // -------------------------------------------------------------------------

    #[test]
    fn custom_backend_from_gate_cmd_splits_on_whitespace() {
        let backend = CustomBackend::from_gate_cmd("make test --jobs 4");
        assert_eq!(backend.argv(), &["make", "test", "--jobs", "4"]);
    }

    #[test]
    fn custom_backend_from_gate_file_uses_path_as_argv0() {
        let backend = CustomBackend::from_gate_file(Path::new("./check.sh"));
        assert_eq!(backend.argv().len(), 1);
        assert!(backend.argv()[0].contains("check.sh"));
    }

    #[test]
    fn custom_backend_passes_when_command_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = CustomBackend::new(shell_exit_argv(0));
        let outcome = backend
            .validate_workflow(
                Path::new("gate.yml"),
                tmp.path(),
                Duration::from_secs(30),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        assert!(matches!(outcome.result, WorkflowResult::Pass));
        assert_eq!(outcome.backend, "custom");
    }

    #[test]
    fn custom_backend_regresses_on_nonzero_exit() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = CustomBackend::new(shell_exit_argv(42));
        let outcome = backend
            .validate_workflow(
                Path::new("gate.yml"),
                tmp.path(),
                Duration::from_secs(30),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::Regression { details }) => {
                assert!(
                    details.contains("42"),
                    "regression details should include the exit code: {details}"
                );
            }
            other => panic!("expected Regression, got {other:?}"),
        }
    }

    #[test]
    fn custom_backend_setup_failure_when_binary_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = CustomBackend::new(vec!["nonexistent-binary-zzz-assay-custom-9876".into()]);
        let outcome = backend
            .validate_workflow(
                Path::new("gate.yml"),
                tmp.path(),
                Duration::from_secs(30),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::SetupFailure { reason }) => {
                assert!(
                    reason.contains("not found"),
                    "reason should indicate missing-binary: {reason}"
                );
            }
            other => panic!("expected SetupFailure, got {other:?}"),
        }
    }

    fn slow_sleep_argv() -> Vec<String> {
        // Platform-portable "block for ~10s" command — same trick as
        // process_runner::tests::slow_sleep_argv. Invoke directly so the
        // kill path on Windows hits ping itself (cmd /C would fork a
        // child that outlives the parent due to the Windows process-tree
        // kill limitation documented in process_runner).
        if cfg!(windows) {
            vec!["ping".into(), "-n".into(), "11".into(), "127.0.0.1".into()]
        } else {
            vec!["sh".into(), "-c".into(), "sleep 10".into()]
        }
    }

    #[test]
    fn custom_backend_reports_timeout_flavor_when_command_overruns() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = CustomBackend::new(slow_sleep_argv());
        let outcome = backend
            .validate_workflow(
                Path::new("gate.yml"),
                tmp.path(),
                Duration::from_millis(500),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::Timeout) => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
        // Should not have waited the full 10 seconds.
        assert!(
            outcome.duration_ms < 5000,
            "timeout should fire promptly: duration_ms={}",
            outcome.duration_ms
        );
    }

    #[test]
    fn build_test_backend_reports_timeout_flavor_when_command_overruns() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = BuildTestBackend::with_commands(vec![slow_sleep_argv()], "test-timeout");
        let outcome = backend
            .validate_workflow(
                Path::new("gate.yml"),
                tmp.path(),
                Duration::from_millis(500),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::Timeout) => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
        assert!(
            outcome.duration_ms < 5000,
            "timeout should fire promptly: duration_ms={}",
            outcome.duration_ms
        );
    }

    #[test]
    fn custom_backend_setup_failure_when_argv_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let backend = CustomBackend::new(vec![]);
        let outcome = backend
            .validate_workflow(
                Path::new("gate.yml"),
                tmp.path(),
                Duration::from_secs(30),
                &tmp.path().join("log.txt"),
            )
            .unwrap();
        match outcome.result {
            WorkflowResult::Fail(FailureFlavor::SetupFailure { reason }) => {
                assert!(
                    reason.contains("empty argv"),
                    "reason should explain empty argv: {reason}"
                );
            }
            other => panic!("expected SetupFailure, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------
    // Validator::auto backend selection (plan §C.4.c)
    // -------------------------------------------------------------------------

    // -------------------------------------------------------------------------
    // Validator + WorkflowFilter integration
    // -------------------------------------------------------------------------

    fn write_workflow(tree: &Path, name: &str, yaml: &str) -> PathBuf {
        let dir = tree.join(".github").join("workflows");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(name), yaml).unwrap();
        PathBuf::from(".github/workflows").join(name)
    }

    #[test]
    fn validate_returns_unvalidated_when_filter_excludes_every_workflow() {
        let tmp = tempfile::tempdir().unwrap();
        let push_only = write_workflow(
            tmp.path(),
            "deploy.yml",
            "name: deploy\non: push\njobs: {}\n",
        );
        let validator = Validator::with_backend(Box::new(MockBackend {
            result: WorkflowResult::Pass,
        }));
        let outcome = validator
            .validate(&sample_proposal(), tmp.path(), &[push_only])
            .unwrap();
        assert_eq!(outcome.conclusion, "unvalidated");
        assert!(matches!(outcome.classification, Classification::Stubbed));
        assert!(
            outcome.validated_workflows.is_empty(),
            "no workflow should have been run"
        );
        assert!(
            outcome.notes.iter().any(|n| n.contains("excluded by")),
            "outcome should explain why nothing ran: {:?}",
            outcome.notes
        );
    }

    #[test]
    fn validate_runs_only_workflows_that_survive_the_filter() {
        let tmp = tempfile::tempdir().unwrap();
        let pr_workflow = write_workflow(
            tmp.path(),
            "ci.yml",
            "name: CI\non: pull_request\njobs: {}\n",
        );
        let deploy_workflow = write_workflow(
            tmp.path(),
            "deploy.yml",
            "name: deploy\non: push\njobs: {}\n",
        );
        let validator = Validator::with_backend(Box::new(MockBackend {
            result: WorkflowResult::Pass,
        }));
        let outcome = validator
            .validate(
                &sample_proposal(),
                tmp.path(),
                &[pr_workflow.clone(), deploy_workflow],
            )
            .unwrap();
        assert_eq!(outcome.conclusion, "success");
        assert_eq!(
            outcome.validated_workflows,
            vec![pr_workflow],
            "only the pull_request workflow should have been run"
        );
        assert!(
            outcome.notes.iter().any(|n| n.contains("filter excluded")),
            "outcome should record what the filter dropped: {:?}",
            outcome.notes
        );
    }

    #[test]
    fn validate_disables_filter_when_accept_all_supplied() {
        let tmp = tempfile::tempdir().unwrap();
        let push_only = write_workflow(
            tmp.path(),
            "deploy.yml",
            "name: deploy\non: push\njobs: {}\n",
        );
        let validator = Validator::with_backend(Box::new(MockBackend {
            result: WorkflowResult::Pass,
        }))
        .with_workflow_filter(WorkflowFilter::accept_all());
        let outcome = validator
            .validate(
                &sample_proposal(),
                tmp.path(),
                std::slice::from_ref(&push_only),
            )
            .unwrap();
        assert_eq!(outcome.conclusion, "success");
        assert_eq!(outcome.validated_workflows, vec![push_only]);
    }

    #[test]
    fn auto_with_errors_when_nothing_applicable() {
        let tmp = tempfile::tempdir().unwrap();
        // Empty tempdir: no Cargo.toml, no .github/workflows/, forge missing.
        let result = Validator::auto_with(tmp.path(), ValidatorExecutor::Docker, false);
        match result {
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("no validator backend applicable"),
                    "error should explain the failure: {msg}"
                );
            }
            Ok(_) => panic!("should fail when no backend applies"),
        }
    }
}
