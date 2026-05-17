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
        _timeout: Duration,
        log_path: &Path,
    ) -> Result<WorkflowOutcome> {
        let started = Instant::now();
        let argv = ValidatorCommandBuilder::new(&self.forge_bin)
            .workflow(workflow)
            .workspace(tree)
            .event("push")
            .executor(self.executor)
            .build_argv();

        let mut command = Command::new(&argv[0]);
        command.args(&argv[1..]);
        command.current_dir(tree);
        let output = command.output().map_err(|source| Error::Io {
            path: tree.to_path_buf(),
            source,
        })?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

        // Best-effort: persist the captured output to log_path. Errors here
        // are non-fatal — the classification doesn't depend on the file
        // landing, but the operator benefits from having logs to grep.
        let log_content = format!("=== STDOUT ===\n{stdout}\n=== STDERR ===\n{stderr}");
        let _ = std::fs::create_dir_all(log_path.parent().unwrap_or(Path::new(".")));
        let _ = std::fs::write(log_path, log_content);

        let duration_ms = started.elapsed().as_millis();
        let exit_code = output.status.code();
        Ok(self.classify(workflow, exit_code, &stdout, &stderr, duration_ms, log_path))
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
// Validator (thin orchestrator over backends)
// =============================================================================

/// Default per-workflow timeout. Plumbed through the trait but not yet
/// honored — see module docs.
pub const DEFAULT_WORKFLOW_TIMEOUT: Duration = Duration::from_secs(30 * 60);

/// Drives a [`ValidatorBackend`] across each workflow in a proposal.
pub struct Validator {
    backend: Box<dyn ValidatorBackend>,
    workflow_timeout: Duration,
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
        }
    }

    /// Override the per-workflow timeout (default
    /// [`DEFAULT_WORKFLOW_TIMEOUT`] = 30 minutes).
    pub fn with_workflow_timeout(mut self, timeout: Duration) -> Self {
        self.workflow_timeout = timeout;
        self
    }

    /// Validate a proposal by running every workflow in `workflow_paths`
    /// against the working tree at `workspace`. Returns a single
    /// `ValidationOutcome` summarizing the union (any failure → failure).
    pub fn validate(
        &self,
        proposal: &Proposal,
        workspace: &Path,
        workflow_paths: &[PathBuf],
    ) -> Result<ValidationOutcome> {
        if workflow_paths.is_empty() {
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
        let mut notes = Vec::new();
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
}
