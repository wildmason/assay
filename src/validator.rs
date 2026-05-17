//! Validator stage — runs each `Proposal`'s affected workflow through
//! `forge run` and turns the conclusion into a `ValidationOutcome`.
//!
//! This module shells out to the existing `forge` CLI rather than linking
//! the orchestrator as a library. The architectural reviewer flagged that
//! a 30+-flag CLI string is fragile, so the mitigation is to pin the
//! exact narrow flag set assay uses in *one* place
//! ([`ValidatorCommandBuilder::build_argv`]) and test against it. When
//! the library-API extraction lands in a future refactor, only this
//! module changes; the `Validator` public surface and `ValidationOutcome`
//! contract stay identical.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::error::{Error, Result};
use crate::model::{Classification, Proposal, ValidationOutcome};

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

#[derive(Debug, Clone)]
pub struct Validator {
    /// Path to the `forge` binary. Defaults to `"forge"` (PATH lookup);
    /// tests override to a fixture script.
    pub forge_bin: PathBuf,
    pub executor: ValidatorExecutor,
}

impl Validator {
    pub fn new(executor: ValidatorExecutor) -> Self {
        Self {
            forge_bin: PathBuf::from("forge"),
            executor,
        }
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

        let mut run_ids = Vec::new();
        let mut any_failure = false;
        let mut notes = Vec::new();
        let mut validated = Vec::new();

        for workflow in workflow_paths {
            let argv = ValidatorCommandBuilder::new(&self.forge_bin)
                .workflow(workflow)
                .workspace(workspace)
                .event("push")
                .executor(self.executor)
                .build_argv();

            let mut command = Command::new(&argv[0]);
            command.args(&argv[1..]);
            command.current_dir(workspace);
            let output = command.output().map_err(|source| Error::Io {
                path: workspace.to_path_buf(),
                source,
            })?;
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

            let parsed = parse_forge_run_output(&stdout);
            match parsed {
                Some(parsed) => {
                    run_ids.push(parsed.run_id.clone());
                    validated.push(workflow.clone());
                    if !parsed.is_success() {
                        any_failure = true;
                        notes.push(format!(
                            "workflow {} concluded {} (ci-forge run id {})",
                            workflow.display(),
                            parsed.conclusion,
                            parsed.run_id,
                        ));
                    }
                }
                None => {
                    any_failure = true;
                    notes.push(format!(
                        "workflow {} produced unparseable forge-run output (exit {}); stderr tail: {}",
                        workflow.display(),
                        output
                            .status
                            .code()
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "signal".into()),
                        stderr.lines().last().unwrap_or("").trim(),
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

/// Builder for the `forge run` invocation. Assay depends on this
/// exact narrow flag set; if `forge`'s CLI changes, this is the single
/// place to update. Unit-tested separately from the subprocess wiring.
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

/// Parsed shape of `forge run --format json` output that assay
/// cares about. Anything beyond these fields is irrelevant to the
/// validator's verdict — keeping the surface narrow means forge's
/// internal receipt schema can evolve without breaking assay.
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
/// caller surfaces that as a validation failure.
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
        // Exactly the v1 contract — if forge-cli's CLI ever changes,
        // this test forces a deliberate update.
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
        // No top-level `conclusion`; the parser must reach into
        // `workflows[].conclusion` so we tolerate schema renaming.
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
        let mut validator = Validator::new(ValidatorExecutor::Docker);
        // Point at a binary that cannot possibly exist.
        validator.forge_bin = PathBuf::from("nonexistent-forge-binary-zzz-12345");
        let tmp = tempfile::tempdir().unwrap();
        let workflow = PathBuf::from("ci.yml");
        let result = validator.validate(&sample_proposal(), tmp.path(), &[workflow]);
        match result {
            Err(Error::Io { .. }) => {}
            other => panic!("expected Io error, got {other:?}"),
        }
    }
}
