//! Manifest-inferred build+test [`crate::validator::ValidatorBackend`].
//!
//! The fallback used when `forge` is not on PATH or the project has
//! no `.github/workflows/` directory: runs a configured command
//! sequence (e.g. `cargo build --workspace` then `cargo test --workspace`)
//! against the prepared tree. The first non-success short-circuits to
//! a `Regression` outcome; a missing binary produces a `SetupFailure`.

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use crate::error::Result;
use crate::failure_parser::{EcosystemHint, hint_from_command, parse as parse_failure};
use crate::process_runner::{RunResult, run_with_timeout};
use crate::verdict_cache::fingerprint_commands;

use super::{FailureFlavor, ValidatorBackend, WorkflowOutcome, WorkflowResult, stderr_tail};

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
                        let hint = hint_from_command(cmd);
                        let failure_context = Some(parse_failure(&stderr_tail_str, hint));
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
                            cached_at_unix_secs: None,
                            failure_context,
                        };
                    }
                }
                BuildTestStepOutcome::TimedOut { stderr, .. } => {
                    let stderr_str = String::from_utf8_lossy(stderr).into_owned();
                    let stderr_tail_str = stderr_tail(&stderr_str, 4096);
                    let hint = hint_from_command(cmd);
                    let failure_context = Some(parse_failure(&stderr_tail_str, hint));
                    return WorkflowOutcome {
                        workflow: workflow.to_path_buf(),
                        backend: self.label,
                        result: WorkflowResult::Fail(FailureFlavor::Timeout),
                        forge_run_id: None,
                        duration_ms,
                        stderr_tail: stderr_tail_str,
                        log_path: log_path.to_path_buf(),
                        cached_at_unix_secs: None,
                        failure_context,
                    };
                }
                BuildTestStepOutcome::SpawnFailed { error } => {
                    let bin = cmd.first().map(String::as_str).unwrap_or("(empty)");
                    let reason = if error.kind() == std::io::ErrorKind::NotFound {
                        format!("binary `{bin}` not found on PATH")
                    } else {
                        format!("couldn't spawn `{bin}`: {error}")
                    };
                    // SetupFailure: no captured stderr, so the
                    // structured context just echoes the reason as
                    // the summary under `generic:unstructured`.
                    let failure_context = Some(parse_failure(&reason, EcosystemHint::Auto));
                    return WorkflowOutcome {
                        workflow: workflow.to_path_buf(),
                        backend: self.label,
                        result: WorkflowResult::Fail(FailureFlavor::SetupFailure { reason }),
                        forge_run_id: None,
                        duration_ms,
                        stderr_tail: String::new(),
                        log_path: log_path.to_path_buf(),
                        cached_at_unix_secs: None,
                        failure_context,
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
            cached_at_unix_secs: None,
            failure_context: None,
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

    fn fingerprint(&self) -> String {
        format!("{}:{}", self.label, fingerprint_commands(&self.commands))
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
                    let stderr_tail_str = stderr_tail(&stderr_combined, 4096);
                    let hint = hint_from_command(cmd);
                    let failure_context = Some(parse_failure(&stderr_tail_str, hint));
                    return Ok(WorkflowOutcome {
                        workflow: workflow.to_path_buf(),
                        backend: self.label,
                        result: WorkflowResult::Fail(FailureFlavor::Timeout),
                        forge_run_id: None,
                        duration_ms: started.elapsed().as_millis(),
                        stderr_tail: stderr_tail_str,
                        log_path: log_path.to_path_buf(),
                        cached_at_unix_secs: None,
                        failure_context,
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
