//! CLI surface for `assay`.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::ecosystem::{DependencyEcosystem, EcosystemContext, default_registry};
use crate::error::{Error, Result};
use crate::model::{
    AssayRunReceipt, Classification, Manifest, Proposal, Provenance, ProvenanceRecord,
    RepositoryRef, RunSummary,
};
use crate::receipt::write_run_receipt;
use crate::validator::{Validator, ValidatorExecutor};
use crate::workflow_filter::WorkflowFilter;

#[derive(Debug, Parser)]
#[command(name = "assay")]
#[command(
    about = "Dependency upgrade impact analyzer — test upgrades against your projects' real CI before you adopt them"
)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Analyze a repository for dependency upgrade impact; report per-proposal pass/fail.
    Analyze(AnalyzeArgs),
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("apply_mode")
        .args(["apply_local", "apply_pr"])
        .multiple(false)
))]
pub struct AnalyzeArgs {
    /// Repository root to scan. Defaults to the current directory.
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    /// Which ecosystems to scan. Defaults to all enabled in config.
    #[arg(long, value_enum)]
    pub ecosystem: Option<EcosystemSelector>,

    /// Write proposed bumps into an isolated retained worktree but do NOT open PRs.
    /// Mutually exclusive with --apply-pr.
    #[arg(long)]
    pub apply_local: bool,

    /// Open PR(s) on the remote forge. Refused when $CI is set, when the
    /// working tree is dirty, or when the push target is a protected
    /// branch — override with --force. Mutually exclusive with --apply-local.
    #[arg(long)]
    pub apply_pr: bool,

    /// Validate Cargo bumps on the host instead of inside Docker. Defeats
    /// the build-script-isolation default. Only use against repos whose
    /// transitive crate graph you fully audit.
    #[arg(long)]
    pub unsafe_host_validation: bool,

    /// Override the apply-pr safety refusals ($CI / dirty tree /
    /// protected branch). Logged as a top-level provenance record.
    #[arg(long)]
    pub force: bool,

    /// Executor used by the Validator stage.
    #[arg(long, value_enum, default_value = "docker")]
    pub executor: ExecutorChoice,

    /// Output format for terminal summaries.
    #[arg(long, value_enum, default_value = "text")]
    pub format: OutputFormat,

    /// Workflow path glob to always include, regardless of trigger.
    /// Repeatable. Match runs against the workflow's basename and its
    /// repo-relative path (forward-slash normalized).
    #[arg(long = "include-workflow", value_name = "GLOB")]
    pub include_workflows: Vec<String>,

    /// Workflow path glob to always exclude. Repeatable. Takes precedence
    /// over `--include-workflow`.
    #[arg(long = "exclude-workflow", value_name = "GLOB")]
    pub exclude_workflows: Vec<String>,

    /// Disable the default pull_request-trigger filter; run every
    /// workflow returned by the ecosystem. Use for projects whose CI
    /// suite isn't expressed via pull_request triggers.
    #[arg(long)]
    pub no_workflow_filter: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum EcosystemSelector {
    Cargo,
    GithubActions,
    All,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum ExecutorChoice {
    Host,
    Docker,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

/// Parse a vector of CLI arguments without running anything. Exposed for tests.
pub fn parse_cli(args: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>) -> Cli {
    Cli::parse_from(args)
}

/// Process entry point. Called by `main()`.
pub fn run() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("assay: {err}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Analyze(args) => analyze_command(args),
    }
}

/// Apply mode derived from mutually-exclusive --apply-local / --apply-pr.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMode {
    DryRun,
    ApplyLocal,
    ApplyPr,
}

impl ApplyMode {
    pub fn from_args(args: &AnalyzeArgs) -> Self {
        if args.apply_pr {
            ApplyMode::ApplyPr
        } else if args.apply_local {
            ApplyMode::ApplyLocal
        } else {
            ApplyMode::DryRun
        }
    }
}

fn analyze_command(args: AnalyzeArgs) -> Result<()> {
    if !args.repo.is_dir() {
        return Err(Error::RepoNotFound(args.repo));
    }
    let mode = ApplyMode::from_args(&args);
    if matches!(mode, ApplyMode::ApplyLocal | ApplyMode::ApplyPr)
        && args.executor == ExecutorChoice::Host
        && !args.unsafe_host_validation
    {
        return Err(Error::other(
            "--executor host requires --unsafe-host-validation for apply modes; \
             dependency validation may execute newly bumped build scripts",
        ));
    }

    // --apply-pr is fully gated until the gh-CLI publisher lands. Surface
    // the actionable next step before any dirty-tree check so the operator
    // gets the most useful message.
    if matches!(mode, ApplyMode::ApplyPr) {
        return Err(Error::other(
            "--apply-pr is not yet wired in v1: see docs/assay-plan.md §C.6.b for the planned gh-CLI-backed implementation.",
        ));
    }
    // Safety: apply modes refuse on a dirty tree unless --force.
    if matches!(mode, ApplyMode::ApplyLocal) && !args.force {
        if let Some(dirty_path) = working_tree_dirty_path(&args.repo)? {
            return Err(Error::other(format!(
                "refusing to --apply-local against a dirty working tree (uncommitted changes at {dirty_path}). \
                 Commit or stash, or pass --force to override."
            )));
        }
    }

    let registry = default_registry();
    let context = EcosystemContext {
        action_store: None,
        allow_network: false,
    };
    let started_at = iso8601_now();
    let run_id = generate_run_id();
    let mut total_manifests = 0usize;
    let mut all_proposals: Vec<(usize, Proposal)> = Vec::new();
    let mut provenance = Provenance::default();

    for (idx, ecosystem) in registry.iter().enumerate() {
        if !ecosystem_enabled(&args, ecosystem.as_ref()) {
            continue;
        }
        let manifests = ecosystem.detect_manifests(&args.repo)?;
        match args.format {
            OutputFormat::Text => report_text(ecosystem.name(), &manifests),
            OutputFormat::Json => report_json(ecosystem.name(), &manifests)?,
        }
        for manifest in &manifests {
            provenance.records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("scanner.{}", ecosystem.name()),
                subject: manifest.path.display().to_string(),
                status: Classification::Exact,
                summary: format!("detected {:?}", manifest.kind),
                artifact_path: None,
                details: None,
            });
        }
        if !manifests.is_empty() {
            let proposals = ecosystem.propose_updates(&manifests, &args.repo, &context)?;
            for proposal in &proposals {
                provenance.records.push(ProvenanceRecord {
                    tool: "assay".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    stage: format!("proposer.{}", ecosystem.name()),
                    subject: proposal.id.clone(),
                    status: proposal.initial_classification,
                    summary: format!("{} {} -> {}", proposal.subject, proposal.from, proposal.to),
                    artifact_path: None,
                    details: Some(serde_json::to_value(proposal).map_err(Error::Json)?),
                });
                if matches!(args.format, OutputFormat::Text) {
                    println!(
                        "    proposal {}: {} {} -> {}",
                        proposal.id, proposal.subject, proposal.from, proposal.to,
                    );
                }
            }
            for proposal in proposals {
                all_proposals.push((idx, proposal));
            }
        }
        total_manifests += manifests.len();
    }

    let mut proposals_passed = 0usize;
    let mut proposals_failed = 0usize;
    let mut proposals_unvalidated = 0usize;

    if matches!(mode, ApplyMode::ApplyLocal) && !all_proposals.is_empty() {
        let validator_executor = match args.executor {
            ExecutorChoice::Host => ValidatorExecutor::Host,
            ExecutorChoice::Docker => ValidatorExecutor::Docker,
        };
        let validator = Validator::auto(&args.repo, validator_executor)?
            .with_workflow_filter(workflow_filter_from_args(&args));

        for (eco_idx, proposal) in &all_proposals {
            let ecosystem = registry[*eco_idx].as_ref();
            let apply_tree = match prepare_apply_local_tree(&args.repo, &run_id, &proposal.id) {
                Ok(path) => path,
                Err(err) => {
                    provenance.records.push(ProvenanceRecord {
                        tool: "assay".into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        stage: format!("applier.{}", ecosystem.name()),
                        subject: proposal.id.clone(),
                        status: Classification::Unsupported,
                        summary: format!("apply tree preparation failed: {err}"),
                        artifact_path: None,
                        details: None,
                    });
                    proposals_failed += 1;
                    continue;
                }
            };
            if let Err(err) = ecosystem.apply_proposal(proposal, &apply_tree) {
                provenance.records.push(ProvenanceRecord {
                    tool: "assay".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    stage: format!("applier.{}", ecosystem.name()),
                    subject: proposal.id.clone(),
                    status: Classification::Unsupported,
                    summary: format!("apply failed: {err}"),
                    artifact_path: None,
                    details: None,
                });
                proposals_failed += 1;
                continue;
            }
            provenance.records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("applier.{}", ecosystem.name()),
                subject: proposal.id.clone(),
                status: Classification::Exact,
                summary: "applied to isolated retained worktree".into(),
                artifact_path: None,
                details: Some(serde_json::json!({ "worktree": apply_tree })),
            });

            // Validate the bump via ci-forge.
            let workflow_paths = ecosystem
                .gate_workflows(proposal, &apply_tree)
                .unwrap_or_default();
            let outcome = match validator.validate(proposal, &apply_tree, &workflow_paths) {
                Ok(outcome) => outcome,
                Err(err) => {
                    // Best-effort: skip validation when forge isn't on PATH.
                    proposals_unvalidated += 1;
                    provenance.records.push(ProvenanceRecord {
                        tool: "assay".into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        stage: format!("validator.{}", ecosystem.name()),
                        subject: proposal.id.clone(),
                        status: Classification::Stubbed,
                        summary: format!("validator could not run: {err}"),
                        artifact_path: None,
                        details: None,
                    });
                    continue;
                }
            };
            match outcome.conclusion.as_str() {
                "success" => proposals_passed += 1,
                "unvalidated" => proposals_unvalidated += 1,
                _ => proposals_failed += 1,
            }
            provenance.records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("validator.{}", ecosystem.name()),
                subject: proposal.id.clone(),
                status: outcome.classification,
                summary: format!(
                    "validation {} ({} run(s))",
                    outcome.conclusion,
                    outcome.ci_forge_run_ids.len()
                ),
                artifact_path: None,
                details: Some(serde_json::to_value(&outcome).map_err(Error::Json)?),
            });
        }
    } else {
        proposals_unvalidated = all_proposals.len();
    }

    let summary = RunSummary {
        manifests_scanned: total_manifests,
        proposals_total: all_proposals.len(),
        proposals_passed,
        proposals_failed,
        proposals_unvalidated,
        prs_opened: 0,
    };
    let finished_at = iso8601_now();
    let receipt = AssayRunReceipt {
        schema_version: 1,
        run_id: run_id.clone(),
        started_at,
        finished_at,
        repository: RepositoryRef {
            path: args.repo.clone(),
            github: None,
            git_ref: None,
        },
        summary,
        provenance,
    };
    let run_json_path = write_run_receipt(&args.repo, &receipt)?;

    if matches!(args.format, OutputFormat::Text) {
        println!(
            "assay: scanned {} manifest(s) across {} ecosystem(s); {} proposal(s) (mode={:?})",
            total_manifests,
            registry.len(),
            all_proposals.len(),
            mode,
        );
        if matches!(mode, ApplyMode::ApplyLocal) {
            println!(
                "assay: applied {} / failed {} / unvalidated {}",
                proposals_passed, proposals_failed, proposals_unvalidated,
            );
            if !all_proposals.is_empty() {
                println!(
                    "assay: applied worktrees are retained under {}",
                    args.repo
                        .join(".assay")
                        .join("runs")
                        .join(&run_id)
                        .join("work")
                        .display()
                );
            }
        }
        println!("assay: receipt written to {}", run_json_path.display());
    }
    Ok(())
}

/// Returns `Some(path_to_first_dirty_file)` if `git status --porcelain`
/// reports any uncommitted change; `None` for a clean tree or when the
/// repo isn't a git checkout (in which case there's nothing to protect).
fn working_tree_dirty_path(repo: &std::path::Path) -> Result<Option<String>> {
    if !repo.join(".git").exists() {
        return Ok(None);
    }
    let output = std::process::Command::new("git")
        .arg("status")
        .arg("--porcelain")
        .current_dir(repo)
        .output()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        // Treat git failure as "we don't know" — better to refuse and ask the
        // operator than risk apply-local on a partial state.
        return Err(Error::other(format!(
            "git status failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().next().map(|s| s.to_string()))
}

fn prepare_apply_local_tree(
    repo: &std::path::Path,
    run_id: &str,
    proposal_id: &str,
) -> Result<PathBuf> {
    if !repo.join(".git").exists() {
        return Err(Error::other(
            "--apply-local requires a git checkout so assay can retain an isolated worktree",
        ));
    }
    let work_root = repo.join(".assay").join("runs").join(run_id).join("work");
    std::fs::create_dir_all(&work_root).map_err(|source| Error::Io {
        path: work_root.clone(),
        source,
    })?;
    let base = safe_apply_tree_name(proposal_id);
    let mut target = work_root.join(&base);
    let mut suffix = 2usize;
    while target.exists() {
        target = work_root.join(format!("{base}-{suffix}"));
        suffix += 1;
    }
    let output = std::process::Command::new("git")
        .arg("worktree")
        .arg("add")
        .arg("--detach")
        .arg(&target)
        .arg("HEAD")
        .current_dir(repo)
        .output()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(target)
}

fn safe_apply_tree_name(proposal_id: &str) -> String {
    let mut out = String::with_capacity(proposal_id.len().min(80));
    let mut last_dash = false;
    for ch in proposal_id.chars().flat_map(char::to_lowercase) {
        let mapped = if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            ch
        } else {
            '-'
        };
        if mapped == '-' {
            if !last_dash && !out.is_empty() {
                out.push(mapped);
                last_dash = true;
            }
        } else {
            out.push(mapped);
            last_dash = false;
        }
        if out.len() >= 80 {
            break;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "proposal".into()
    } else {
        out
    }
}

fn generate_run_id() -> String {
    let unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("assay-{unix_ms}")
}

fn iso8601_now() -> String {
    // Lean-weight ISO 8601 in UTC without pulling chrono. We have second
    // granularity which is sufficient for receipt timestamps.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let (year, month, day, hour, minute, second) = unix_to_utc_components(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Convert a UNIX timestamp (seconds since 1970-01-01) to (year, month,
/// day, hour, minute, second) in UTC. Avoids the chrono dependency.
fn unix_to_utc_components(secs: u64) -> (i32, u32, u32, u32, u32, u32) {
    let days_since_epoch = (secs / 86_400) as i64;
    let seconds_today = secs % 86_400;
    let hour = (seconds_today / 3600) as u32;
    let minute = ((seconds_today % 3600) / 60) as u32;
    let second = (seconds_today % 60) as u32;
    let (year, month, day) = civil_from_days(days_since_epoch);
    (year, month, day, hour, minute, second)
}

/// Algorithm from Howard Hinnant: convert days since 1970-01-01 to civil
/// (year, month, day). Public-domain reference implementation.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

/// Build the [`WorkflowFilter`] from the parsed CLI args.
///
/// Defaults to [`WorkflowFilter::pull_request_default`]; flipped to
/// [`WorkflowFilter::accept_all`] when `--no-workflow-filter` is set.
/// Include/exclude globs are layered on top of either base.
fn workflow_filter_from_args(args: &AnalyzeArgs) -> WorkflowFilter {
    let base = if args.no_workflow_filter {
        WorkflowFilter::accept_all()
    } else {
        WorkflowFilter::pull_request_default()
    };
    WorkflowFilter {
        include_globs: args.include_workflows.clone(),
        exclude_globs: args.exclude_workflows.clone(),
        ..base
    }
}

fn ecosystem_enabled(args: &AnalyzeArgs, ecosystem: &dyn DependencyEcosystem) -> bool {
    let Some(selector) = args.ecosystem else {
        return true;
    };
    matches!(
        (selector, ecosystem.name()),
        (EcosystemSelector::All, _)
            | (EcosystemSelector::Cargo, "cargo")
            | (EcosystemSelector::GithubActions, "github-actions")
    )
}

fn report_text(name: &str, manifests: &[Manifest]) {
    println!("[{name}] manifests detected: {}", manifests.len());
    for manifest in manifests {
        println!("  - {}", manifest.path.display());
    }
}

fn report_json(name: &str, manifests: &[Manifest]) -> Result<()> {
    let payload = serde_json::json!({
        "ecosystem": name,
        "manifests": manifests,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&payload).map_err(crate::error::Error::Json)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cli_accepts_analyze_with_defaults() {
        let cli = parse_cli(["assay", "analyze"]);
        match cli.command {
            Command::Analyze(args) => {
                assert!(!args.apply_local);
                assert!(!args.apply_pr);
                assert!(!args.unsafe_host_validation);
                assert!(!args.force);
                assert_eq!(args.executor, ExecutorChoice::Docker);
                assert!(args.ecosystem.is_none());
            }
        }
    }

    #[test]
    fn parse_cli_rejects_apply_local_and_remote_together() {
        let parsed = Cli::try_parse_from(["assay", "analyze", "--apply-local", "--apply-pr"]);
        assert!(
            parsed.is_err(),
            "--apply-local and --apply-pr must be mutually exclusive"
        );
    }

    #[test]
    fn parse_cli_accepts_ecosystem_selector() {
        let cli = parse_cli(["assay", "analyze", "--ecosystem", "cargo"]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(args.ecosystem, Some(EcosystemSelector::Cargo));
    }

    #[test]
    fn parse_cli_accepts_explicit_executor_host() {
        let cli = parse_cli(["assay", "analyze", "--executor", "host"]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(args.executor, ExecutorChoice::Host);
    }

    #[test]
    fn analyze_rejects_host_executor_for_apply_without_explicit_unsafe_flag() {
        let tmp = tempfile::tempdir().unwrap();
        let err = analyze_command(AnalyzeArgs {
            repo: tmp.path().to_path_buf(),
            ecosystem: None,
            apply_local: true,
            apply_pr: false,
            unsafe_host_validation: false,
            force: true,
            executor: ExecutorChoice::Host,
            format: OutputFormat::Text,
            include_workflows: Vec::new(),
            exclude_workflows: Vec::new(),
            no_workflow_filter: false,
        })
        .expect_err("host validation must be gated");
        assert!(err.to_string().contains("--unsafe-host-validation"));
    }

    #[test]
    fn apply_local_tree_is_retained_under_assay_run_work_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        git(repo, ["init"]);
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        git(repo, ["add", "Cargo.toml"]);
        git(
            repo,
            [
                "-c",
                "user.email=assay@example.invalid",
                "-c",
                "user.name=assay",
                "commit",
                "-m",
                "init",
            ],
        );

        let tree = prepare_apply_local_tree(repo, "assay-test-run", "Cargo Serde/1.0.215").unwrap();

        assert!(tree.starts_with(repo.join(".assay").join("runs")));
        assert_ne!(tree, repo);
        assert!(tree.join("Cargo.toml").is_file());
        assert_eq!(
            tree.file_name().and_then(|n| n.to_str()),
            Some("cargo-serde-1-0-215")
        );
    }

    fn git<const N: usize>(repo: &std::path::Path, args: [&str; N]) {
        let output = std::process::Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git must start");
        assert!(
            output.status.success(),
            "git failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn ecosystem_enabled_with_all_selector_includes_all() {
        let args = AnalyzeArgs {
            repo: ".".into(),
            ecosystem: Some(EcosystemSelector::All),
            apply_local: false,
            apply_pr: false,
            unsafe_host_validation: false,
            force: false,
            executor: ExecutorChoice::Docker,
            format: OutputFormat::Text,
            include_workflows: Vec::new(),
            exclude_workflows: Vec::new(),
            no_workflow_filter: false,
        };
        let cargo = crate::ecosystem::cargo::CargoEcosystem;
        let gha = crate::ecosystem::github_actions::GitHubActionsEcosystem;
        assert!(ecosystem_enabled(&args, &cargo));
        assert!(ecosystem_enabled(&args, &gha));
    }

    #[test]
    fn parse_cli_accepts_repeated_include_workflow_flags() {
        let cli = parse_cli([
            "assay",
            "analyze",
            "--include-workflow",
            "deploy.yml",
            "--include-workflow",
            "release.yml",
        ]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(args.include_workflows, vec!["deploy.yml", "release.yml"]);
    }

    #[test]
    fn parse_cli_accepts_repeated_exclude_workflow_flags() {
        let cli = parse_cli([
            "assay",
            "analyze",
            "--exclude-workflow",
            "smoke-*.yml",
            "--exclude-workflow",
            "lint.yml",
        ]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(args.exclude_workflows, vec!["smoke-*.yml", "lint.yml"]);
    }

    #[test]
    fn parse_cli_accepts_no_workflow_filter_flag() {
        let cli = parse_cli(["assay", "analyze", "--no-workflow-filter"]);
        let Command::Analyze(args) = cli.command;
        assert!(args.no_workflow_filter);
    }

    #[test]
    fn workflow_filter_from_args_defaults_to_pull_request_only() {
        let args = AnalyzeArgs {
            repo: ".".into(),
            ecosystem: None,
            apply_local: false,
            apply_pr: false,
            unsafe_host_validation: false,
            force: false,
            executor: ExecutorChoice::Docker,
            format: OutputFormat::Text,
            include_workflows: Vec::new(),
            exclude_workflows: Vec::new(),
            no_workflow_filter: false,
        };
        let filter = workflow_filter_from_args(&args);
        assert!(filter.require_pull_request_trigger);
        assert!(filter.include_globs.is_empty());
        assert!(filter.exclude_globs.is_empty());
    }

    #[test]
    fn workflow_filter_from_args_disables_trigger_check_when_no_workflow_filter_set() {
        let args = AnalyzeArgs {
            repo: ".".into(),
            ecosystem: None,
            apply_local: false,
            apply_pr: false,
            unsafe_host_validation: false,
            force: false,
            executor: ExecutorChoice::Docker,
            format: OutputFormat::Text,
            include_workflows: Vec::new(),
            exclude_workflows: Vec::new(),
            no_workflow_filter: true,
        };
        let filter = workflow_filter_from_args(&args);
        assert!(!filter.require_pull_request_trigger);
    }

    #[test]
    fn workflow_filter_from_args_passes_through_include_exclude_globs() {
        let args = AnalyzeArgs {
            repo: ".".into(),
            ecosystem: None,
            apply_local: false,
            apply_pr: false,
            unsafe_host_validation: false,
            force: false,
            executor: ExecutorChoice::Docker,
            format: OutputFormat::Text,
            include_workflows: vec!["always.yml".into()],
            exclude_workflows: vec!["never-*.yml".into()],
            no_workflow_filter: false,
        };
        let filter = workflow_filter_from_args(&args);
        assert_eq!(filter.include_globs, vec!["always.yml"]);
        assert_eq!(filter.exclude_globs, vec!["never-*.yml"]);
        assert!(filter.require_pull_request_trigger);
    }

    #[test]
    fn ecosystem_enabled_with_cargo_selector_excludes_gha() {
        let args = AnalyzeArgs {
            repo: ".".into(),
            ecosystem: Some(EcosystemSelector::Cargo),
            apply_local: false,
            apply_pr: false,
            unsafe_host_validation: false,
            force: false,
            executor: ExecutorChoice::Docker,
            format: OutputFormat::Text,
            include_workflows: Vec::new(),
            exclude_workflows: Vec::new(),
            no_workflow_filter: false,
        };
        let cargo = crate::ecosystem::cargo::CargoEcosystem;
        let gha = crate::ecosystem::github_actions::GitHubActionsEcosystem;
        assert!(ecosystem_enabled(&args, &cargo));
        assert!(!ecosystem_enabled(&args, &gha));
    }
}
