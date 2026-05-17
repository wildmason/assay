//! CLI surface for `assay`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::ecosystem::{DependencyEcosystem, EcosystemContext, default_registry};
use crate::error::{Error, Result};
use crate::model::{
    AssayRunReceipt, Classification, Manifest, Proposal, Provenance, ProvenanceRecord,
    RepositoryRef, RunSummary,
};
use crate::publisher::gh_cli::{GhCliBackend, parse_owner_repo_from_origin};
use crate::publisher::{
    PullRequestBackend, PullRequestParams, build_pull_request_request, guards::guard_push_target,
};
use crate::receipt::write_run_receipt;
use crate::sanitize::sanitize_commit_subject;
use crate::validator::{CustomBackend, Validator, ValidatorExecutor};
use crate::worker_pool::{Semaphore, WorkerContext, WorkerPool};
use crate::workflow_filter::WorkflowFilter;

use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

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
#[command(group(
    ArgGroup::new("gate_override")
        .args(["gate_cmd", "gate_file"])
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

    /// Override the auto-selected validator backend with an operator-
    /// supplied shell-line. Whitespace-split argv (no shell features —
    /// for pipes/redirection write a script and use `--gate-file`).
    /// Mutually exclusive with `--gate-file`. When set, `--executor` is
    /// silently ignored (CustomBackend bypasses forge entirely).
    #[arg(long = "gate-cmd", value_name = "SHELL_LINE")]
    pub gate_cmd: Option<String>,

    /// Override the auto-selected validator backend with a script.
    /// The script's shebang controls interpretation. Mutually exclusive
    /// with `--gate-cmd`. When set, `--executor` is silently ignored.
    #[arg(long = "gate-file", value_name = "PATH")]
    pub gate_file: Option<PathBuf>,

    /// Git remote to push to when `--apply-pr` is set. Defaults to `origin`.
    #[arg(long, default_value = "origin")]
    pub remote: String,

    /// Project entry point. Accepts a manifest file (e.g. `Cargo.toml`,
    /// `.github/workflows/ci.yml`) or a directory. With a manifest file,
    /// the file's repo root is inferred and only the matching ecosystem
    /// runs. With a directory, every configured ecosystem runs against it.
    /// Overrides `--repo` and any `--ecosystem` value.
    #[arg(long, value_name = "PATH")]
    pub project: Option<PathBuf>,

    /// Worker threads for the per-proposal apply+validate pipeline.
    /// Defaults to `min(4, available_parallelism())`. Cargo proposals
    /// stay capped at 1 concurrent worker by default (configurable via
    /// `.assay.toml [ecosystems.cargo] max_parallel`).
    #[arg(long, value_name = "N")]
    pub threads: Option<usize>,

    /// Stop dispatching new proposals after the first non-success outcome.
    /// In-flight proposals run to completion. Default is run-all-and-report.
    #[arg(long)]
    pub fail_fast: bool,
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
    let project_scope = ProjectScope::resolve(&args)?;
    let mut args = args;
    // Override --repo / --ecosystem with whatever --project resolved to.
    args.repo = project_scope.repo_root.clone();
    if let Some(eco) = project_scope.ecosystem_restriction {
        args.ecosystem = Some(eco);
    }
    if !args.repo.is_dir() {
        return Err(Error::RepoNotFound(args.repo));
    }
    let mode = ApplyMode::from_args(&args);
    // The host-executor safety check only matters when forge runs the
    // gate; --gate-cmd / --gate-file bypass forge entirely and the
    // operator is opting into running their own commands.
    let gate_override = args.gate_cmd.is_some() || args.gate_file.is_some();
    if matches!(mode, ApplyMode::ApplyLocal | ApplyMode::ApplyPr)
        && args.executor == ExecutorChoice::Host
        && !args.unsafe_host_validation
        && !gate_override
    {
        return Err(Error::other(
            "--executor host requires --unsafe-host-validation for apply modes; \
             dependency validation may execute newly bumped build scripts",
        ));
    }

    // Safety: apply modes refuse on a dirty tree unless --force.
    if matches!(mode, ApplyMode::ApplyLocal | ApplyMode::ApplyPr) && !args.force {
        if let Some(dirty_path) = working_tree_dirty_path(&args.repo)? {
            let mode_label = if matches!(mode, ApplyMode::ApplyLocal) {
                "--apply-local"
            } else {
                "--apply-pr"
            };
            return Err(Error::other(format!(
                "refusing to {mode_label} against a dirty working tree (uncommitted changes at {dirty_path}). \
                 Commit or stash, or pass --force to override."
            )));
        }
    }
    // Apply-pr preflight: $CI must not be set (we don't open PRs inside CI runs
    // unless the operator explicitly overrides via --force).
    if matches!(mode, ApplyMode::ApplyPr) && !args.force && std::env::var("CI").is_ok() {
        return Err(Error::other(
            "refusing to --apply-pr while $CI is set; CI runs should consume assay's report, not open PRs. \
             Pass --force to override.",
        ));
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
    let mut completed_runs: Vec<ProposalRun> = Vec::new();
    let mut pre_validation_failures = 0usize;

    if matches!(mode, ApplyMode::ApplyLocal | ApplyMode::ApplyPr) && !all_proposals.is_empty() {
        let validator =
            build_validator(&args)?.with_workflow_filter(workflow_filter_from_args(&args));

        let units: Vec<WorkUnit> = all_proposals
            .iter()
            .map(|(eco_idx, proposal)| WorkUnit {
                eco_idx: *eco_idx,
                ecosystem_name: registry[*eco_idx].name(),
                proposal: proposal.clone(),
            })
            .collect();

        let pool = WorkerPool {
            threads: args.threads.unwrap_or_else(WorkerPool::default_threads),
            fail_fast: args.fail_fast,
        };
        // Build semaphores from the v1 defaults (cargo cap=1, others
        // unbounded). Reading the EcosystemEntry's max_parallel from
        // .assay.toml is the natural next step but isn't wired yet.
        let semaphores = vec![("cargo", Arc::new(Semaphore::new(1)))];
        let git_mutex = Mutex::new(());
        let ctx = WorkerContext {
            semaphores,
            git_mutex: &git_mutex,
        };

        let validator_ref = &validator;
        let registry_ref = &registry;
        let repo_ref = args.repo.as_path();
        let run_id_ref = run_id.as_str();
        let outcomes = pool.run(
            units,
            ctx,
            |unit, ctx| {
                process_proposal_unit(unit, validator_ref, registry_ref, repo_ref, run_id_ref, ctx)
            },
            |outcome| {
                // `Discovered` is intentionally NOT red — it's a successful
                // surfacing of a non-applyable bump, not a failure.
                matches!(outcome, WorkerOutcome::PreValidationFailure { .. })
                    || matches!(outcome, WorkerOutcome::ValidatorErrored { .. })
                    || matches!(
                        outcome,
                        WorkerOutcome::Completed { outcome, .. } if outcome.conclusion != "success"
                    )
            },
            |unit| unit.ecosystem_name,
        );

        // Drain outcomes back into the existing aggregation shape.
        for outcome in outcomes {
            match outcome {
                WorkerOutcome::PreValidationFailure {
                    eco_idx: _,
                    proposal: _,
                    provenance: pr_records,
                } => {
                    provenance.records.extend(pr_records);
                    proposals_failed += 1;
                    pre_validation_failures += 1;
                }
                WorkerOutcome::ValidatorErrored {
                    eco_idx: _,
                    proposal: _,
                    provenance: pr_records,
                } => {
                    provenance.records.extend(pr_records);
                    proposals_unvalidated += 1;
                }
                WorkerOutcome::Completed {
                    eco_idx,
                    proposal,
                    sandbox,
                    outcome,
                    provenance: pr_records,
                } => {
                    provenance.records.extend(pr_records);
                    match outcome.conclusion.as_str() {
                        "success" => proposals_passed += 1,
                        "unvalidated" => proposals_unvalidated += 1,
                        _ => proposals_failed += 1,
                    }
                    completed_runs.push(ProposalRun {
                        eco_idx,
                        proposal,
                        sandbox,
                        outcome,
                    });
                }
            }
        }
    } else {
        proposals_unvalidated = all_proposals.len();
    }

    let mut commit_summary: Option<CommitSummary> = None;
    let mut pr_summary: Option<ApplyPrSummary> = None;
    if matches!(mode, ApplyMode::ApplyLocal) && !all_proposals.is_empty() {
        commit_summary = Some(perform_apply_local_commit(
            &args.repo,
            &registry,
            &mut completed_runs,
            pre_validation_failures,
            &mut provenance,
        )?);
    }
    if matches!(mode, ApplyMode::ApplyPr) && !all_proposals.is_empty() {
        let backend = GhCliBackend::default();
        pr_summary = Some(perform_apply_pr(
            &args.repo,
            &registry,
            &mut completed_runs,
            pre_validation_failures,
            &mut provenance,
            &backend,
            &args.remote,
            &run_id,
        )?);
    }

    let summary = RunSummary {
        manifests_scanned: total_manifests,
        proposals_total: all_proposals.len(),
        proposals_passed,
        proposals_failed,
        proposals_unvalidated,
        // Reserved for future tier short-circuits; today all three
        // tiers flow through apply+validate.
        proposals_discovered: 0,
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
        // Per-tier breakdown surfaces the helm-style "110 deps behind
        // latest but constraint-pinned" gap that plain `cargo update`
        // hides. Walks all_proposals directly — the source of truth.
        let (lockfile_only, compatible, breaking) =
            tier_counts(all_proposals.iter().map(|(_, p)| p));
        println!(
            "assay: scanned {} manifest(s) across {} ecosystem(s); {} proposal(s) (mode={:?})",
            total_manifests,
            registry.len(),
            all_proposals.len(),
            mode,
        );
        println!(
            "assay: tier breakdown: {} lockfile-only / {} compatible / {} breaking",
            lockfile_only, compatible, breaking,
        );
        if (compatible + breaking) > 0 {
            print_discovered_section(all_proposals.iter().map(|(_, p)| p));
        }
        if matches!(mode, ApplyMode::ApplyLocal) {
            println!(
                "assay: validated {} green / {} red / {} unvalidated",
                proposals_passed, proposals_failed, proposals_unvalidated,
            );
            match &commit_summary {
                Some(CommitSummary::Committed {
                    bump_count,
                    paths,
                    subject,
                }) => {
                    println!(
                        "assay: committed {} bump(s) to current branch as `{}` ({} path(s) updated: {})",
                        bump_count,
                        subject,
                        paths.len(),
                        paths
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                }
                Some(CommitSummary::SkippedDueToFailures { red_count, total }) => {
                    println!(
                        "assay: refused to commit (--apply-local requires all-green); {} of {} proposal(s) failed validation",
                        red_count, total,
                    );
                }
                Some(CommitSummary::NothingToCommit) => {
                    println!("assay: nothing to commit (no green proposals)");
                }
                None => {}
            }
            if !all_proposals.is_empty() {
                println!(
                    "assay: sandbox worktrees retained for audit under {}",
                    args.repo
                        .join(".assay")
                        .join("runs")
                        .join(&run_id)
                        .join("work")
                        .display()
                );
            }
        }
        if matches!(mode, ApplyMode::ApplyPr) {
            println!(
                "assay: validated {} green / {} red / {} unvalidated",
                proposals_passed, proposals_failed, proposals_unvalidated,
            );
            match &pr_summary {
                Some(ApplyPrSummary::Published {
                    url,
                    branch,
                    bump_count,
                }) => {
                    println!(
                        "assay: opened PR for {bump_count} bump(s) on branch `{branch}`: {url}"
                    );
                }
                Some(ApplyPrSummary::SkippedDueToFailures { red_count, total }) => {
                    println!(
                        "assay: refused to open PR (--apply-pr requires all-green); {} of {} proposal(s) failed validation",
                        red_count, total,
                    );
                }
                Some(ApplyPrSummary::NothingToPublish) => {
                    println!("assay: nothing to publish (no green proposals)");
                }
                None => {}
            }
        }
        println!("assay: receipt written to {}", run_json_path.display());
    }
    Ok(())
}

/// One unit dispatched to the worker pool — a single (ecosystem, proposal)
/// pair. Workers pull these and run apply + validate sequentially.
struct WorkUnit {
    eco_idx: usize,
    /// Cached for the worker pool's per-ecosystem semaphore lookup.
    ecosystem_name: &'static str,
    proposal: Proposal,
}

/// What a worker thread produces for one [`WorkUnit`].
///
/// `eco_idx` and `proposal` are carried on the failure variants for
/// future error-reporting that wants to address the failed proposal by
/// id. The current aggregator only reads them via the structural match
/// in `analyze_command`, so allow the dead-code lint here.
#[allow(dead_code)]
#[derive(Debug)]
enum WorkerOutcome {
    /// Apply tree preparation or `apply_proposal` failed before validation
    /// could run.
    PreValidationFailure {
        eco_idx: usize,
        proposal: Proposal,
        provenance: Vec<ProvenanceRecord>,
    },
    /// Validator couldn't run at all (e.g. forge not on PATH AND no
    /// recognized manifest).
    ValidatorErrored {
        eco_idx: usize,
        proposal: Proposal,
        provenance: Vec<ProvenanceRecord>,
    },
    /// Pipeline completed with a real validation outcome.
    Completed {
        eco_idx: usize,
        proposal: Proposal,
        sandbox: PathBuf,
        outcome: crate::model::ValidationOutcome,
        provenance: Vec<ProvenanceRecord>,
    },
}

/// Returns `(lockfile_only, compatible, breaking)` counts from a stream of
/// proposals. Used by the text reporter to surface the tier breakdown
/// without re-walking the worker pool outcomes.
fn tier_counts<'a>(proposals: impl IntoIterator<Item = &'a Proposal>) -> (usize, usize, usize) {
    use crate::model::BumpTier;
    let mut lockfile_only = 0usize;
    let mut compatible = 0usize;
    let mut breaking = 0usize;
    for proposal in proposals {
        match proposal.bump_tier {
            BumpTier::LockfileOnly => lockfile_only += 1,
            BumpTier::Compatible => compatible += 1,
            BumpTier::Breaking => breaking += 1,
        }
    }
    (lockfile_only, compatible, breaking)
}

/// Prints the per-tier discovered-bump table to stdout.
///
/// Format:
///
/// ```text
/// assay: discovered upgrades (not auto-applied — manifest constraint edit required):
///   compatible:
///     cargo_metadata  0.18.1 -> 0.20.0
///   breaking:
///     serde  1.0.215 -> 2.0.0
/// ```
fn print_discovered_section<'a>(proposals: impl IntoIterator<Item = &'a Proposal>) {
    use crate::model::BumpTier;
    let mut compatible: Vec<&Proposal> = Vec::new();
    let mut breaking: Vec<&Proposal> = Vec::new();
    for p in proposals {
        match p.bump_tier {
            BumpTier::Compatible => compatible.push(p),
            BumpTier::Breaking => breaking.push(p),
            BumpTier::LockfileOnly => {}
        }
    }
    if compatible.is_empty() && breaking.is_empty() {
        return;
    }
    println!("assay: discovered upgrades (not auto-applied — manifest constraint edit required):");
    let print_group = |label: &str, mut group: Vec<&Proposal>| {
        if group.is_empty() {
            return;
        }
        group.sort_by(|a, b| a.subject.cmp(&b.subject));
        println!("  {label}:");
        for p in group {
            let mut line = format!("    {}  {} -> {}", p.subject, p.from, p.to);
            if !p.notes.is_empty() {
                line.push_str(&format!("  [{}]", p.notes.join(", ")));
            }
            println!("{line}");
        }
    };
    print_group("compatible", compatible);
    print_group("breaking", breaking);
}

/// Worker body: prepare sandbox → apply proposal → gate workflows → validate.
///
/// All provenance records produced during this unit live on the
/// returned `WorkerOutcome` so the main thread can drain them into the
/// shared `Provenance` without contention.
///
/// All three [`crate::model::BumpTier`] cases flow through this body:
/// LockfileOnly relies on `cargo update --workspace`; Compatible /
/// Breaking widen the constraint in Cargo.toml(s) first and then run
/// the same lockfile-bump step. The validator sees whichever shape
/// the bump produced and reports pass/fail against real CI.
fn process_proposal_unit(
    unit: WorkUnit,
    validator: &Validator,
    registry: &[Box<dyn DependencyEcosystem>],
    repo: &Path,
    run_id: &str,
    ctx: &WorkerContext<'_>,
) -> WorkerOutcome {
    let mut records: Vec<ProvenanceRecord> = Vec::new();
    let ecosystem = registry[unit.eco_idx].as_ref();

    // Conc-2: `git worktree add` is serialized across workers to avoid
    // .git/index.lock races.
    let apply_tree = {
        let _git_guard = ctx.git_mutex.lock().unwrap();
        prepare_apply_local_tree(repo, run_id, &unit.proposal.id)
    };
    let apply_tree = match apply_tree {
        Ok(path) => path,
        Err(err) => {
            records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("applier.{}", ecosystem.name()),
                subject: unit.proposal.id.clone(),
                status: Classification::Unsupported,
                summary: format!("apply tree preparation failed: {err}"),
                artifact_path: None,
                details: None,
            });
            return WorkerOutcome::PreValidationFailure {
                eco_idx: unit.eco_idx,
                proposal: unit.proposal,
                provenance: records,
            };
        }
    };

    if let Err(err) = ecosystem.apply_proposal(&unit.proposal, &apply_tree) {
        records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: format!("applier.{}", ecosystem.name()),
            subject: unit.proposal.id.clone(),
            status: Classification::Unsupported,
            summary: format!("apply failed: {err}"),
            artifact_path: None,
            details: None,
        });
        return WorkerOutcome::PreValidationFailure {
            eco_idx: unit.eco_idx,
            proposal: unit.proposal,
            provenance: records,
        };
    }
    records.push(ProvenanceRecord {
        tool: "assay".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        stage: format!("applier.{}", ecosystem.name()),
        subject: unit.proposal.id.clone(),
        status: Classification::Exact,
        summary: "applied to sandbox worktree".into(),
        artifact_path: None,
        details: Some(serde_json::json!({ "sandbox": apply_tree })),
    });

    let workflow_paths = ecosystem
        .gate_workflows(&unit.proposal, &apply_tree)
        .unwrap_or_default();
    let outcome = match validator.validate(&unit.proposal, &apply_tree, &workflow_paths) {
        Ok(outcome) => outcome,
        Err(err) => {
            records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("validator.{}", ecosystem.name()),
                subject: unit.proposal.id.clone(),
                status: Classification::Stubbed,
                summary: format!("validator could not run: {err}"),
                artifact_path: None,
                details: None,
            });
            return WorkerOutcome::ValidatorErrored {
                eco_idx: unit.eco_idx,
                proposal: unit.proposal,
                provenance: records,
            };
        }
    };
    records.push(ProvenanceRecord {
        tool: "assay".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        stage: format!("validator.{}", ecosystem.name()),
        subject: unit.proposal.id.clone(),
        status: outcome.classification,
        summary: format!(
            "validation {} ({} run(s))",
            outcome.conclusion,
            outcome.ci_forge_run_ids.len()
        ),
        artifact_path: None,
        details: serde_json::to_value(&outcome).ok(),
    });
    WorkerOutcome::Completed {
        eco_idx: unit.eco_idx,
        proposal: unit.proposal,
        sandbox: apply_tree,
        outcome,
        provenance: records,
    }
}

/// One proposal's full lifecycle through the apply-local pipeline:
/// applier produced a sandbox tree, validator scored it. Held in memory
/// until the post-loop commit phase decides whether to copy-back.
struct ProposalRun {
    eco_idx: usize,
    proposal: Proposal,
    sandbox: PathBuf,
    outcome: crate::model::ValidationOutcome,
}

/// What happened during the post-validation `--apply-local` commit phase.
#[derive(Debug)]
enum CommitSummary {
    /// All proposals validated green and the commit was created.
    Committed {
        bump_count: usize,
        paths: Vec<PathBuf>,
        subject: String,
    },
    /// One or more proposals didn't validate green; refusing to commit
    /// preserves the "atomic, all-green" semantic of `--apply-local`.
    SkippedDueToFailures { red_count: usize, total: usize },
    /// No proposals reached validation cleanly — nothing to commit.
    NothingToCommit,
}

/// Run the post-validation commit phase for `--apply-local`.
///
/// Per plan §C.6.a: validate all proposals first, then if every proposal
/// validated green, sort by proposal ID (Conc-9), copy-back each from
/// its sandbox to the host tree, and create one atomic commit. If any
/// proposal didn't validate green (failure, unvalidated, or pre-apply
/// failure), refuse to commit — the user can re-run after fixing the
/// failing proposals.
fn perform_apply_local_commit(
    repo: &Path,
    registry: &[Box<dyn DependencyEcosystem>],
    completed_runs: &mut [ProposalRun],
    pre_validation_failures: usize,
    provenance: &mut Provenance,
) -> Result<CommitSummary> {
    let red_count = pre_validation_failures
        + completed_runs
            .iter()
            .filter(|r| r.outcome.conclusion != "success")
            .count();
    let total = completed_runs.len() + pre_validation_failures;
    if total == 0 {
        return Ok(CommitSummary::NothingToCommit);
    }
    if red_count > 0 {
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_local".into(),
            subject: "<aggregate>".into(),
            status: Classification::Unsupported,
            summary: format!(
                "refused to commit: {} of {} proposal(s) didn't validate green",
                red_count, total
            ),
            artifact_path: None,
            details: None,
        });
        return Ok(CommitSummary::SkippedDueToFailures { red_count, total });
    }

    // All-green: sort by proposal ID for byte-deterministic commits
    // (Conc-9), then copy each sandbox's validated change-set back to
    // the host tree.
    completed_runs.sort_by(|a, b| a.proposal.id.cmp(&b.proposal.id));

    let mut modified_paths: Vec<PathBuf> = Vec::new();
    let mut body_lines: Vec<String> = Vec::new();
    for run in completed_runs.iter() {
        let ecosystem = registry[run.eco_idx].as_ref();
        let modified = ecosystem
            .copy_back(&run.proposal, &run.sandbox, repo)
            .map_err(|err| {
                Error::other(format!(
                    "copy-back failed for proposal `{}`: {err}",
                    run.proposal.id
                ))
            })?;
        for path in &modified {
            if !modified_paths.contains(path) {
                modified_paths.push(path.clone());
            }
        }
        body_lines.push(format!(
            "- {} {} -> {} ({})",
            run.proposal.subject,
            run.proposal.from,
            run.proposal.to,
            run.outcome.classification.as_str()
        ));
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_local".into(),
            subject: run.proposal.id.clone(),
            status: Classification::Exact,
            summary: format!("copied back {} path(s)", modified.len()),
            artifact_path: None,
            details: Some(serde_json::json!({
                "modified": modified.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            })),
        });
    }

    if modified_paths.is_empty() {
        return Ok(CommitSummary::NothingToCommit);
    }

    let raw_subject = if completed_runs.len() == 1 {
        let p = &completed_runs[0].proposal;
        format!(
            "chore(deps): bump {} from {} to {}",
            p.subject, p.from, p.to
        )
    } else {
        format!("chore(deps): bump {} dependencies", completed_runs.len())
    };
    let subject = sanitize_commit_subject(&raw_subject)
        .map_err(|err| {
            Error::other(format!(
                "internal: generated commit subject failed sanitization: {err}"
            ))
        })?
        .to_string();
    let body = body_lines.join("\n");

    git_add_paths(repo, &modified_paths)?;
    git_commit(repo, &subject, &body)?;

    provenance.records.push(ProvenanceRecord {
        tool: "assay".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        stage: "publisher.apply_local".into(),
        subject: "<commit>".into(),
        status: Classification::Exact,
        summary: subject.clone(),
        artifact_path: None,
        details: Some(serde_json::json!({
            "bump_count": completed_runs.len(),
            "modified_paths": modified_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        })),
    });

    Ok(CommitSummary::Committed {
        bump_count: completed_runs.len(),
        paths: modified_paths,
        subject,
    })
}

/// Outcome of `--apply-pr` orchestration.
#[derive(Debug)]
enum ApplyPrSummary {
    Published {
        url: String,
        branch: String,
        bump_count: usize,
    },
    SkippedDueToFailures {
        red_count: usize,
        total: usize,
    },
    NothingToPublish,
}

/// Compute a deterministic branch name covering every green proposal.
///
/// Single-bump → `branch_name_for_bump(eco, subject, from, to)`.
/// Multi-bump → `assay/multi/<N>-<short-hash-of-all-ids>` so the name
/// remains injective on the set of proposals AND stable across re-runs.
fn compute_branch_name_for_runs(runs: &[ProposalRun]) -> String {
    if runs.len() == 1 {
        let p = &runs[0].proposal;
        return crate::publisher::branch_name::branch_name_for_bump(
            &p.ecosystem,
            &p.subject,
            &p.from,
            &p.to,
        );
    }
    let mut hasher = Sha256::new();
    hasher.update(b"assay:multi:v1:");
    for run in runs {
        hasher.update(run.proposal.id.as_bytes());
        hasher.update(b"|");
    }
    let digest = hasher.finalize();
    let hex_short: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    format!("assay/multi/{}-{hex_short}", runs.len())
}

/// Run the post-validation `--apply-pr` flow:
/// branch → worktree → copy_back → commit → push → open PR.
#[allow(clippy::too_many_arguments)]
fn perform_apply_pr(
    repo: &Path,
    registry: &[Box<dyn DependencyEcosystem>],
    completed_runs: &mut [ProposalRun],
    pre_validation_failures: usize,
    provenance: &mut Provenance,
    backend: &dyn PullRequestBackend,
    remote: &str,
    run_id: &str,
) -> Result<ApplyPrSummary> {
    let red_count = pre_validation_failures
        + completed_runs
            .iter()
            .filter(|r| r.outcome.conclusion != "success")
            .count();
    let total = completed_runs.len() + pre_validation_failures;
    if total == 0 {
        return Ok(ApplyPrSummary::NothingToPublish);
    }
    if red_count > 0 {
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_pr".into(),
            subject: "<aggregate>".into(),
            status: Classification::Unsupported,
            summary: format!(
                "refused to open PR: {} of {} proposal(s) didn't validate green",
                red_count, total
            ),
            artifact_path: None,
            details: None,
        });
        return Ok(ApplyPrSummary::SkippedDueToFailures { red_count, total });
    }

    completed_runs.sort_by(|a, b| a.proposal.id.cmp(&b.proposal.id));

    let (owner, repo_name) = parse_owner_repo_from_origin(repo, remote)
        .map_err(|err| Error::other(format!("couldn't determine owner/repo: {err}")))?;
    let branch = compute_branch_name_for_runs(completed_runs);
    crate::publisher::git_push::validate_branch_name(&branch).map_err(|err| {
        Error::other(format!(
            "internal: generated branch name `{branch}` fails validation: {err}"
        ))
    })?;
    crate::publisher::git_push::validate_remote_name(remote).map_err(|err| {
        Error::other(format!(
            "--remote `{remote}` fails charset validation: {err}"
        ))
    })?;

    // Create a fresh worktree on a new branch from HEAD. The worktree
    // is where copy-back + commit happen; the host main checkout is
    // never mutated by --apply-pr.
    let worktree = repo
        .join(".assay")
        .join("runs")
        .join(run_id)
        .join("pr-tree");
    if let Some(parent) = worktree.parent() {
        std::fs::create_dir_all(parent).map_err(|source| Error::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let output = std::process::Command::new("git")
        .args(["worktree", "add", "-b"])
        .arg(&branch)
        .arg(&worktree)
        .arg("HEAD")
        .current_dir(repo)
        .output()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git worktree add (branch `{branch}`) failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    // Copy back into the worktree.
    let mut modified_paths: Vec<PathBuf> = Vec::new();
    let mut body_lines: Vec<String> = Vec::new();
    for run in completed_runs.iter() {
        let ecosystem = registry[run.eco_idx].as_ref();
        let modified = ecosystem
            .copy_back(&run.proposal, &run.sandbox, &worktree)
            .map_err(|err| {
                Error::other(format!(
                    "copy-back failed for proposal `{}`: {err}",
                    run.proposal.id
                ))
            })?;
        for path in &modified {
            if !modified_paths.contains(path) {
                modified_paths.push(path.clone());
            }
        }
        body_lines.push(format!(
            "- {} {} -> {} ({})",
            run.proposal.subject,
            run.proposal.from,
            run.proposal.to,
            run.outcome.classification.as_str()
        ));
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_pr".into(),
            subject: run.proposal.id.clone(),
            status: Classification::Exact,
            summary: format!("copied back {} path(s)", modified.len()),
            artifact_path: None,
            details: None,
        });
    }

    if modified_paths.is_empty() {
        return Ok(ApplyPrSummary::NothingToPublish);
    }

    let raw_subject = if completed_runs.len() == 1 {
        let p = &completed_runs[0].proposal;
        format!(
            "chore(deps): bump {} from {} to {}",
            p.subject, p.from, p.to
        )
    } else {
        format!("chore(deps): bump {} dependencies", completed_runs.len())
    };
    let subject = sanitize_commit_subject(&raw_subject)
        .map_err(|err| {
            Error::other(format!(
                "internal: generated commit subject failed sanitization: {err}"
            ))
        })?
        .to_string();
    let body = body_lines.join("\n");
    git_add_paths(&worktree, &modified_paths)?;
    git_commit(&worktree, &subject, &body)?;

    // Push the branch.
    crate::publisher::git_push::push_branch(&worktree, remote, &branch)
        .map_err(|err| Error::other(format!("git push failed: {err}")))?;

    // After push, fetch branch metadata and run the three-guard check.
    // Defense in depth: branch namespace is validated upstream, but the
    // default/protected-branch check needs server-side state.
    let metadata = backend.fetch_branch_metadata(&owner, &repo_name, &branch)?;
    guard_push_target(&branch, &metadata).map_err(|err| {
        Error::other(format!(
            "post-push guard rejected branch `{branch}`: {err} \
             (the branch was pushed but the PR was NOT opened; you may want to delete the remote branch)"
        ))
    })?;

    // Open the PR. Title overrides build_pull_request_request's default
    // "Bump <subject>" shape so the multi-bump case reads cleanly.
    let title = if completed_runs.len() == 1 {
        format!(
            "Bump {} from {} to {}",
            completed_runs[0].proposal.subject,
            completed_runs[0].proposal.from,
            completed_runs[0].proposal.to,
        )
    } else {
        format!("Bump {} dependencies via assay", completed_runs.len())
    };
    let base = detect_default_branch(repo, remote).unwrap_or_else(|| "main".into());
    let mut request = build_pull_request_request(PullRequestParams {
        owner: &owner,
        repo: &repo_name,
        branch: &branch,
        base: &base,
        subject: &title,
        body: body.clone(),
        labels: vec!["assay".into()],
        reviewers: vec![],
        draft: false,
    });
    request.title = title;
    let response = backend.open_pull_request(&request).map_err(|err| {
        Error::other(format!(
            "the branch was pushed but `gh pr create` failed: {err}. \
             You can open the PR manually from {}.",
            request.branch,
        ))
    })?;

    provenance.records.push(ProvenanceRecord {
        tool: "assay".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        stage: "publisher.apply_pr".into(),
        subject: "<pr>".into(),
        status: Classification::Exact,
        summary: response.url.clone(),
        artifact_path: None,
        details: Some(serde_json::json!({
            "branch": branch,
            "url": response.url,
            "number": response.number,
        })),
    });

    Ok(ApplyPrSummary::Published {
        url: response.url,
        branch,
        bump_count: completed_runs.len(),
    })
}

/// Detect the repository's default branch using `git remote show <remote>`.
/// Falls back to None if anything goes wrong; callers default to "main".
fn detect_default_branch(repo: &Path, remote: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["remote", "show", remote])
        .current_dir(repo)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("HEAD branch: ") {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Stage exactly the listed paths via `git add`. Refuses paths that
/// resolve outside the repo to defend against `..` traversal.
fn git_add_paths(repo: &Path, paths: &[PathBuf]) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }
    let mut cmd = std::process::Command::new("git");
    cmd.arg("add").arg("--").current_dir(repo);
    for path in paths {
        cmd.arg(path);
    }
    let output = cmd.output().map_err(|source| Error::Io {
        path: repo.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

/// Create a single commit on the current branch with the given subject
/// and body. Refuses to amend; if there's nothing staged, returns an
/// error rather than silently no-opping.
fn git_commit(repo: &Path, subject: &str, body: &str) -> Result<()> {
    let mut cmd = std::process::Command::new("git");
    cmd.arg("commit").current_dir(repo);
    cmd.arg("-m").arg(subject);
    if !body.is_empty() {
        cmd.arg("-m").arg(body);
    }
    let output = cmd.output().map_err(|source| Error::Io {
        path: repo.to_path_buf(),
        source,
    })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git commit failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
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

/// Resolved scope for `--project`. When set, narrows the repo root
/// AND restricts the run to a single ecosystem (inferred from the
/// manifest filename).
#[derive(Debug, Clone)]
struct ProjectScope {
    repo_root: PathBuf,
    ecosystem_restriction: Option<EcosystemSelector>,
}

impl ProjectScope {
    fn resolve(args: &AnalyzeArgs) -> Result<Self> {
        let Some(path) = args.project.as_deref() else {
            return Ok(ProjectScope {
                repo_root: args.repo.clone(),
                ecosystem_restriction: None,
            });
        };
        if !path.exists() {
            return Err(Error::other(format!(
                "--project path `{}` does not exist",
                path.display()
            )));
        }
        if path.is_dir() {
            return Ok(ProjectScope {
                repo_root: path.to_path_buf(),
                ecosystem_restriction: None,
            });
        }
        // path is a file — infer ecosystem and repo root.
        let (eco, repo_root) = infer_project_scope_from_manifest(path).ok_or_else(|| {
            Error::other(format!(
                "--project file `{}` is not a recognized manifest. \
                 Supported: Cargo.toml (cargo), .github/workflows/*.yml (github-actions).",
                path.display()
            ))
        })?;
        Ok(ProjectScope {
            repo_root,
            ecosystem_restriction: Some(eco),
        })
    }
}

/// Infer (ecosystem, repo_root) from a manifest file path.
///
/// Recognized manifests:
/// - `<root>/Cargo.toml` → cargo, root = parent
/// - `<root>/.github/workflows/<name>.yml` → github-actions, root = `<root>`
/// - `<root>/.github/actions/<name>/action.yml` → github-actions, root = `<root>`
fn infer_project_scope_from_manifest(path: &Path) -> Option<(EcosystemSelector, PathBuf)> {
    let filename = path.file_name()?.to_str()?;
    if filename.eq_ignore_ascii_case("Cargo.toml") {
        let parent = path.parent()?.to_path_buf();
        return Some((EcosystemSelector::Cargo, parent));
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if matches!(ext.as_str(), "yml" | "yaml") {
        // Walk parents to find `.github` then take its parent as repo root.
        let mut cursor = path.parent();
        while let Some(dir) = cursor {
            if dir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.eq_ignore_ascii_case(".github"))
            {
                return Some((
                    EcosystemSelector::GithubActions,
                    dir.parent()?.to_path_buf(),
                ));
            }
            cursor = dir.parent();
        }
    }
    None
}

/// Construct the [`Validator`] for this run.
///
/// `--gate-cmd` / `--gate-file` short-circuit auto-selection by wrapping
/// the operator-supplied command in a [`CustomBackend`]; otherwise we
/// defer to [`Validator::auto`] to pick `forge-run` (when `forge` and
/// `.github/workflows/` are both present) or `build-test` (manifest-
/// inferred fallback).
fn build_validator(args: &AnalyzeArgs) -> Result<Validator> {
    if let Some(cmd) = args.gate_cmd.as_deref() {
        return Ok(Validator::with_backend(Box::new(
            CustomBackend::from_gate_cmd(cmd),
        )));
    }
    if let Some(file) = args.gate_file.as_deref() {
        return Ok(Validator::with_backend(Box::new(
            CustomBackend::from_gate_file(file),
        )));
    }
    let validator_executor = match args.executor {
        ExecutorChoice::Host => ValidatorExecutor::Host,
        ExecutorChoice::Docker => ValidatorExecutor::Docker,
    };
    Validator::auto(&args.repo, validator_executor)
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
            gate_cmd: None,
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
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
            gate_cmd: None,
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
        };
        let cargo = crate::ecosystem::cargo::CargoEcosystem;
        let gha = crate::ecosystem::github_actions::GitHubActionsEcosystem;
        assert!(ecosystem_enabled(&args, &cargo));
        assert!(ecosystem_enabled(&args, &gha));
    }

    // -------------------------------------------------------------------------
    // --project flag + ProjectScope::resolve
    // -------------------------------------------------------------------------

    #[test]
    fn parse_cli_accepts_threads_flag() {
        let cli = parse_cli(["assay", "analyze", "--threads", "8"]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(args.threads, Some(8));
    }

    #[test]
    fn parse_cli_defaults_threads_to_none() {
        let cli = parse_cli(["assay", "analyze"]);
        let Command::Analyze(args) = cli.command;
        assert!(
            args.threads.is_none(),
            "default --threads should be None so the pool picks the sensible default"
        );
    }

    #[test]
    fn parse_cli_accepts_fail_fast_flag() {
        let cli = parse_cli(["assay", "analyze", "--fail-fast"]);
        let Command::Analyze(args) = cli.command;
        assert!(args.fail_fast);
    }

    #[test]
    fn parse_cli_defaults_fail_fast_off() {
        let cli = parse_cli(["assay", "analyze"]);
        let Command::Analyze(args) = cli.command;
        assert!(!args.fail_fast);
    }

    #[test]
    fn parse_cli_accepts_project_flag() {
        let cli = parse_cli(["assay", "analyze", "--project", "path/to/Cargo.toml"]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(
            args.project.as_deref(),
            Some(std::path::Path::new("path/to/Cargo.toml"))
        );
    }

    #[test]
    fn project_scope_resolves_directory_as_repo_root_without_restriction() {
        let tmp = tempfile::tempdir().unwrap();
        let args = AnalyzeArgs {
            repo: ".".into(),
            project: Some(tmp.path().to_path_buf()),
            ..default_test_args()
        };
        let scope = ProjectScope::resolve(&args).expect("directory project resolves");
        assert_eq!(scope.repo_root, tmp.path());
        assert!(scope.ecosystem_restriction.is_none());
    }

    #[test]
    fn project_scope_resolves_cargo_toml_to_cargo_ecosystem() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        std::fs::write(&manifest, "[workspace]\n").unwrap();
        let args = AnalyzeArgs {
            repo: ".".into(),
            project: Some(manifest.clone()),
            ..default_test_args()
        };
        let scope = ProjectScope::resolve(&args).expect("Cargo.toml resolves");
        assert_eq!(scope.repo_root, tmp.path());
        assert_eq!(scope.ecosystem_restriction, Some(EcosystemSelector::Cargo));
    }

    #[test]
    fn project_scope_resolves_workflow_yaml_to_github_actions() {
        let tmp = tempfile::tempdir().unwrap();
        let workflows = tmp.path().join(".github").join("workflows");
        std::fs::create_dir_all(&workflows).unwrap();
        let workflow = workflows.join("ci.yml");
        std::fs::write(&workflow, "name: ci\n").unwrap();
        let args = AnalyzeArgs {
            repo: ".".into(),
            project: Some(workflow),
            ..default_test_args()
        };
        let scope = ProjectScope::resolve(&args).expect("workflow yaml resolves");
        assert_eq!(scope.repo_root, tmp.path());
        assert_eq!(
            scope.ecosystem_restriction,
            Some(EcosystemSelector::GithubActions)
        );
    }

    #[test]
    fn project_scope_resolves_composite_action_to_github_actions() {
        let tmp = tempfile::tempdir().unwrap();
        let action_dir = tmp.path().join(".github").join("actions").join("my-action");
        std::fs::create_dir_all(&action_dir).unwrap();
        let action_file = action_dir.join("action.yml");
        std::fs::write(
            &action_file,
            "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n",
        )
        .unwrap();
        let args = AnalyzeArgs {
            repo: ".".into(),
            project: Some(action_file),
            ..default_test_args()
        };
        let scope = ProjectScope::resolve(&args).expect("composite action resolves");
        assert_eq!(scope.repo_root, tmp.path());
        assert_eq!(
            scope.ecosystem_restriction,
            Some(EcosystemSelector::GithubActions)
        );
    }

    #[test]
    fn project_scope_errors_on_unrecognized_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let weird = tmp.path().join("Makefile");
        std::fs::write(&weird, "all:\n\techo hi\n").unwrap();
        let args = AnalyzeArgs {
            repo: ".".into(),
            project: Some(weird),
            ..default_test_args()
        };
        let err = ProjectScope::resolve(&args).expect_err("unrecognized manifest must fail");
        assert!(
            err.to_string().contains("not a recognized manifest"),
            "error should explain: {err}"
        );
    }

    #[test]
    fn project_scope_errors_when_path_does_not_exist() {
        let args = AnalyzeArgs {
            repo: ".".into(),
            project: Some(std::path::PathBuf::from(
                "/nonexistent/path/zzz/assay/Cargo.toml",
            )),
            ..default_test_args()
        };
        let err = ProjectScope::resolve(&args).expect_err("missing path must fail");
        assert!(err.to_string().contains("does not exist"));
    }

    /// Default AnalyzeArgs for tests that only care about a few fields.
    fn default_test_args() -> AnalyzeArgs {
        AnalyzeArgs {
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
            gate_cmd: None,
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
        }
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
    fn parse_cli_accepts_gate_cmd_flag() {
        let cli = parse_cli(["assay", "analyze", "--gate-cmd", "make test"]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(args.gate_cmd.as_deref(), Some("make test"));
        assert!(args.gate_file.is_none());
    }

    #[test]
    fn parse_cli_accepts_gate_file_flag() {
        let cli = parse_cli(["assay", "analyze", "--gate-file", "./scripts/check.sh"]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(
            args.gate_file.as_deref(),
            Some(std::path::Path::new("./scripts/check.sh"))
        );
        assert!(args.gate_cmd.is_none());
    }

    #[test]
    fn parse_cli_rejects_gate_cmd_and_gate_file_together() {
        let parsed = Cli::try_parse_from([
            "assay",
            "analyze",
            "--gate-cmd",
            "make test",
            "--gate-file",
            "./check.sh",
        ]);
        assert!(
            parsed.is_err(),
            "--gate-cmd and --gate-file must be mutually exclusive"
        );
    }

    #[test]
    fn build_validator_uses_custom_backend_for_gate_cmd() {
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
            gate_cmd: Some("make test".into()),
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
        };
        let validator = build_validator(&args).expect("gate-cmd should always build");
        // The Validator field isn't pub, but `validate` against an empty
        // tree and no workflows surfaces a deterministic outcome we can
        // assert on — the *unvalidated* path doesn't run the backend, so
        // the assertion focuses on the construction succeeding.
        let tmp = tempfile::tempdir().unwrap();
        let outcome = validator
            .validate(
                &crate::model::Proposal {
                    id: "p".into(),
                    ecosystem: "cargo".into(),
                    kind: crate::model::ProposalKind::Version,
                    subject: "x".into(),
                    from: "1".into(),
                    to: "2".into(),
                    initial_classification: crate::model::Classification::Exact,
                    manifest_paths: vec![],
                    notes: vec![],
                    bump_tier: crate::model::BumpTier::LockfileOnly,
                },
                tmp.path(),
                &[],
            )
            .unwrap();
        assert_eq!(outcome.conclusion, "unvalidated");
    }

    #[test]
    fn build_validator_uses_custom_backend_for_gate_file() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("check.sh");
        std::fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
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
            gate_cmd: None,
            gate_file: Some(script),
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
        };
        // Just needs to not error during construction.
        build_validator(&args).expect("gate-file should always build");
    }

    #[test]
    fn build_validator_errors_for_empty_dir_when_no_gate_override() {
        // Empty tempdir: no Cargo.toml, no .github/workflows/, and no
        // gate override — Validator::auto should fail with the canonical
        // "no validator backend applicable" error.
        let tmp = tempfile::tempdir().unwrap();
        let args = AnalyzeArgs {
            repo: tmp.path().to_path_buf(),
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
            gate_cmd: None,
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
        };
        // forge may or may not be on PATH; what matters is that the
        // empty dir gives no manifest and no workflows. On a dev box
        // where forge is missing the auto-selector errors immediately;
        // when forge IS on PATH the auto-selector falls to the
        // BuildTestBackend::infer step which also returns None.
        // If for some reason a backend was selectable on this host
        // (unlikely in an empty tempdir), that's fine — the test
        // proves construction works either way.
        if let Err(err) = build_validator(&args) {
            let msg = err.to_string();
            assert!(
                msg.contains("no validator backend applicable"),
                "error should explain why no backend was selectable: {msg}"
            );
        }
    }

    #[test]
    fn host_executor_safety_gate_is_waived_when_gate_override_present() {
        // --executor host normally requires --unsafe-host-validation for
        // apply modes; with --gate-cmd, forge isn't involved at all so
        // the gate should not apply.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let result = analyze_command(AnalyzeArgs {
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
            gate_cmd: Some("true".into()),
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
        });
        // We don't care whether the rest of the pipeline succeeds in
        // this empty tempdir; the assertion is that we are *not*
        // rejected by the host-executor safety check.
        if let Err(err) = result {
            assert!(
                !err.to_string().contains("--unsafe-host-validation"),
                "gate override should waive the host-executor safety gate: {err}"
            );
        }
    }

    // -------------------------------------------------------------------------
    // perform_apply_local_commit — end-to-end apply-local
    // -------------------------------------------------------------------------

    fn init_git_repo(repo: &std::path::Path) {
        git(repo, ["init", "-q"]);
        git(repo, ["config", "user.email", "assay@example.invalid"]);
        git(repo, ["config", "user.name", "assay-test"]);
        git(repo, ["config", "commit.gpgsign", "false"]);
    }

    fn sample_cargo_proposal_for_apply() -> crate::model::Proposal {
        crate::model::Proposal {
            id: "cargo-serde-1-0-215".into(),
            ecosystem: "cargo".into(),
            kind: crate::model::ProposalKind::Version,
            subject: "serde".into(),
            from: "1.0.200".into(),
            to: "1.0.215".into(),
            initial_classification: crate::model::Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: crate::model::BumpTier::LockfileOnly,
        }
    }

    fn sample_outcome(conclusion: &str) -> crate::model::ValidationOutcome {
        crate::model::ValidationOutcome {
            proposal_id: "cargo-serde-1-0-215".into(),
            conclusion: conclusion.into(),
            ci_forge_run_ids: Vec::new(),
            validated_workflows: Vec::new(),
            classification: crate::model::Classification::Exact,
            notes: Vec::new(),
        }
    }

    #[test]
    fn perform_apply_local_commit_creates_one_commit_when_all_green() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let repo = repo_tmp.path();
        init_git_repo(repo);
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        std::fs::write(repo.join("Cargo.lock"), "version = 3\n").unwrap();
        git(repo, ["add", "Cargo.toml", "Cargo.lock"]);
        git(repo, ["commit", "-m", "init"]);

        // Set up a sandbox whose Cargo.lock differs from the host's.
        let sandbox_tmp = tempfile::tempdir().unwrap();
        let sandbox = sandbox_tmp.path();
        std::fs::write(
            sandbox.join("Cargo.lock"),
            "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.215\"\n",
        )
        .unwrap();

        let registry = crate::ecosystem::default_registry();
        let mut completed_runs = vec![ProposalRun {
            eco_idx: 0, // cargo
            proposal: sample_cargo_proposal_for_apply(),
            sandbox: sandbox.to_path_buf(),
            outcome: sample_outcome("success"),
        }];
        let mut provenance = crate::model::Provenance::default();

        let summary =
            perform_apply_local_commit(repo, &registry, &mut completed_runs, 0, &mut provenance)
                .expect("apply-local commit should succeed");

        match summary {
            CommitSummary::Committed {
                bump_count,
                paths,
                subject,
            } => {
                assert_eq!(bump_count, 1);
                assert_eq!(paths, vec![PathBuf::from("Cargo.lock")]);
                assert!(
                    subject.starts_with("chore(deps): bump serde from 1.0.200 to 1.0.215"),
                    "subject should describe the single bump: {subject}"
                );
            }
            other => panic!("expected Committed, got {other:?}"),
        }

        // Host Cargo.lock must now match sandbox.
        let host_lock = std::fs::read_to_string(repo.join("Cargo.lock")).unwrap();
        assert!(
            host_lock.contains("1.0.215"),
            "host lock should carry the validated bump: {host_lock}"
        );

        // Exactly one new commit was added.
        let log = std::process::Command::new("git")
            .args(["log", "--oneline"])
            .current_dir(repo)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&log.stdout);
        assert_eq!(
            stdout.lines().count(),
            2,
            "expected init + apply commit, got:\n{stdout}"
        );
    }

    #[test]
    fn perform_apply_local_commit_refuses_when_any_proposal_failed() {
        let repo_tmp = tempfile::tempdir().unwrap();
        let repo = repo_tmp.path();
        init_git_repo(repo);
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        std::fs::write(repo.join("Cargo.lock"), "version = 3\n").unwrap();
        git(repo, ["add", "Cargo.toml", "Cargo.lock"]);
        git(repo, ["commit", "-m", "init"]);

        let sandbox_tmp = tempfile::tempdir().unwrap();
        std::fs::write(sandbox_tmp.path().join("Cargo.lock"), "version = 3\n").unwrap();

        let registry = crate::ecosystem::default_registry();
        // One green proposal + one failed validation. The mixed state
        // should refuse the commit.
        let mut completed_runs = vec![
            ProposalRun {
                eco_idx: 0,
                proposal: sample_cargo_proposal_for_apply(),
                sandbox: sandbox_tmp.path().to_path_buf(),
                outcome: sample_outcome("success"),
            },
            ProposalRun {
                eco_idx: 0,
                proposal: crate::model::Proposal {
                    id: "cargo-tokio-1-x".into(),
                    ..sample_cargo_proposal_for_apply()
                },
                sandbox: sandbox_tmp.path().to_path_buf(),
                outcome: sample_outcome("failure"),
            },
        ];
        let mut provenance = crate::model::Provenance::default();

        let summary =
            perform_apply_local_commit(repo, &registry, &mut completed_runs, 0, &mut provenance)
                .expect("refusal is not an error result");

        match summary {
            CommitSummary::SkippedDueToFailures { red_count, total } => {
                assert_eq!(red_count, 1, "one failure should be counted");
                assert_eq!(total, 2);
            }
            other => panic!("expected SkippedDueToFailures, got {other:?}"),
        }

        // No new commits beyond `init`.
        let log = std::process::Command::new("git")
            .args(["log", "--oneline"])
            .current_dir(repo)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&log.stdout);
        assert_eq!(
            stdout.lines().count(),
            1,
            "no apply commit should have been created: {stdout}"
        );
    }

    // -------------------------------------------------------------------------
    // perform_apply_pr — gh-CLI-backed publisher (against mock backend)
    // -------------------------------------------------------------------------

    struct MockPrBackend {
        // Records calls so tests can assert on them.
        opened: std::sync::Mutex<Vec<crate::publisher::PullRequestRequest>>,
        metadata: crate::publisher::BranchMetadata,
    }

    impl crate::publisher::PullRequestBackend for MockPrBackend {
        fn fetch_branch_metadata(
            &self,
            _owner: &str,
            _repo: &str,
            _branch: &str,
        ) -> std::result::Result<crate::publisher::BranchMetadata, crate::publisher::BackendError>
        {
            Ok(self.metadata.clone())
        }

        fn open_pull_request(
            &self,
            request: &crate::publisher::PullRequestRequest,
        ) -> std::result::Result<
            crate::publisher::PullRequestResponse,
            crate::publisher::BackendError,
        > {
            self.opened.lock().unwrap().push(request.clone());
            Ok(crate::publisher::PullRequestResponse {
                url: "https://github.com/assay/test/pull/99".into(),
                number: 99,
            })
        }
    }

    /// Build a `file:///...` URL that git can push to on Windows + Unix.
    fn file_url(path: &std::path::Path) -> String {
        let canon = std::fs::canonicalize(path).unwrap();
        let s = canon.to_str().unwrap().to_string();
        if cfg!(windows) {
            // Strip the verbatim/UNC prefix `\\?\` that canonicalize adds.
            let stripped = s.strip_prefix(r"\\?\").unwrap_or(&s);
            let normalized = stripped.replace('\\', "/");
            format!("file:///{normalized}")
        } else {
            format!("file://{s}")
        }
    }

    /// Create a bare repo and a working repo with origin pointing at it.
    /// Returns (working tempdir, bare tempdir, working path, bare path).
    fn make_local_remote_pair() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
    ) {
        let bare = tempfile::tempdir().unwrap();
        let bare_path = bare.path().to_path_buf();
        git(&bare_path, ["init", "--bare", "-q", "-b", "main"]);

        let work = tempfile::tempdir().unwrap();
        let work_path = work.path().to_path_buf();
        init_git_repo(&work_path);
        std::fs::write(work_path.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        std::fs::write(work_path.join("Cargo.lock"), "version = 3\n").unwrap();
        git(&work_path, ["add", "Cargo.toml", "Cargo.lock"]);
        git(&work_path, ["commit", "-m", "init"]);
        // Rename branch to main for consistency.
        git(&work_path, ["branch", "-M", "main"]);
        // Wire origin via a file:// URL so git on Windows doesn't read
        // the drive letter as an SSH hostname.
        let url = file_url(&bare_path);
        git(&work_path, ["remote", "add", "origin", url.as_str()]);
        (work, bare, work_path, bare_path)
    }

    #[test]
    fn perform_apply_pr_pushes_branch_and_opens_pr_when_all_green() {
        let (_work_tmp, _bare_tmp, repo, _bare) = make_local_remote_pair();
        // Override remote URL with one parse_owner_repo_from_url can read.
        // `git remote set-url origin <new>` updates it.
        git(
            &repo,
            [
                "remote",
                "set-url",
                "origin",
                "https://github.com/wildmason/assay-test",
            ],
        );
        // But to actually push, we also need a real fetch URL — set the
        // pushurl back to the bare repo while keeping the fetch URL as the
        // GitHub-shape URL.
        let bare_url = file_url(&_bare);
        git(
            &repo,
            ["remote", "set-url", "--push", "origin", bare_url.as_str()],
        );

        let sandbox = tempfile::tempdir().unwrap();
        std::fs::write(
            sandbox.path().join("Cargo.lock"),
            "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.215\"\n",
        )
        .unwrap();

        let registry = crate::ecosystem::default_registry();
        let mut completed_runs = vec![ProposalRun {
            eco_idx: 0,
            proposal: sample_cargo_proposal_for_apply(),
            sandbox: sandbox.path().to_path_buf(),
            outcome: sample_outcome("success"),
        }];
        let mut provenance = crate::model::Provenance::default();
        let backend = MockPrBackend {
            opened: std::sync::Mutex::new(Vec::new()),
            metadata: crate::publisher::BranchMetadata {
                name: "assay/cargo/serde-1-0-215-placeholder".into(),
                is_default: false,
                is_protected: false,
            },
        };

        let summary = perform_apply_pr(
            &repo,
            &registry,
            &mut completed_runs,
            0,
            &mut provenance,
            &backend,
            "origin",
            "assay-test-run-pushed",
        )
        .expect("apply-pr should succeed");

        match summary {
            ApplyPrSummary::Published {
                url,
                branch,
                bump_count,
            } => {
                assert_eq!(bump_count, 1);
                assert!(branch.starts_with("assay/cargo/serde-"));
                assert!(url.contains("/pull/"));
            }
            other => panic!("expected Published, got {other:?}"),
        }
        let opened = backend.opened.lock().unwrap();
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].owner, "wildmason");
        assert_eq!(opened[0].repo, "assay-test");
        assert!(opened[0].title.contains("serde"));
    }

    #[test]
    fn perform_apply_pr_refuses_when_any_proposal_failed() {
        let (_w, _b, repo, _bp) = make_local_remote_pair();
        let sandbox = tempfile::tempdir().unwrap();
        std::fs::write(sandbox.path().join("Cargo.lock"), "version = 3\n").unwrap();

        let registry = crate::ecosystem::default_registry();
        let mut completed_runs = vec![ProposalRun {
            eco_idx: 0,
            proposal: sample_cargo_proposal_for_apply(),
            sandbox: sandbox.path().to_path_buf(),
            outcome: sample_outcome("failure"),
        }];
        let mut provenance = crate::model::Provenance::default();
        let backend = MockPrBackend {
            opened: std::sync::Mutex::new(Vec::new()),
            metadata: crate::publisher::BranchMetadata {
                name: "x".into(),
                is_default: false,
                is_protected: false,
            },
        };

        let summary = perform_apply_pr(
            &repo,
            &registry,
            &mut completed_runs,
            0,
            &mut provenance,
            &backend,
            "origin",
            "assay-test-run-refused",
        )
        .expect("refusal is not an error result");

        match summary {
            ApplyPrSummary::SkippedDueToFailures { red_count, total } => {
                assert_eq!(red_count, 1);
                assert_eq!(total, 1);
            }
            other => panic!("expected SkippedDueToFailures, got {other:?}"),
        }
        assert!(
            backend.opened.lock().unwrap().is_empty(),
            "no PR should have been opened"
        );
    }

    #[test]
    fn perform_apply_pr_refuses_when_metadata_marks_branch_protected() {
        let (_w, _b, repo, _bp) = make_local_remote_pair();
        git(
            &repo,
            [
                "remote",
                "set-url",
                "origin",
                "https://github.com/wildmason/assay-test",
            ],
        );
        let bare_url = file_url(&_bp);
        git(
            &repo,
            ["remote", "set-url", "--push", "origin", bare_url.as_str()],
        );
        let sandbox = tempfile::tempdir().unwrap();
        std::fs::write(
            sandbox.path().join("Cargo.lock"),
            "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.215\"\n",
        )
        .unwrap();

        let registry = crate::ecosystem::default_registry();
        let mut completed_runs = vec![ProposalRun {
            eco_idx: 0,
            proposal: sample_cargo_proposal_for_apply(),
            sandbox: sandbox.path().to_path_buf(),
            outcome: sample_outcome("success"),
        }];
        let mut provenance = crate::model::Provenance::default();
        let backend = MockPrBackend {
            opened: std::sync::Mutex::new(Vec::new()),
            // Server-side metadata claims the branch is protected — the
            // guard must refuse PR creation even though everything else
            // is green.
            metadata: crate::publisher::BranchMetadata {
                name: "<placeholder>".into(),
                is_default: false,
                is_protected: true,
            },
        };

        let err = perform_apply_pr(
            &repo,
            &registry,
            &mut completed_runs,
            0,
            &mut provenance,
            &backend,
            "origin",
            "assay-test-run-protected",
        )
        .expect_err("protected branch metadata must reject");
        assert!(
            err.to_string().contains("protected"),
            "error should explain protection: {err}"
        );
        assert!(
            backend.opened.lock().unwrap().is_empty(),
            "no PR should have been opened after guard refusal"
        );
    }

    #[test]
    fn perform_apply_local_commit_is_deterministic_across_runs() {
        let setup = || -> (tempfile::TempDir, tempfile::TempDir) {
            let repo_tmp = tempfile::tempdir().unwrap();
            let repo = repo_tmp.path();
            init_git_repo(repo);
            std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
            std::fs::write(repo.join("Cargo.lock"), "version = 3\n").unwrap();
            git(repo, ["add", "Cargo.toml", "Cargo.lock"]);
            git(repo, ["commit", "-m", "init"]);
            let sandbox_tmp = tempfile::tempdir().unwrap();
            std::fs::write(
                sandbox_tmp.path().join("Cargo.lock"),
                "version = 3\n[[package]]\nname = \"serde\"\nversion = \"1.0.215\"\n",
            )
            .unwrap();
            (repo_tmp, sandbox_tmp)
        };

        let run = |repo: &std::path::Path, sandbox: &std::path::Path| -> String {
            let registry = crate::ecosystem::default_registry();
            // Three proposals in DIFFERENT input orders to prove the
            // sort-by-id step normalizes the result.
            let mut completed_runs = vec![
                ProposalRun {
                    eco_idx: 0,
                    proposal: crate::model::Proposal {
                        id: "cargo-z".into(),
                        subject: "z-crate".into(),
                        from: "1.0".into(),
                        to: "1.1".into(),
                        ..sample_cargo_proposal_for_apply()
                    },
                    sandbox: sandbox.to_path_buf(),
                    outcome: sample_outcome("success"),
                },
                ProposalRun {
                    eco_idx: 0,
                    proposal: crate::model::Proposal {
                        id: "cargo-a".into(),
                        subject: "a-crate".into(),
                        from: "1.0".into(),
                        to: "1.1".into(),
                        ..sample_cargo_proposal_for_apply()
                    },
                    sandbox: sandbox.to_path_buf(),
                    outcome: sample_outcome("success"),
                },
                ProposalRun {
                    eco_idx: 0,
                    proposal: crate::model::Proposal {
                        id: "cargo-m".into(),
                        subject: "m-crate".into(),
                        from: "1.0".into(),
                        to: "1.1".into(),
                        ..sample_cargo_proposal_for_apply()
                    },
                    sandbox: sandbox.to_path_buf(),
                    outcome: sample_outcome("success"),
                },
            ];
            let mut provenance = crate::model::Provenance::default();
            perform_apply_local_commit(repo, &registry, &mut completed_runs, 0, &mut provenance)
                .unwrap();
            let output = std::process::Command::new("git")
                .args(["log", "--pretty=format:%s%n%b", "-n", "1"])
                .current_dir(repo)
                .output()
                .unwrap();
            String::from_utf8_lossy(&output.stdout).into_owned()
        };

        let (repo1, sb1) = setup();
        let (repo2, sb2) = setup();
        let commit1 = run(repo1.path(), sb1.path());
        let commit2 = run(repo2.path(), sb2.path());
        assert_eq!(
            commit1, commit2,
            "two runs against same inputs must produce byte-identical commits"
        );
        // Body order should be alphabetical-by-proposal-id.
        let a_pos = commit1.find("a-crate").expect("a-crate in body");
        let m_pos = commit1.find("m-crate").expect("m-crate in body");
        let z_pos = commit1.find("z-crate").expect("z-crate in body");
        assert!(a_pos < m_pos && m_pos < z_pos, "body order must be sorted");
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
            gate_cmd: None,
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
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
            gate_cmd: None,
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
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
            gate_cmd: None,
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
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
            gate_cmd: None,
            gate_file: None,
            remote: "origin".into(),
            project: None,
            threads: None,
            fail_fast: false,
        };
        let cargo = crate::ecosystem::cargo::CargoEcosystem;
        let gha = crate::ecosystem::github_actions::GitHubActionsEcosystem;
        assert!(ecosystem_enabled(&args, &cargo));
        assert!(!ecosystem_enabled(&args, &gha));
    }
}
