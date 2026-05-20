//! CLI surface for `assay`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::ecosystem::{DependencyEcosystem, EcosystemContext, default_registry};
use crate::error::{Error, Result};
use crate::model::{
    AssayRunReceipt, Classification, Manifest, ManifestKind, Proposal, Provenance,
    ProvenanceRecord, RepositoryRef, RunSummary,
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
        .args(["apply_local", "apply_pr", "validate"])
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

    /// Run the validator stage on every proposal in an isolated sandbox
    /// and report per-proposal pass/fail — WITHOUT committing or opening
    /// PRs. The "test upgrades before adopting" mode. Mutually exclusive
    /// with `--apply-local` and `--apply-pr`.
    #[arg(long)]
    pub validate: bool,

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

    /// Suppress the per-ecosystem manifest-detection breadcrumbs
    /// (`[npm] manifests detected: N`, `[cargo] manifests detected:
    /// M`, etc.) and the per-proposal `proposal <id>: ...` lines.
    /// The bottom-of-run summary + tier breakdown + per-tier detail
    /// section still print. Useful when piping text output into
    /// another tool or when the breadcrumbs are too noisy. No effect
    /// on `--format json` (which already batches output to a single
    /// document at end-of-run).
    #[arg(long)]
    pub quiet: bool,

    /// Disable network calls during proposer phase. Network-bound
    /// ecosystems (currently: GitHub Actions, which resolves
    /// `uses:@SHA` against the latest release on github.com) fall
    /// back to whatever the action-store cache already holds —
    /// proposals are still emitted, but each is annotated with
    /// `source:offline-cache` and a "may be stale" note in the
    /// receipt. When no cache entry exists for an action, no
    /// proposal is emitted. Local-only ecosystems (Cargo, npm) are
    /// unaffected. Defaults to network-enabled.
    #[arg(long)]
    pub offline: bool,

    /// Bypass the action-store cache and force a fresh fetch for every
    /// GitHub API lookup. No effect in `--offline` mode (no source to
    /// refresh from). Default behavior: cache entries are served when
    /// fresh (< 7 days old) and re-fetched when stale.
    #[arg(long = "refresh-cache")]
    pub refresh_cache: bool,

    /// Suppress a specific proposal subject for this run, in addition to
    /// any `[ecosystems.<eco>] ignore = [...]` lists in `.assay.toml`.
    /// Format: `<ecosystem>:<subject>` (e.g. `cargo:reqwest` or
    /// `github-actions:actions/checkout`). Repeatable. CLI ignores are
    /// merged with — and never override — config-file ignores.
    #[arg(long = "ignore", value_name = "ECO:SUBJECT")]
    pub ignore: Vec<String>,

    /// Bypass the per-workflow verdict cache: every validator invocation
    /// runs the gate workflow fresh, and no entry is written. Use when
    /// you suspect a cached entry is stale beyond its TTL or want a
    /// clean CI baseline. Has no effect on DryRun (validator skipped).
    #[arg(long = "no-cache")]
    pub no_cache: bool,

    /// Verdict cache TTL. Cached entries older than this value are
    /// treated as cache misses and re-validated. Accepts shorthand
    /// durations: `30m`, `2h`, `7d`, `1w`. Default: `7d`.
    #[arg(long = "cache-ttl", value_name = "DURATION", default_value = "7d")]
    pub cache_ttl: String,

    /// For every proposal, attach a structured rationale to the
    /// receipt and surface it in the report. Each explanation names
    /// the classifier rule that fired (e.g. `cargo:caret-major-1-plus`,
    /// `gha:ref-shape-loosening`), the inputs that drove the decision,
    /// and the resulting tier. Useful for auditing why a bump was
    /// classified Compatible vs Breaking when the choice isn't obvious.
    #[arg(long)]
    pub explain: bool,

    /// Filter validator gate workflows by workspace-member precision:
    /// when a workflow uses an explicit `-p <member>` / `--package
    /// <member>` / `--workspace <member>` selector that targets ONLY
    /// non-affected members, skip the workflow. Workflows with
    /// wildcard selectors (`--workspace` / `-r` / etc.) and workflows
    /// with no member selectors are kept conservatively. Opt-in via
    /// this flag for v1; default behavior is unchanged (every gate
    /// workflow runs against every proposal). Speeds up validation
    /// on large monorepos where a dep is consumed by only a small
    /// subset of members.
    #[arg(long = "member-gate")]
    pub member_gate: bool,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, ValueEnum)]
pub enum EcosystemSelector {
    Cargo,
    GithubActions,
    Npm,
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
    /// Proposer phase only. Fast — no per-proposal sandbox or
    /// validator. Reports proposals as `unvalidated`.
    DryRun,
    /// Proposer + validator. Runs each proposal through an isolated
    /// sandbox + the configured validator gate and reports pass/fail.
    /// Does NOT commit or open PRs — closes the dogfood-tour-2026-05-19
    /// finding A (default `analyze` not delivering the "test before
    /// adopt" value-prop).
    Validate,
    ApplyLocal,
    ApplyPr,
}

impl ApplyMode {
    pub fn from_args(args: &AnalyzeArgs) -> Self {
        if args.apply_pr {
            ApplyMode::ApplyPr
        } else if args.apply_local {
            ApplyMode::ApplyLocal
        } else if args.validate {
            ApplyMode::Validate
        } else {
            ApplyMode::DryRun
        }
    }

    /// `true` when the mode runs the validator stage (Validate /
    /// ApplyLocal / ApplyPr). DryRun is the only mode that skips it.
    pub fn runs_validator(self) -> bool {
        matches!(
            self,
            ApplyMode::Validate | ApplyMode::ApplyLocal | ApplyMode::ApplyPr
        )
    }

    /// `true` when the mode copies validated greens back to the host
    /// repo (ApplyLocal commits / ApplyPr pushes). Validate and DryRun
    /// both leave the host unchanged.
    pub fn mutates_host(self) -> bool {
        matches!(self, ApplyMode::ApplyLocal | ApplyMode::ApplyPr)
    }
}

fn analyze_command(args: AnalyzeArgs) -> Result<()> {
    let mut args = args;
    // Load config first — ProjectScope::resolve needs `[project] roots`
    // for the polyglot multi-scan-root case.
    let config = crate::config::load(&args.repo)?;
    let project_scope = ProjectScope::resolve(&args, &config)?;
    // Override --repo / --ecosystem with whatever --project / config
    // resolved to. `args.repo` is what assay treats as the artifact
    // root (where `.assay/` lives + where the git checks anchor).
    args.repo = project_scope.artifact_root.clone();
    if let Some(eco) = project_scope.ecosystem_restriction {
        args.ecosystem = Some(eco);
    }
    if !args.repo.is_dir() {
        return Err(Error::RepoNotFound(args.repo));
    }
    for root in &project_scope.scan_roots {
        if !root.is_dir() {
            return Err(Error::RepoNotFound(root.clone()));
        }
    }
    let mode = ApplyMode::from_args(&args);
    // --member-gate only filters validator workflows. In DryRun the
    // validator never runs, so the flag is a no-op there. Without
    // this hint, the dogfood (ci-forge) showed an operator might
    // think `--member-gate` is doing something when paired with the
    // default (proposer-only) analyze mode.
    if args.member_gate && !mode.runs_validator() {
        eprintln!(
            "[member-gate] note: --member-gate filters validator gate workflows; the \
             current mode ({:?}) doesn't run the validator, so this flag has no effect. \
             Add --validate (or --apply-local / --apply-pr) to exercise member-precise gating.",
            mode,
        );
    }
    // The host-executor safety check matters whenever the validator
    // runs (Validate, ApplyLocal, ApplyPr) — `cargo build` against a
    // newly-bumped tree may execute build scripts assay just pulled
    // from the registry. `--gate-cmd` / `--gate-file` bypass forge
    // entirely and the operator is opting into running their own
    // commands.
    let gate_override = args.gate_cmd.is_some() || args.gate_file.is_some();
    if mode.runs_validator()
        && args.executor == ExecutorChoice::Host
        && !args.unsafe_host_validation
        && !gate_override
    {
        return Err(Error::other(
            "--executor host requires --unsafe-host-validation when the validator runs \
             (--validate, --apply-local, --apply-pr); dependency validation may \
             execute newly bumped build scripts",
        ));
    }

    // Safety: mutating modes refuse on a dirty tree unless --force.
    // Validate runs the validator without touching the host so a
    // dirty tree is fine.
    if mode.mutates_host()
        && !args.force
        && let Some(dirty_path) = working_tree_dirty_path(&args.repo)?
    {
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
    // Apply-pr preflight: $CI must not be set (we don't open PRs inside CI runs
    // unless the operator explicitly overrides via --force).
    if matches!(mode, ApplyMode::ApplyPr) && !args.force && std::env::var("CI").is_ok() {
        return Err(Error::other(
            "refusing to --apply-pr while $CI is set; CI runs should consume assay's report, not open PRs. \
             Pass --force to override.",
        ));
    }
    // Apply-pr preflight: gh CLI must be installed and authenticated with
    // the repo scope. Fail fast before doing validation work the operator
    // would only discover wasted at `gh pr create` time. --force bypasses.
    if matches!(mode, ApplyMode::ApplyPr) && !args.force {
        preflight_apply_pr_gh_auth(&GhCliBackend::default())?;
    }
    // Apply-pr preflight: detect a broken global `insteadOf` rewrite that
    // would silently break `git push` for every github.com URL by rewriting
    // them into a form with an empty `x-access-token:` credential.
    if matches!(mode, ApplyMode::ApplyPr) && !args.force {
        preflight_apply_pr_insteadof(&args.repo)?;
    }

    let registry = default_registry();
    let started_at = iso8601_now();
    let run_id = generate_run_id();
    let mut total_manifests = 0usize;
    let mut all_proposals: Vec<(usize, PathBuf, Proposal)> = Vec::new();
    let mut provenance = Provenance::default();
    // Per-ecosystem manifest-count tally for the post-scan zero-result
    // hint. Honors the active --ecosystem filter (skipped ecosystems
    // aren't counted as "0 manifests"). Used to emit "no manifests
    // found at <root> for <eco>" when the user explicitly requested
    // an ecosystem that turned up nothing — the helm dogfood
    // (`.github/workflows/` absent) and mortar dogfood (orphan
    // root-level lockfile) both showed silent zero output as the
    // worst kind of "did it work?" confusion.
    let mut per_eco_manifest_count: std::collections::BTreeMap<&'static str, usize> =
        std::collections::BTreeMap::new();

    // Polyglot scan loop: every scan_root × every enabled ecosystem.
    // Each ecosystem's `detect_manifests` is scoped to one scan_root
    // at a time, so manifests at sibling roots (e.g. Tauri's
    // `src-tauri/Cargo.toml` and `ui/package.json`) are discovered
    // independently in the same run. Proposals carry their originating
    // scan_root forward so apply + merge land in the right sandbox.
    for scan_root in &project_scope.scan_roots {
        for (idx, ecosystem) in registry.iter().enumerate() {
            if !ecosystem_enabled(&args, ecosystem.as_ref()) {
                continue;
            }
            let manifests = ecosystem.detect_manifests(scan_root)?;
            // For multi-root reporting we want the scan_root's path
            // RELATIVE to the artifact root so the reporter prints
            // `src-tauri` / `ui` instead of full absolute paths. None
            // → repo root case (no prefix needed).
            let scan_root_rel = relative_prefix(&args.repo, scan_root);
            // JSON mode suppresses inline per-ecosystem reporting:
            // the full structured payload is emitted once at the end
            // of the run as a single valid JSON document (mirroring
            // the receipt). Inline per-ecosystem objects produced a
            // stream of top-level JSON objects that was neither
            // strict JSON nor NDJSON — `JSON.parse(stdout)` failed and
            // the proposals were missing from the payload entirely
            // (2026-05-20 dogfood, 4 of 7 agents confirmed). --quiet
            // also suppresses the inline breadcrumb (still emits the
            // bottom-of-run summary).
            if matches!(args.format, OutputFormat::Text) && !args.quiet {
                report_text(ecosystem.name(), scan_root_rel.as_deref(), &manifests);
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
                // Build a per-ecosystem context with the matching ignore
                // list from .assay.toml. The action_store still lives at
                // the artifact root (one cache per repo, shared across
                // scan_roots) — only the manifest-discovery scope changes
                // per scan_root.
                let context = EcosystemContext {
                    action_store: Some(args.repo.join(".assay").join("actions")),
                    allow_network: !args.offline,
                    ignored_subjects: resolve_ignore_list(&config, &args.ignore, ecosystem.name()),
                    refresh_cache: args.refresh_cache,
                };
                let mut proposals = ecosystem.propose_updates(&manifests, scan_root, &context)?;
                // Enrich each proposal with the list of workspace members
                // that directly declare the subject as a dependency. Scoped
                // to scan_root so per-sub-project consumer lists are
                // correct (e.g. Tauri `src-tauri` cargo consumers stay
                // distinct from `ui` npm consumers).
                for proposal in &mut proposals {
                    if let Ok(consumers) = ecosystem.affected_consumers(proposal, scan_root) {
                        proposal.affected_consumers = consumers;
                    }
                }
                // --explain: attach a structured rationale to every
                // proposal so the operator can audit why each was
                // classified as it was. No-op when the flag isn't set;
                // the proposers run the same classification logic
                // regardless, this just persists the matching
                // explanation for the receipt + reporter.
                if args.explain {
                    populate_proposal_explanations(&mut proposals, ecosystem.name());
                }
                for proposal in &proposals {
                    provenance.records.push(ProvenanceRecord {
                        tool: "assay".into(),
                        version: env!("CARGO_PKG_VERSION").into(),
                        stage: format!("proposer.{}", ecosystem.name()),
                        subject: proposal.id.clone(),
                        status: proposal.initial_classification,
                        summary: format!(
                            "{} {} -> {}",
                            proposal.subject, proposal.from, proposal.to
                        ),
                        artifact_path: None,
                        details: Some(serde_json::to_value(proposal).map_err(Error::Json)?),
                    });
                    // Text mode prints proposals as they're discovered
                    // (progressive feedback during slow cargo runs).
                    // JSON mode batches everything into the final
                    // single-document emission at end-of-run. --quiet
                    // suppresses the inline lines; the bottom-of-run
                    // per-tier section still surfaces every proposal.
                    if matches!(args.format, OutputFormat::Text) && !args.quiet {
                        println!(
                            "    proposal {}: {} {} -> {}",
                            proposal.id, proposal.subject, proposal.from, proposal.to,
                        );
                    }
                }
                for proposal in proposals {
                    all_proposals.push((idx, scan_root.clone(), proposal));
                }
            }
            total_manifests += manifests.len();
            *per_eco_manifest_count.entry(ecosystem.name()).or_insert(0) += manifests.len();
        }
    }

    // Zero-manifest hint for explicitly-filtered ecosystems. Only
    // fires when the user passed `--ecosystem <name>` for a SPECIFIC
    // ecosystem (not the implicit `all` default), so the broader
    // "everything-was-scanned" runs don't get noisy. The text format
    // surfaces this directly; the receipt JSON already records the
    // empty scan via the absence of any `scanner.<name>` provenance
    // record.
    if matches!(args.format, OutputFormat::Text)
        && let Some(selector) = args.ecosystem
        && !matches!(selector, EcosystemSelector::All)
    {
        for ecosystem in registry.iter() {
            if !ecosystem_enabled(&args, ecosystem.as_ref()) {
                continue;
            }
            let count = per_eco_manifest_count
                .get(ecosystem.name())
                .copied()
                .unwrap_or(0);
            if count == 0 {
                let hint = zero_manifest_hint(ecosystem.name());
                println!(
                    "[{}] no manifests found under `{}`{}",
                    ecosystem.name(),
                    args.repo.display(),
                    hint,
                );
            }
        }
    }

    let mut proposals_passed = 0usize;
    let mut proposals_failed = 0usize;
    let mut pre_validation_failure_rows: Vec<PreValidationFailureRow> = Vec::new();
    let mut proposals_unvalidated = 0usize;
    let mut completed_runs: Vec<ProposalRun> = Vec::new();
    let mut pre_validation_failures = 0usize;

    if mode.runs_validator() && !all_proposals.is_empty() {
        let validator = build_validator(&args, &args.repo)?
            .with_workflow_filter(workflow_filter_from_args(&args));

        let units: Vec<WorkUnit> = all_proposals
            .iter()
            .map(|(eco_idx, scan_root, proposal)| WorkUnit {
                eco_idx: *eco_idx,
                ecosystem_name: registry[*eco_idx].name(),
                proposal: proposal.clone(),
                scan_root: scan_root.clone(),
            })
            .collect();

        let pool = WorkerPool {
            threads: args.threads.unwrap_or_else(WorkerPool::default_threads),
            fail_fast: args.fail_fast,
        };
        // Build per-ecosystem semaphores from `.assay.toml`'s
        // `[ecosystems.<eco>] max_parallel` values (each ecosystem's
        // default lives in `config::default_<eco>_ecosystem`). `max_parallel
        // = 0` means unbounded (the `Semaphore::new(0)` shape — no permit
        // accounting). The worker pool looks entries up by ecosystem name
        // and skips acquire on misses, so any ecosystem omitted here runs
        // unbounded — every shipped ecosystem must be listed.
        let semaphores = vec![
            (
                "cargo",
                Arc::new(Semaphore::new(config.ecosystems.cargo.max_parallel)),
            ),
            (
                "github-actions",
                Arc::new(Semaphore::new(
                    config.ecosystems.github_actions.max_parallel,
                )),
            ),
            (
                "npm",
                Arc::new(Semaphore::new(config.ecosystems.npm.max_parallel)),
            ),
        ];
        let git_mutex = Mutex::new(());
        let ctx = WorkerContext {
            semaphores,
            git_mutex: &git_mutex,
            member_gate: args.member_gate,
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
                    eco_idx,
                    proposal,
                    provenance: pr_records,
                    summary,
                } => {
                    provenance.records.extend(pr_records);
                    proposals_failed += 1;
                    pre_validation_failures += 1;
                    pre_validation_failure_rows.push(PreValidationFailureRow {
                        eco_idx,
                        proposal,
                        summary,
                    });
                }
                WorkerOutcome::ValidatorErrored {
                    eco_idx: _,
                    proposal: _,
                    provenance: pr_records,
                    summary: _,
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
                    scan_root,
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
                        scan_root,
                    });
                }
            }
        }
    } else {
        proposals_unvalidated = all_proposals.len();
    }

    let mut commit_summary: Option<CommitSummary> = None;
    let mut pr_summary: Option<ApplyPrSummary> = None;
    if mode.mutates_host() && !all_proposals.is_empty() {
        // The Validator built above runs the merge step's revalidation
        // pass for any ecosystem with two or more individually-green
        // proposals. When the run is report-only or had no proposals,
        // no validator was built — but we wouldn't be inside this block
        // either, so the unwrap is safe by construction.
        let validator = build_validator(&args, &args.repo)?
            .with_workflow_filter(workflow_filter_from_args(&args));
        if matches!(mode, ApplyMode::ApplyLocal) {
            commit_summary = Some(perform_apply_local_commit(
                &args.repo,
                &registry,
                &mut completed_runs,
                pre_validation_failures,
                &mut provenance,
                &validator,
                &run_id,
            )?);
        }
        if matches!(mode, ApplyMode::ApplyPr) {
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
                &validator,
                &config.pull_request.labels,
                &config.pull_request.reviewers,
                config.pull_request.draft,
            )?);
        }
    }

    let (proposals_shipped, proposals_merged_dropped) =
        ship_counts(&commit_summary, &pr_summary, proposals_passed);
    let summary = RunSummary {
        manifests_scanned: total_manifests,
        proposals_total: all_proposals.len(),
        proposals_passed,
        proposals_failed,
        proposals_unvalidated,
        // Reserved for future tier short-circuits; today all three
        // tiers flow through apply+validate.
        proposals_discovered: 0,
        proposals_merged_dropped,
        proposals_shipped,
        prs_opened: 0,
    };
    let finished_at = iso8601_now();
    // Canonicalize the repository path so receipts don't carry the
    // `--project .` trailing-dot artifact (showed up as `<repo>\.` in
    // the nlg smoke). Falls back to the un-normalized value when
    // canonicalize fails (path doesn't exist, perms, etc.). The
    // result is then forward-slash-normalized so cross-platform
    // receipt consumers don't have to special-case Windows
    // backslashes (multiple dogfood agents flagged the slash
    // mixing as cosmetically jarring).
    let repository_path = args
        .repo
        .canonicalize()
        .map(strip_extended_length_prefix)
        .map(forward_slash_path)
        .unwrap_or_else(|_| args.repo.clone());
    let receipt = AssayRunReceipt {
        schema_version: crate::model::CURRENT_RECEIPT_SCHEMA_VERSION,
        run_id: run_id.clone(),
        started_at,
        finished_at,
        repository: RepositoryRef {
            path: repository_path,
            github: None,
            git_ref: None,
        },
        run_context: Some(capture_run_context()),
        summary,
        provenance,
    };
    let run_json_path = write_run_receipt(&args.repo, &receipt)?;

    if matches!(args.format, OutputFormat::Json) {
        // Single end-of-run JSON document. Mirrors the on-disk
        // receipt 1:1 so any tooling that knows how to parse the
        // receipt can also parse `--format json` stdout — and so
        // `JSON.parse(stdout)` actually succeeds (regression for the
        // dogfood-confirmed "multiple top-level objects" bug). The
        // receipt path is attached as a sibling field for callers
        // that want to drop into the on-disk artifact directly.
        let payload = serde_json::json!({
            "receipt": receipt,
            "receipt_path": run_json_path.display().to_string(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(crate::error::Error::Json)?
        );
    }

    if matches!(args.format, OutputFormat::Text) {
        // Per-tier breakdown surfaces the helm-style "110 deps behind
        // latest but constraint-pinned" gap that plain `cargo update`
        // hides. Walks all_proposals directly — the source of truth.
        let (lockfile_only, compatible, breaking) =
            tier_counts(all_proposals.iter().map(|(_, _, p)| p));
        // Active-ecosystem count honors `--ecosystem` so the summary
        // doesn't read "across 3 ecosystem(s)" when only one ran (the
        // gha-eventsmith / ci-forge / helm dogfood agents all flagged
        // this as misleading). Total compiled-in count is printed in
        // parentheses when the user filtered, so the diff between
        // active and total is visible.
        let active_eco_count = registry
            .iter()
            .filter(|eco| ecosystem_enabled(&args, eco.as_ref()))
            .count();
        let eco_phrase = if active_eco_count == registry.len() {
            format!("{} ecosystem(s)", active_eco_count)
        } else {
            format!("{} of {} ecosystem(s)", active_eco_count, registry.len())
        };
        println!(
            "assay: scanned {} manifest(s) across {}; {} proposal(s) (mode={:?})",
            total_manifests,
            eco_phrase,
            all_proposals.len(),
            mode,
        );
        println!(
            "assay: tier breakdown: {} lockfile-only / {} compatible / {} breaking",
            lockfile_only, compatible, breaking,
        );
        if (compatible + breaking) > 0 {
            print_discovered_section(all_proposals.iter().map(|(_, _, p)| p));
        }
        // Validate / ApplyLocal / ApplyPr all run the validator and
        // share the same "validated N green / M red / K unvalidated"
        // summary line + red-proposal detail section.
        if mode.runs_validator() {
            println!(
                "assay: validated {} green / {} red / {} unvalidated",
                proposals_passed, proposals_failed, proposals_unvalidated,
            );
            let (cached_workflow_total, fresh_workflow_total) =
                aggregate_cache_counts(&completed_runs);
            let workflow_total = cached_workflow_total + fresh_workflow_total;
            if workflow_total > 0 {
                let saved_pct = (cached_workflow_total * 100)
                    .checked_div(workflow_total)
                    .unwrap_or(0);
                println!(
                    "assay: verdict cache: {} cached / {} fresh ({}% reused; --no-cache to bypass, --cache-ttl <dur> to tune)",
                    cached_workflow_total, fresh_workflow_total, saved_pct,
                );
            }
            let member_skipped_total = aggregate_member_skipped_count(&completed_runs);
            if member_skipped_total > 0 {
                println!(
                    "assay: member-precise gating: {member_skipped_total} workflow(s) skipped (named only non-affected workspace members)",
                );
            }
            if let Some(red_section) =
                format_red_proposal_section(&completed_runs, &pre_validation_failure_rows)
            {
                print!("{red_section}");
            }
        }
        if matches!(mode, ApplyMode::Validate) && !all_proposals.is_empty() {
            // Validate is non-mutating; the retained sandboxes mirror
            // the --apply-local behavior so the operator can inspect
            // exactly what each proposal would have committed.
            println!(
                "assay: sandbox worktrees retained for audit under {} (mode=Validate; no commit, no PR)",
                args.repo
                    .join(".assay")
                    .join("runs")
                    .join(&run_id)
                    .join("work")
                    .display()
            );
        }
        if matches!(mode, ApplyMode::ApplyLocal) {
            match &commit_summary {
                Some(CommitSummary::Committed {
                    bump_count,
                    paths,
                    subject,
                    merged_drops,
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
                    if !merged_drops.is_empty() {
                        println!(
                            "assay: {} individually-green proposal(s) dropped from the merged ship (see receipt for details)",
                            merged_drops.len()
                        );
                        for drop in merged_drops {
                            println!("  - {}: {}", drop.proposal_id, drop.reason);
                        }
                    }
                }
                Some(CommitSummary::SkippedDueToFailures { red_count, total }) => {
                    println!(
                        "assay: refused to commit (--apply-local requires all-green); {} of {} proposal(s) failed validation",
                        red_count, total,
                    );
                }
                Some(CommitSummary::AllDroppedByMerge { drops }) => {
                    println!(
                        "assay: every individually-green proposal was dropped by the merge step ({} drop(s)); nothing committed",
                        drops.len()
                    );
                    for drop in drops {
                        println!("  - {}: {}", drop.proposal_id, drop.reason);
                    }
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
            // "validated" + red section already printed above by the
            // shared `mode.runs_validator()` branch.
            match &pr_summary {
                Some(ApplyPrSummary::Published {
                    url,
                    branch,
                    bump_count,
                    merged_drops,
                }) => {
                    println!(
                        "assay: opened PR for {bump_count} bump(s) on branch `{branch}`: {url}"
                    );
                    if !merged_drops.is_empty() {
                        println!(
                            "assay: {} individually-green proposal(s) dropped from the merged ship (see receipt for details)",
                            merged_drops.len()
                        );
                        for drop in merged_drops {
                            println!("  - {}: {}", drop.proposal_id, drop.reason);
                        }
                    }
                }
                Some(ApplyPrSummary::SkippedDueToFailures { red_count, total }) => {
                    println!(
                        "assay: refused to open PR (--apply-pr requires all-green); {} of {} proposal(s) failed validation",
                        red_count, total,
                    );
                }
                Some(ApplyPrSummary::AllDroppedByMerge { drops }) => {
                    println!(
                        "assay: every individually-green proposal was dropped by the merge step ({} drop(s)); no PR opened",
                        drops.len()
                    );
                    for drop in drops {
                        println!("  - {}: {}", drop.proposal_id, drop.reason);
                    }
                }
                Some(ApplyPrSummary::NothingToPublish) => {
                    println!("assay: nothing to publish (no green proposals)");
                }
                None => {}
            }
        }
        println!(
            "assay: receipt written to {}",
            forward_slash_path(run_json_path.clone()).display()
        );
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
    /// The scan_root this proposal originated from. For Tauri-style
    /// polyglot layouts, sibling ecosystems live in different
    /// subdirectories under the artifact root — apply/validate must
    /// run inside the scan_root, not against the artifact root.
    scan_root: PathBuf,
}

/// What a worker thread produces for one [`WorkUnit`].
///
/// `eco_idx` and `proposal` are carried on the failure variants for
/// future error-reporting that wants to address the failed proposal by
/// id. The current aggregator only reads them via the structural match
/// in `analyze_command`, so allow the dead-code lint here.
///
/// The `Completed` variant carries a `ValidationOutcome` (large struct
/// with provenance vectors) while the failure variants are smaller; the
/// `large_enum_variant` clippy lint flags the size disparity but
/// boxing every variant would muddy the call sites and the enum is
/// only ever held on one thread at a time. Allow the lint.
#[allow(dead_code, clippy::large_enum_variant)]
#[derive(Debug)]
enum WorkerOutcome {
    /// Apply tree preparation or `apply_proposal` failed before validation
    /// could run.
    PreValidationFailure {
        eco_idx: usize,
        proposal: Proposal,
        provenance: Vec<ProvenanceRecord>,
        /// One-line reason carried separately from the provenance
        /// records so the reporter can render per-failed-proposal
        /// detail without scanning the provenance trail.
        summary: String,
    },
    /// Validator couldn't run at all (e.g. forge not on PATH AND no
    /// recognized manifest).
    ValidatorErrored {
        eco_idx: usize,
        proposal: Proposal,
        provenance: Vec<ProvenanceRecord>,
        summary: String,
    },
    /// Pipeline completed with a real validation outcome.
    Completed {
        eco_idx: usize,
        proposal: Proposal,
        sandbox: PathBuf,
        outcome: crate::model::ValidationOutcome,
        provenance: Vec<ProvenanceRecord>,
        /// Forwarded from the input `WorkUnit` so the merge planner can
        /// group by (eco_idx, scan_root) when proposals come from
        /// multiple sub-projects (Tauri polyglot).
        scan_root: PathBuf,
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

/// Prints the per-tier upgrade table to stdout.
///
/// Format:
///
/// ```text
/// assay: per-tier upgrades:
///   compatible (within-major; manifest constraint widening applied):
///     cargo_metadata  0.18.1 -> 0.20.0
///   breaking (crosses semver-major; manifest edit applied):
///     serde  1.0.215 -> 2.0.0
/// ```
fn print_discovered_section<'a>(proposals: impl IntoIterator<Item = &'a Proposal>) {
    use crate::model::BumpTier;
    let mut lockfile_only: Vec<&Proposal> = Vec::new();
    let mut compatible: Vec<&Proposal> = Vec::new();
    let mut breaking: Vec<&Proposal> = Vec::new();
    for p in proposals {
        match p.bump_tier {
            BumpTier::LockfileOnly => lockfile_only.push(p),
            BumpTier::Compatible => compatible.push(p),
            BumpTier::Breaking => breaking.push(p),
        }
    }
    // Lockfile-only is shown in the per-tier section only when it
    // carries at least one cohort — otherwise it stays collapsed into
    // the top-of-run "tier breakdown: N lockfile-only / ..." count to
    // keep single-package cargo runs lean. The dogfood (slate, aegis,
    // mortar) flagged 33-line @angular/* + @tiptap/* lockfile-only
    // walls; surfacing the cohort header as one line under
    // `lockfile-only:` is the dense-but-informative pivot.
    let lockfile_has_cohort = lockfile_only.iter().any(|p| p.cohort.is_some());
    if compatible.is_empty() && breaking.is_empty() && !lockfile_has_cohort {
        return;
    }
    println!("assay: per-tier upgrades:");
    let print_group = |label: &str, group: Vec<&Proposal>| {
        if group.is_empty() {
            return;
        }
        println!("  {label}:");
        print_group_with_cohorts(&group);
    };
    if lockfile_has_cohort {
        print_group("lockfile-only", lockfile_only);
    }
    print_group("compatible", compatible);
    print_group("breaking", breaking);
}

/// Render one tier-group with cohort awareness: cohort members
/// collapse into one header line plus a member list; stand-alones
/// render as-is. Stable ordering — cohorts first (alphabetical by id),
/// then stand-alones (alphabetical by subject). This keeps the dense
/// "@angular/* family" line at the top of a tier when an Angular
/// project has half a dozen lockfile-only minor bumps; previously the
/// reader had to mentally regroup them. See the 2026-05-20 dogfood
/// against slate/aegis/wildmason.dev where this gap surfaced 3×.
fn print_group_with_cohorts(group: &[&Proposal]) {
    use std::collections::BTreeMap;
    let mut by_cohort: BTreeMap<String, Vec<&Proposal>> = BTreeMap::new();
    let mut standalone: Vec<&Proposal> = Vec::new();
    for &p in group {
        match &p.cohort {
            Some(id) => by_cohort.entry(id.clone()).or_default().push(p),
            None => standalone.push(p),
        }
    }
    // Single-member cohorts (only one cohort package present in this
    // tier — e.g. `@angular/cdk` alone with no `@angular/material`)
    // render as stand-alone lines: a one-element cohort header
    // wrapping a single member is pure overhead and obscures the
    // version. Multi-member cohorts (the actual lockstep-bump value-
    // prop) get the cohort header.
    for (cohort_id, mut members) in by_cohort {
        members.sort_by(|a, b| a.subject.cmp(&b.subject));
        if members.len() == 1 {
            standalone.push(members.into_iter().next().unwrap());
        } else {
            print_cohort_block(&cohort_id, &members);
        }
    }
    standalone.sort_by(|a, b| a.subject.cmp(&b.subject));
    for p in standalone {
        print_single_proposal_line(p);
    }
}

/// Render a cohort group as a single header line plus an indented
/// member list. Shows the version range when members target
/// different versions (e.g. `@angular/cdk` lags `@angular/core` by 2
/// patches in some Angular releases) and a single version when they
/// all converge.
fn print_cohort_block(cohort_id: &str, members: &[&Proposal]) {
    let display = crate::ecosystem::npm_cohorts::KNOWN_COHORTS
        .iter()
        .find(|c| c.id == cohort_id)
        .map(|c| c.display)
        .unwrap_or(cohort_id);
    let from_versions: std::collections::BTreeSet<&str> =
        members.iter().map(|p| p.from.as_str()).collect();
    let to_versions: std::collections::BTreeSet<&str> =
        members.iter().map(|p| p.to.as_str()).collect();
    let from_str = format_version_set(&from_versions);
    let to_str = format_version_set(&to_versions);
    let n = members.len();
    let word = if n == 1 { "package" } else { "packages" };
    println!("    {display} cohort ({n} {word}, {from_str} -> {to_str}):");
    for p in members {
        let mut line = format!("      - {}", p.subject);
        // Only show per-member version when it diverges from the
        // group's range — otherwise the cohort header already covers
        // it and the per-member line is noise.
        if from_versions.len() > 1 || to_versions.len() > 1 {
            line.push_str(&format!("  {} -> {}", p.from, p.to));
        }
        if !p.notes.is_empty() {
            line.push_str(&format!("  [{}]", p.notes.join(", ")));
        }
        line.push_str(&format_consumers_suffix(&p.affected_consumers));
        println!("{line}");
        if let Some(exp) = &p.explanation {
            println!("        [{}] {}", exp.rule, exp.summary);
        }
    }
}

fn print_single_proposal_line(p: &Proposal) {
    let mut line = format!("    {}  {} -> {}", p.subject, p.from, p.to);
    if !p.notes.is_empty() {
        line.push_str(&format!("  [{}]", p.notes.join(", ")));
    }
    line.push_str(&format_consumers_suffix(&p.affected_consumers));
    println!("{line}");
    if let Some(exp) = &p.explanation {
        println!("      [{}] {}", exp.rule, exp.summary);
    }
}

/// Display a set of version strings as either a single value (when
/// everyone agrees) or a `min..max` range. Used by the cohort header
/// to show convergent vs divergent member versions in one line.
fn format_version_set(versions: &std::collections::BTreeSet<&str>) -> String {
    let mut iter = versions.iter();
    let first = match iter.next() {
        Some(v) => *v,
        None => return String::new(),
    };
    if versions.len() == 1 {
        return first.to_string();
    }
    let last = versions.iter().last().copied().unwrap_or(first);
    format!("{first}..{last}")
}

/// Render a parenthesized "(N consumer(s): a, b, c)" suffix for the
/// reporter line. Returns an empty string when no consumers were
/// recorded — that's the GHA case (no workspace-member axis) and the
/// "the proposed dep isn't declared in any other member" case. Long
/// lists are truncated to the first 4 names with a trailing `, …+N`
/// marker so the line stays scannable.
fn format_consumers_suffix(consumers: &[crate::model::ConsumerId]) -> String {
    if consumers.is_empty() {
        return String::new();
    }
    const MAX_NAMES: usize = 4;
    let mut sorted: Vec<&crate::model::ConsumerId> = consumers.iter().collect();
    sorted.sort();
    let n = sorted.len();
    let label = if n == 1 { "consumer" } else { "consumers" };
    let head_count = sorted.len().min(MAX_NAMES);
    let head: Vec<String> = sorted
        .iter()
        .take(head_count)
        .map(|s| s.to_string())
        .collect();
    let tail = if n > MAX_NAMES {
        format!(", …+{}", n - MAX_NAMES)
    } else {
        String::new()
    };
    format!("  ({n} {label}: {}{tail})", head.join(", "))
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
    artifact_root: &Path,
    run_id: &str,
    ctx: &WorkerContext<'_>,
) -> WorkerOutcome {
    let mut records: Vec<ProvenanceRecord> = Vec::new();
    let ecosystem = registry[unit.eco_idx].as_ref();

    // Conc-2: `git worktree add` is serialized across workers to avoid
    // .git/index.lock races. The sandbox is set up against the unit's
    // scan_root (Tauri sub-project) while `.assay/` is anchored at the
    // shared artifact_root.
    let scan_root = unit.scan_root.clone();
    let apply_tree = {
        let _git_guard = ctx.git_mutex.lock().unwrap();
        prepare_apply_local_tree(artifact_root, &scan_root, run_id, &unit.proposal.id)
    };
    let apply_tree = match apply_tree {
        Ok(path) => path,
        Err(err) => {
            let summary = format!("apply tree preparation failed: {err}");
            records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("applier.{}", ecosystem.name()),
                subject: unit.proposal.id.clone(),
                status: Classification::Unsupported,
                summary: summary.clone(),
                artifact_path: None,
                details: None,
            });
            return WorkerOutcome::PreValidationFailure {
                eco_idx: unit.eco_idx,
                proposal: unit.proposal,
                provenance: records,
                summary,
            };
        }
    };

    if let Err(err) = ecosystem.apply_proposal(&unit.proposal, &apply_tree) {
        let summary = format!("apply failed: {err}");
        records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: format!("applier.{}", ecosystem.name()),
            subject: unit.proposal.id.clone(),
            status: Classification::Unsupported,
            summary: summary.clone(),
            artifact_path: None,
            details: None,
        });
        return WorkerOutcome::PreValidationFailure {
            eco_idx: unit.eco_idx,
            proposal: unit.proposal,
            provenance: records,
            summary,
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
    // Member-precise filter: when --member-gate is set, drop
    // workflows that name only non-affected workspace members. The
    // filter never drops wildcard workflows (--workspace etc.) or
    // workflows with no member selectors.
    let (workflow_paths, member_skipped) = if ctx.member_gate {
        let (kept, dropped) = crate::member_gate::filter_workflows_by_member(
            &apply_tree,
            &workflow_paths,
            &unit.proposal.affected_consumers,
        );
        for record in &dropped {
            records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("member-gate.{}", ecosystem.name()),
                subject: unit.proposal.id.clone(),
                status: Classification::Stubbed,
                summary: format!(
                    "skipped workflow `{}` ({:?})",
                    record.workflow.display(),
                    record.decision
                ),
                artifact_path: None,
                details: Some(serde_json::json!({
                    "workflow": record.workflow,
                    "decision": format!("{:?}", record.decision),
                })),
            });
        }
        (kept, dropped.len())
    } else {
        (workflow_paths, 0usize)
    };
    let outcome = match validator.validate(&unit.proposal, &apply_tree, &workflow_paths) {
        Ok(mut outcome) => {
            outcome.member_skipped_workflow_count = member_skipped;
            outcome
        }
        Err(err) => {
            let summary = format!("validator could not run: {err}");
            records.push(ProvenanceRecord {
                tool: "assay".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                stage: format!("validator.{}", ecosystem.name()),
                subject: unit.proposal.id.clone(),
                status: Classification::Stubbed,
                summary: summary.clone(),
                artifact_path: None,
                details: None,
            });
            return WorkerOutcome::ValidatorErrored {
                eco_idx: unit.eco_idx,
                proposal: unit.proposal,
                provenance: records,
                summary,
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
        scan_root,
    }
}

/// One proposal's full lifecycle through the apply-local pipeline:
/// applier produced a sandbox tree, validator scored it. Held in memory
/// until the post-loop commit phase decides whether to copy-back.
#[derive(Clone)]
struct ProposalRun {
    eco_idx: usize,
    proposal: Proposal,
    sandbox: PathBuf,
    outcome: crate::model::ValidationOutcome,
    /// Where this proposal's manifest lived on the host. Threaded
    /// into the merge planner so copy-back lands in the right
    /// sub-project tree (Tauri polyglot: cargo proposals go back to
    /// `src-tauri`, npm proposals to `ui`).
    scan_root: PathBuf,
}

/// Per-proposal apply-stage failure row, surfaced alongside
/// [`ProposalRun`]-tracked validation failures so the reporter can
/// render "why" details for both.
#[derive(Debug)]
struct PreValidationFailureRow {
    #[allow(dead_code)]
    eco_idx: usize,
    proposal: Proposal,
    summary: String,
}

/// Maximum lines of captured stderr to render per failed proposal in
/// the human reporter. Anything past this gets a one-line truncation
/// marker so the operator knows there's more in the receipt.
const REPORTER_STDERR_LINE_LIMIT: usize = 12;

/// Render the "why did these proposals fail" block for the human
/// reporter. Returns `None` when no proposals failed — caller skips
/// the section entirely (no empty header).
///
/// The block lists every red proposal once, with its
/// `subject from → to` line, a flavor tag (`[REGRESSION]`,
/// `[SETUP-FAILURE]`, `[TIMEOUT]`, or `[APPLY-FAILURE]` for pre-
/// validation failures), and either the last N lines of captured
/// Aggregate cached/fresh per-workflow validation counts across every
/// completed proposal run in this analyze pass. Sums [`ValidationOutcome::
/// cached_workflow_count`] and `total_workflow_count - cached_workflow_count`
/// so the report can render the cache-utilization line without re-deriving
/// the breakdown elsewhere.
fn aggregate_cache_counts(completed_runs: &[ProposalRun]) -> (usize, usize) {
    let mut cached = 0usize;
    let mut total = 0usize;
    for run in completed_runs {
        cached += run.outcome.cached_workflow_count;
        total += run.outcome.total_workflow_count;
    }
    let fresh = total.saturating_sub(cached);
    (cached, fresh)
}

/// Sum [`ValidationOutcome::member_skipped_workflow_count`] across all
/// completed proposal runs. Returns the total number of workflows the
/// member-precise filter dropped this pass.
fn aggregate_member_skipped_count(completed_runs: &[ProposalRun]) -> usize {
    completed_runs
        .iter()
        .map(|r| r.outcome.member_skipped_workflow_count)
        .sum()
}

/// stderr (validator failures) or the apply-stage summary string
/// (pre-validation failures). Ordering is alphabetical by proposal
/// id so successive runs produce byte-identical output.
fn format_red_proposal_section(
    completed_runs: &[ProposalRun],
    pre_val_failures: &[PreValidationFailureRow],
) -> Option<String> {
    let mut validation_failures: Vec<&ProposalRun> = completed_runs
        .iter()
        .filter(|r| r.outcome.conclusion != "success" && r.outcome.conclusion != "unvalidated")
        .collect();
    let mut pv_sorted: Vec<&PreValidationFailureRow> = pre_val_failures.iter().collect();
    if validation_failures.is_empty() && pv_sorted.is_empty() {
        return None;
    }
    validation_failures.sort_by(|a, b| a.proposal.id.cmp(&b.proposal.id));
    pv_sorted.sort_by(|a, b| a.proposal.id.cmp(&b.proposal.id));

    let total = validation_failures.len() + pv_sorted.len();
    let mut out = String::new();
    out.push_str(&format!("assay: red proposals ({total}):\n"));

    for run in &validation_failures {
        let flavor = run
            .outcome
            .failure_details
            .first()
            .map(|d| d.flavor.as_str())
            .unwrap_or("FAILURE");
        out.push_str(&format!(
            "  {} {} {} → {} [{}]{}\n",
            run.proposal.id,
            run.proposal.subject,
            run.proposal.from,
            run.proposal.to,
            flavor,
            format_consumers_suffix(&run.proposal.affected_consumers),
        ));
        for detail in &run.outcome.failure_details {
            if detail.stderr_tail.trim().is_empty() {
                continue;
            }
            out.push_str(&format!("    last stderr ({}):\n", detail.backend));
            let lines: Vec<&str> = detail.stderr_tail.lines().collect();
            let total_lines = lines.len();
            let start = total_lines.saturating_sub(REPORTER_STDERR_LINE_LIMIT);
            if start > 0 {
                out.push_str(&format!(
                    "      [... {} earlier line(s) elided; see receipt for full tail ...]\n",
                    start
                ));
            }
            for line in &lines[start..] {
                out.push_str("      ");
                out.push_str(line);
                out.push('\n');
            }
        }
    }

    for row in &pv_sorted {
        out.push_str(&format!(
            "  {} {} {} → {} [APPLY-FAILURE]{}\n    {}\n",
            row.proposal.id,
            row.proposal.subject,
            row.proposal.from,
            row.proposal.to,
            format_consumers_suffix(&row.proposal.affected_consumers),
            row.summary,
        ));
    }

    Some(out)
}

/// What happened during the post-validation `--apply-local` commit phase.
#[derive(Debug)]
enum CommitSummary {
    /// At least one proposal validated green individually AND survived
    /// the merge step. The atomic commit captures whatever the merge
    /// step shipped (which may exclude individually-green proposals
    /// the merge step had to drop — see `merged_drops`).
    Committed {
        bump_count: usize,
        paths: Vec<PathBuf>,
        subject: String,
        /// Individually-green proposals that the merge step dropped
        /// because including them turned the merged validation red.
        /// The commit ships the largest subset that greened.
        merged_drops: Vec<MergedDropInfo>,
    },
    /// One or more proposals didn't validate green individually; refusing
    /// to commit preserves the "atomic, all-individually-green" precondition
    /// of `--apply-local`.
    SkippedDueToFailures { red_count: usize, total: usize },
    /// Every individually-green proposal was dropped by the merge step —
    /// no subset of the greens validated together. Nothing to commit but
    /// the per-proposal greens are visible in the receipt and the operator
    /// can split into smaller batches.
    AllDroppedByMerge { drops: Vec<MergedDropInfo> },
    /// No proposals reached validation cleanly — nothing to commit.
    NothingToCommit,
}

/// Receipt-friendly view of a merge-step drop.
#[derive(Debug, Clone)]
pub(crate) struct MergedDropInfo {
    pub proposal_id: String,
    pub reason: String,
}

/// Compute the `(proposals_shipped, proposals_merged_dropped)` counters
/// for the `RunSummary` from the apply outcome.
///
/// For modes that never run apply (report-only, or no proposals at all):
/// shipped is 0 and dropped is 0. For apply-local + apply-pr:
/// shipped is the count that landed in the commit/PR, dropped is the
/// count of individually-green proposals the merge step rejected.
/// The invariant `shipped + dropped == proposals_passed` holds for the
/// happy path; on the `SkippedDueToFailures` / `NothingToCommit` paths
/// nothing ships but greens haven't been dropped by the merge step
/// either, so both counters return 0.
fn ship_counts(
    commit: &Option<CommitSummary>,
    pr: &Option<ApplyPrSummary>,
    _proposals_passed: usize,
) -> (usize, usize) {
    match (commit, pr) {
        (
            Some(CommitSummary::Committed {
                bump_count,
                merged_drops,
                ..
            }),
            _,
        ) => (*bump_count, merged_drops.len()),
        (Some(CommitSummary::AllDroppedByMerge { drops }), _) => (0, drops.len()),
        (
            _,
            Some(ApplyPrSummary::Published {
                bump_count,
                merged_drops,
                ..
            }),
        ) => (*bump_count, merged_drops.len()),
        (_, Some(ApplyPrSummary::AllDroppedByMerge { drops })) => (0, drops.len()),
        _ => (0, 0),
    }
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
    validator: &Validator,
    run_id: &str,
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

    // All-green individually. Sort by proposal ID for byte-deterministic
    // commits (Conc-9), then run the multi-proposal merge applier to
    // collapse per-ecosystem greens into one sandbox per ecosystem
    // (defeats the prior per-proposal copy-back last-write-wins bug for
    // cargo Compatible/Breaking and all npm tiers).
    completed_runs.sort_by(|a, b| a.proposal.id.cmp(&b.proposal.id));

    let ship_plan = build_ship_plan_from_runs(
        repo,
        run_id,
        registry,
        validator,
        completed_runs,
        provenance,
    )?;

    // Identify which runs survived the merge step.
    let mut shipped_flat: Vec<(usize, &ProposalRun)> = Vec::new();
    for outcome in &ship_plan {
        for run_idx in &outcome.shipped {
            shipped_flat.push((outcome.eco_idx, &completed_runs[*run_idx]));
        }
    }
    let merged_drops: Vec<MergedDropInfo> = ship_plan
        .iter()
        .flat_map(|o| {
            o.dropped.iter().map(|d| MergedDropInfo {
                proposal_id: completed_runs[d.run_idx].proposal.id.clone(),
                reason: d.reason.clone(),
            })
        })
        .collect();

    if shipped_flat.is_empty() {
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_local".into(),
            subject: "<aggregate>".into(),
            status: Classification::Unsupported,
            summary: format!(
                "refused to commit: every individually-green proposal was dropped by the merge step ({} drop(s))",
                merged_drops.len()
            ),
            artifact_path: None,
            details: Some(serde_json::json!({
                "drops": merged_drops.iter().map(|d| serde_json::json!({
                    "proposal_id": d.proposal_id,
                    "reason": d.reason,
                })).collect::<Vec<_>>(),
            })),
        });
        return Ok(CommitSummary::AllDroppedByMerge {
            drops: merged_drops,
        });
    }

    let mut modified_paths: Vec<PathBuf> = Vec::new();
    for outcome in &ship_plan {
        if outcome.shipped.is_empty() {
            continue;
        }
        let ecosystem = registry[outcome.eco_idx].as_ref();
        let shipped_proposals: Vec<&Proposal> = outcome
            .shipped
            .iter()
            .map(|i| &completed_runs[*i].proposal)
            .collect();
        // Copy back into the originating scan_root's host tree — for
        // Tauri polyglot that means cargo proposals land in
        // `src-tauri/` and npm proposals in `ui/`, not at the
        // artifact root.
        let modified = ecosystem
            .copy_back_merged(&shipped_proposals, &outcome.sandbox, &outcome.scan_root)
            .map_err(|err| {
                Error::other(format!(
                    "merged copy-back failed for `{}` ecosystem: {err}",
                    ecosystem.name()
                ))
            })?;
        // copy_back_merged returns paths relative to `outcome.scan_root`.
        // For `git add` from the artifact_root, prefix each with the
        // scan_root's relative-to-artifact-root path so multi-root
        // (Tauri polyglot) commits include `src-tauri/Cargo.toml` and
        // `ui/package.json`, not bare `Cargo.toml` / `package.json`.
        let prefix = relative_prefix(repo, &outcome.scan_root);
        for path in &modified {
            let joined = match &prefix {
                Some(p) if !p.as_os_str().is_empty() => p.join(path),
                _ => path.clone(),
            };
            if !modified_paths.contains(&joined) {
                modified_paths.push(joined);
            }
        }
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_local".into(),
            subject: format!("<merged:{}>", ecosystem.name()),
            status: Classification::Exact,
            summary: format!(
                "copied back {} path(s) for {} merged proposal(s)",
                modified.len(),
                shipped_proposals.len()
            ),
            artifact_path: None,
            details: Some(serde_json::json!({
                "ecosystem": ecosystem.name(),
                "proposals": shipped_proposals.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
                "scan_root": outcome.scan_root.display().to_string(),
                "modified": modified.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            })),
        });
    }

    if modified_paths.is_empty() {
        return Ok(CommitSummary::NothingToCommit);
    }

    let body = build_commit_body(completed_runs, &shipped_flat, &merged_drops);
    let raw_subject = if shipped_flat.len() == 1 {
        let p = &shipped_flat[0].1.proposal;
        format!(
            "chore(deps): bump {} from {} to {}",
            p.subject, p.from, p.to
        )
    } else {
        format!("chore(deps): bump {} dependencies", shipped_flat.len())
    };
    let subject = sanitize_commit_subject(&raw_subject)
        .map_err(|err| {
            Error::other(format!(
                "internal: generated commit subject failed sanitization: {err}"
            ))
        })?
        .to_string();

    let skipped_gitignored = git_add_paths(repo, &modified_paths)?;
    if !skipped_gitignored.is_empty() {
        emit_gitignored_skip_warning(&skipped_gitignored);
    }
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
            "bump_count": shipped_flat.len(),
            "merged_drops": merged_drops.iter().map(|d| serde_json::json!({
                "proposal_id": d.proposal_id,
                "reason": d.reason,
            })).collect::<Vec<_>>(),
            "modified_paths": modified_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        })),
    });

    Ok(CommitSummary::Committed {
        bump_count: shipped_flat.len(),
        paths: modified_paths,
        subject,
        merged_drops,
    })
}

/// Build the commit body from the shipped + dropped lists. Each shipped
/// proposal gets one bullet (subject vN -> vN+1 (classification)); if
/// any proposals were dropped by the merge step, a second section flags
/// them with the reason so the operator can re-batch them manually.
fn build_commit_body(
    completed_runs: &[ProposalRun],
    shipped_flat: &[(usize, &ProposalRun)],
    merged_drops: &[MergedDropInfo],
) -> String {
    let mut lines: Vec<String> = Vec::new();
    for (_eco, run) in shipped_flat {
        lines.push(format!(
            "- {} {} -> {} ({})",
            run.proposal.subject,
            run.proposal.from,
            run.proposal.to,
            run.outcome.classification.as_str()
        ));
    }
    if !merged_drops.is_empty() {
        lines.push(String::new());
        lines.push(format!(
            "Dropped by merge step ({} individually-green proposal(s) excluded because the merged validation reded):",
            merged_drops.len()
        ));
        for drop in merged_drops {
            let proposal_subject = completed_runs
                .iter()
                .find(|r| r.proposal.id == drop.proposal_id)
                .map(|r| {
                    format!(
                        "{} {} -> {}",
                        r.proposal.subject, r.proposal.from, r.proposal.to
                    )
                })
                .unwrap_or_else(|| drop.proposal_id.clone());
            lines.push(format!("- {} ({})", proposal_subject, drop.reason));
        }
    }
    lines.join("\n")
}

/// Run the merge applier across `completed_runs`, returning a per-
/// ecosystem ship plan. Thin wrapper so cli.rs holds the borrow shape
/// (constructing the &[RunRef] view) and apply_merger owns the merge
/// algorithm.
fn build_ship_plan_from_runs(
    repo: &Path,
    run_id: &str,
    registry: &[Box<dyn DependencyEcosystem>],
    validator: &Validator,
    completed_runs: &[ProposalRun],
    provenance: &mut Provenance,
) -> Result<Vec<crate::apply_merger::EcosystemMergeOutcome>> {
    let run_refs: Vec<crate::apply_merger::RunRef<'_>> = completed_runs
        .iter()
        .map(|r| crate::apply_merger::RunRef {
            eco_idx: r.eco_idx,
            proposal: &r.proposal,
            sandbox: r.sandbox.as_path(),
            outcome: &r.outcome,
            scan_root: r.scan_root.as_path(),
        })
        .collect();
    crate::apply_merger::build_ship_plan(repo, run_id, registry, validator, &run_refs, provenance)
}

/// Outcome of `--apply-pr` orchestration.
#[derive(Debug)]
enum ApplyPrSummary {
    Published {
        url: String,
        branch: String,
        bump_count: usize,
        merged_drops: Vec<MergedDropInfo>,
    },
    SkippedDueToFailures {
        red_count: usize,
        total: usize,
    },
    /// Every individually-green proposal was dropped by the merge step.
    AllDroppedByMerge {
        drops: Vec<MergedDropInfo>,
    },
    NothingToPublish,
}

/// Compute a deterministic branch name covering every shipped proposal.
///
/// Single-bump → `branch_name_for_bump(eco, subject, from, to)`.
/// Multi-bump → `assay/multi/<N>-<short-hash-of-all-ids>` so the name
/// remains injective on the set of proposals AND stable across re-runs.
fn compute_branch_name_for_runs(runs: &[&ProposalRun]) -> String {
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

/// Pre-flight check that `gh` is installed and authenticated with the
/// `repo` scope before `--apply-pr` starts validating proposals.
///
/// Without this guard the operator could spend minutes on validation
/// only to fail at `gh pr create` time. `--force` bypasses upstream for
/// edge cases (`gh` in a non-standard location, plans to open the PR
/// manually after the branch lands, etc.).
/// Best-effort cleanup of local `--apply-pr` artifacts (worktree +
/// branch) after a partial run. Pure function over side-effects so it
/// can be tested directly against a temp git fixture.
///
/// REMOTE state (a pushed branch) is intentionally NOT cleaned up:
/// when push succeeds but PR-open fails, the operator may want to
/// manually open the PR from the pushed branch, so we leave that for
/// them to decide.
fn cleanup_local_apply_state(git_root: &Path, worktree: Option<&Path>, local_branch: Option<&str>) {
    if let Some(wt) = worktree {
        let _ = std::process::Command::new("git")
            .arg("worktree")
            .arg("remove")
            .arg("--force")
            .arg(wt)
            .current_dir(git_root)
            .output();
    }
    if let Some(branch) = local_branch {
        let _ = std::process::Command::new("git")
            .arg("branch")
            .arg("-D")
            .arg(branch)
            .current_dir(git_root)
            .output();
    }
}

/// RAII guard that calls [`cleanup_local_apply_state`] on Drop unless
/// [`PartialApplyState::dismiss`] was called first. Used by
/// `perform_apply_pr` to make sure a worktree+branch created mid-run
/// doesn't survive a panic or early `?` return — that leftover branch
/// is the "branch already exists" footgun every retry stumbled over
/// before this guard existed.
struct PartialApplyState {
    git_root: PathBuf,
    worktree: Option<PathBuf>,
    local_branch: Option<String>,
    /// When true, Drop is a no-op (worktree+branch preserved as the
    /// audit trail for a successful Published run).
    success: bool,
    /// When false, Drop still cleans up but suppresses the "cleaned up
    /// partial state" warning — used for expected no-op early-returns
    /// like `NothingToPublish` where the cleanup isn't error recovery.
    noisy: bool,
}

impl PartialApplyState {
    fn new(git_root: PathBuf) -> Self {
        Self {
            git_root,
            worktree: None,
            local_branch: None,
            success: false,
            noisy: true,
        }
    }

    fn track_local(&mut self, worktree: PathBuf, branch: String) {
        self.worktree = Some(worktree);
        self.local_branch = Some(branch);
    }

    /// Mark the operation successful so Drop becomes a no-op and the
    /// worktree + local branch are preserved as the run's audit trail.
    fn dismiss(mut self) {
        self.success = true;
    }

    /// Allow Drop to clean up the local state but suppress the
    /// early-exit warning. Used when the run exited for an expected
    /// non-error reason (e.g. `NothingToPublish` post copy-back).
    fn dismiss_quietly(mut self) {
        self.noisy = false;
    }
}

impl Drop for PartialApplyState {
    fn drop(&mut self) {
        if self.success {
            return;
        }
        let had_local = self.worktree.is_some() || self.local_branch.is_some();
        cleanup_local_apply_state(
            &self.git_root,
            self.worktree.as_deref(),
            self.local_branch.as_deref(),
        );
        if self.noisy && had_local {
            eprintln!(
                "assay: cleaned up partial --apply-pr state (worktree + local branch) after early-exit; \
                 any pushed remote branch was left alone for manual recovery."
            );
        }
    }
}

/// Filter the operator's requested reviewers down to ones the
/// publisher will let through to `gh pr create --reviewer ...`.
///
/// Team-level reviewers (the `org/team` form) bypass the collaborator
/// filter — GitHub exposes them via a different endpoint and the
/// assignability semantics differ. User-level reviewers (bare
/// usernames) must appear in `backend.list_collaborators` or `gh pr
/// create` will fail the whole PR-open call.
///
/// On `list_collaborators` error the publisher drops all user-level
/// reviewers (parallel to the label-filter fallback) — the PR is the
/// load-bearing artifact, reviewer assignment is convenience.
fn filter_reviewers_to_collaborators(
    backend: &dyn crate::publisher::PullRequestBackend,
    owner: &str,
    repo: &str,
    requested: &[String],
) -> Vec<String> {
    if requested.is_empty() {
        return Vec::new();
    }
    let mut teams: Vec<&str> = Vec::new();
    let mut users: Vec<&str> = Vec::new();
    for name in requested {
        if name.contains('/') {
            teams.push(name.as_str());
        } else {
            users.push(name.as_str());
        }
    }
    if users.is_empty() {
        return teams.into_iter().map(str::to_string).collect();
    }
    let collaborators = match backend.list_collaborators(owner, repo) {
        Ok(set) => set,
        Err(err) => {
            eprintln!(
                "assay: WARNING: couldn't list collaborators on {owner}/{repo} ({err}); \
                 opening the PR without user-level reviewers (team reviewers, if any, are still attached)"
            );
            return teams.into_iter().map(str::to_string).collect();
        }
    };
    let collaborator_set: std::collections::HashSet<&str> =
        collaborators.iter().map(String::as_str).collect();
    let mut keep_users: Vec<&str> = Vec::new();
    let mut drop_users: Vec<&str> = Vec::new();
    for user in users {
        if collaborator_set.contains(user) {
            keep_users.push(user);
        } else {
            drop_users.push(user);
        }
    }
    if !drop_users.is_empty() {
        eprintln!(
            "assay: WARNING: dropping {} reviewer(s) who aren't collaborators on {owner}/{repo}: {}",
            drop_users.len(),
            drop_users.join(", ")
        );
    }
    teams
        .into_iter()
        .chain(keep_users)
        .map(str::to_string)
        .collect()
}

/// Format the error message for a failed `git worktree add` during
/// --apply-pr. When stderr suggests the branch already exists (the
/// common case when a prior run failed before PR open), append a
/// remediation hint listing the exact cleanup commands.
fn format_worktree_add_failure(branch: &str, stderr_trimmed: &str) -> String {
    if stderr_trimmed.contains("already exists") {
        return format!(
            "git worktree add (branch `{branch}`) failed: {stderr_trimmed}\n\n\
             A prior --apply-pr run likely created this branch and exited before opening the PR. \
             To retry, delete the branch first:\n  \
             git branch -D {branch}\n  \
             git push <remote> --delete {branch}   # only if the prior run also pushed"
        );
    }
    format!("git worktree add (branch `{branch}`) failed: {stderr_trimmed}")
}

/// Ensure every label in `requested` exists on the target repo, then
/// return the subset of names safe to pass to `gh pr create --label`.
///
/// Behavior:
/// 1. Look up the existing label set via `backend.list_labels`. On
///    error, drop ALL labels and warn — the PR is the load-bearing
///    artifact, labels are categorisation polish.
/// 2. For every requested label NOT already in the existing set, call
///    `backend.create_label`. On success keep the label. On failure
///    drop it and warn — same forward-progress posture as step 1.
/// 3. Return the union of already-existing labels and successfully
///    created labels (in request order).
///
/// This replaces the prior filter-only helper: operators who declared
/// labels in `.assay.toml` now have those labels auto-provisioned the
/// first time `--apply-pr` runs against a fresh repo, instead of the
/// PR opening unattended.
fn ensure_labels_exist(
    backend: &dyn crate::publisher::PullRequestBackend,
    owner: &str,
    repo: &str,
    requested: &[String],
) -> Vec<String> {
    if requested.is_empty() {
        return Vec::new();
    }
    let existing = match backend.list_labels(owner, repo) {
        Ok(labels) => labels,
        Err(err) => {
            eprintln!(
                "assay: WARNING: couldn't list labels on {owner}/{repo} ({err}); \
                 opening the PR without any labels"
            );
            return Vec::new();
        }
    };
    let existing_set: std::collections::HashSet<&str> =
        existing.iter().map(String::as_str).collect();
    let mut kept: Vec<String> = Vec::new();
    let mut create_failures: Vec<String> = Vec::new();
    for name in requested {
        if existing_set.contains(name.as_str()) {
            kept.push(name.clone());
            continue;
        }
        match backend.create_label(owner, repo, name) {
            Ok(()) => kept.push(name.clone()),
            Err(err) => {
                create_failures.push(format!("{name} ({err})"));
            }
        }
    }
    if !create_failures.is_empty() {
        eprintln!(
            "assay: WARNING: dropping {} label(s) that couldn't be auto-created on {owner}/{repo}: {}",
            create_failures.len(),
            create_failures.join(", ")
        );
    }
    kept
}

fn preflight_apply_pr_gh_auth(backend: &GhCliBackend) -> Result<()> {
    backend.check_auth().map_err(|err| {
        Error::other(format!(
            "apply-pr pre-flight: gh CLI auth check failed: {err} \
             (run `gh auth login -s repo` and retry, or pass --force to skip this check)"
        ))
    })
}

/// Config key for the specific broken `insteadOf` rewrite — when this
/// key is set with any non-empty value, `git push` to any github.com
/// URL will be rewritten through a literal `x-access-token:@` prefix
/// (empty password) which git treats as a real failing credential
/// instead of consulting its credential helper.
const BROKEN_INSTEADOF_KEY: &str = "url.https://x-access-token:@github.com/.insteadof";

/// Pure check: given the raw `git config --get-all <KEY>` output (or
/// `None` if the key wasn't set), return Err with a remediation when
/// the broken rewrite is present. Returns the std `Result<_, String>`
/// shape (NOT the crate alias) so the pure check stays independent of
/// the crate's [`crate::error::Error`] enum.
fn check_insteadof_rewrite(git_config_value: Option<&str>) -> std::result::Result<(), String> {
    let Some(value) = git_config_value else {
        return Ok(());
    };
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    Err(format!(
        "apply-pr pre-flight: your global git config has \
         `{BROKEN_INSTEADOF_KEY} = {trimmed}` which rewrites every github.com URL to embed an EMPTY \
         x-access-token credential. git treats the empty token as a real (failing) credential and \
         never consults its credential helper, breaking `git push` for every wildmason repo.\n\n\
         Recommended fix (removes the broken rule globally):\n  \
         git config --global --unset url.\"https://x-access-token:@github.com/\".insteadOf\n\n\
         Workaround for this run only: pass --force to bypass this check, then push from a remote \
         whose URL embeds a real token (e.g. `git remote set-url <remote> https://x-access-token:$(gh auth token)@github.com/<owner>/<repo>.git`)."
    ))
}

/// Run the `insteadOf` rewrite check against the operator's git config.
fn preflight_apply_pr_insteadof(repo: &Path) -> Result<()> {
    let output = std::process::Command::new("git")
        .args(["config", "--get-all", BROKEN_INSTEADOF_KEY])
        .current_dir(repo)
        .output();
    let value = match output {
        // `git config --get-all` exits non-zero when the key is absent;
        // that's the happy case, not an error.
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).into_owned()),
        Ok(_) => None,
        // Couldn't invoke git at all — let downstream stages surface
        // that error in their own context rather than fail the preflight.
        Err(_) => return Ok(()),
    };
    check_insteadof_rewrite(value.as_deref()).map_err(Error::other)
}

/// Run the post-validation `--apply-pr` flow:
/// branch → worktree → merge-apply → copy_back → commit → push → open PR.
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
    validator: &Validator,
    requested_labels: &[String],
    requested_reviewers: &[String],
    draft: bool,
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

    let ship_plan = build_ship_plan_from_runs(
        repo,
        run_id,
        registry,
        validator,
        completed_runs,
        provenance,
    )?;

    let mut shipped_flat: Vec<(usize, &ProposalRun)> = Vec::new();
    for outcome in &ship_plan {
        for run_idx in &outcome.shipped {
            shipped_flat.push((outcome.eco_idx, &completed_runs[*run_idx]));
        }
    }
    let merged_drops: Vec<MergedDropInfo> = ship_plan
        .iter()
        .flat_map(|o| {
            o.dropped.iter().map(|d| MergedDropInfo {
                proposal_id: completed_runs[d.run_idx].proposal.id.clone(),
                reason: d.reason.clone(),
            })
        })
        .collect();

    if shipped_flat.is_empty() {
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_pr".into(),
            subject: "<aggregate>".into(),
            status: Classification::Unsupported,
            summary: format!(
                "refused to open PR: every individually-green proposal was dropped by the merge step ({} drop(s))",
                merged_drops.len()
            ),
            artifact_path: None,
            details: None,
        });
        return Ok(ApplyPrSummary::AllDroppedByMerge {
            drops: merged_drops,
        });
    }

    let (owner, repo_name) = parse_owner_repo_from_origin(repo, remote)
        .map_err(|err| Error::other(format!("couldn't determine owner/repo: {err}")))?;
    let shipped_runs: Vec<&ProposalRun> = shipped_flat.iter().map(|(_, r)| *r).collect();
    let branch = compute_branch_name_for_runs(&shipped_runs);
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
    // Same sub-dir support as `prepare_apply_local_tree`: walk up to
    // the real git root so `git worktree add` finds the shared .git.
    let git_root = git_top_level(repo)?;
    let output = std::process::Command::new("git")
        .args(["worktree", "add", "-b"])
        .arg(&branch)
        .arg(&worktree)
        .arg("HEAD")
        .current_dir(&git_root)
        .output()
        .map_err(|source| Error::Io {
            path: git_root.clone(),
            source,
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::other(format_worktree_add_failure(
            &branch,
            stderr.trim(),
        )));
    }

    // From here on, any early-exit must clean up the local worktree +
    // branch we just created. The guard's Drop runs on every code path
    // that doesn't reach `partial.dismiss()` at the bottom of this
    // function.
    let mut partial = PartialApplyState::new(git_root.clone());
    partial.track_local(worktree.clone(), branch.clone());

    // Copy back into the worktree, per merged-ecosystem set.
    let mut modified_paths: Vec<PathBuf> = Vec::new();
    for outcome in &ship_plan {
        if outcome.shipped.is_empty() {
            continue;
        }
        let ecosystem = registry[outcome.eco_idx].as_ref();
        let shipped_proposals: Vec<&Proposal> = outcome
            .shipped
            .iter()
            .map(|i| &completed_runs[*i].proposal)
            .collect();
        // Locate the worktree's mirror of this outcome's scan_root. For
        // single-root, this IS the worktree. For Tauri polyglot, this
        // is `<worktree>/<scan_root-relative-to-artifact-root>` (e.g.
        // `<worktree>/src-tauri`).
        let prefix = relative_prefix(repo, &outcome.scan_root);
        let host_target = match &prefix {
            Some(p) if !p.as_os_str().is_empty() => worktree.join(p),
            _ => worktree.clone(),
        };
        let modified = ecosystem
            .copy_back_merged(&shipped_proposals, &outcome.sandbox, &host_target)
            .map_err(|err| {
                Error::other(format!(
                    "merged copy-back failed for `{}` ecosystem: {err}",
                    ecosystem.name()
                ))
            })?;
        for path in &modified {
            let joined = match &prefix {
                Some(p) if !p.as_os_str().is_empty() => p.join(path),
                _ => path.clone(),
            };
            if !modified_paths.contains(&joined) {
                modified_paths.push(joined);
            }
        }
        provenance.records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: "publisher.apply_pr".into(),
            subject: format!("<merged:{}>", ecosystem.name()),
            status: Classification::Exact,
            summary: format!(
                "copied back {} path(s) for {} merged proposal(s)",
                modified.len(),
                shipped_proposals.len()
            ),
            artifact_path: None,
            details: Some(serde_json::json!({
                "ecosystem": ecosystem.name(),
                "proposals": shipped_proposals.iter().map(|p| p.id.clone()).collect::<Vec<_>>(),
                "scan_root": outcome.scan_root.display().to_string(),
            })),
        });
    }

    if modified_paths.is_empty() {
        // Worktree was created but copy-back found nothing to stage.
        // Clean up quietly — this is an expected no-op, not an error.
        partial.dismiss_quietly();
        return Ok(ApplyPrSummary::NothingToPublish);
    }

    let body = build_commit_body(completed_runs, &shipped_flat, &merged_drops);
    let raw_subject = if shipped_flat.len() == 1 {
        let p = &shipped_flat[0].1.proposal;
        format!(
            "chore(deps): bump {} from {} to {}",
            p.subject, p.from, p.to
        )
    } else {
        format!("chore(deps): bump {} dependencies", shipped_flat.len())
    };
    let subject = sanitize_commit_subject(&raw_subject)
        .map_err(|err| {
            Error::other(format!(
                "internal: generated commit subject failed sanitization: {err}"
            ))
        })?
        .to_string();
    let skipped_gitignored = git_add_paths(&worktree, &modified_paths)?;
    if !skipped_gitignored.is_empty() {
        emit_gitignored_skip_warning(&skipped_gitignored);
    }
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
    let title = if shipped_flat.len() == 1 {
        format!(
            "Bump {} from {} to {}",
            shipped_flat[0].1.proposal.subject,
            shipped_flat[0].1.proposal.from,
            shipped_flat[0].1.proposal.to,
        )
    } else {
        format!("Bump {} dependencies via assay", shipped_flat.len())
    };
    let base = detect_default_branch(repo, remote).unwrap_or_else(|| "main".into());
    let labels = ensure_labels_exist(backend, &owner, &repo_name, requested_labels);
    let reviewers =
        filter_reviewers_to_collaborators(backend, &owner, &repo_name, requested_reviewers);
    let mut request = build_pull_request_request(PullRequestParams {
        owner: &owner,
        repo: &repo_name,
        branch: &branch,
        base: &base,
        subject: &title,
        body: body.clone(),
        labels,
        reviewers,
        draft,
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

    // Reaching here means push + branch metadata guard + PR open all
    // succeeded. The worktree + local branch are part of the run's
    // audit trail (operator can `cd .assay/runs/<run-id>/pr-tree` and
    // inspect), so dismiss the cleanup guard.
    partial.dismiss();

    Ok(ApplyPrSummary::Published {
        url: response.url,
        branch,
        bump_count: shipped_flat.len(),
        merged_drops,
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
///
/// Paths that are both untracked AND match a `.gitignore` rule are
/// silently skipped — `git add` would otherwise abort the whole batch
/// with "paths are ignored by one of your .gitignore files." Library
/// projects routinely gitignore lockfiles even though assay's
/// sandbox-validated bump touches them; refusing to commit anything in
/// that case would fail an apply where the meaningful artifact (the
/// manifest constraint widening) was perfectly valid. The caller
/// receives the skipped paths so it can surface a warning.
fn git_add_paths(repo: &Path, paths: &[PathBuf]) -> Result<Vec<PathBuf>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }
    let (stageable, ignored) = partition_stageable_paths(repo, paths)?;
    if stageable.is_empty() {
        return Err(Error::other(format!(
            "git add refused: all {} modified path(s) are gitignored — nothing to commit \
             (paths: {})",
            ignored.len(),
            ignored
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let mut cmd = std::process::Command::new("git");
    cmd.arg("add").arg("--").current_dir(repo);
    for path in &stageable {
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
    Ok(ignored)
}

/// Print a stderr warning naming the gitignored paths that were
/// excluded from the commit. Library projects routinely gitignore
/// lockfiles — the meaningful artifact (the manifest constraint
/// widening) still ships, but the lockfile change stays as an
/// unstaged working-tree edit the user can either keep, discard with
/// `git restore`, or regenerate with `cargo update` / `npm install`.
fn emit_gitignored_skip_warning(skipped: &[PathBuf]) {
    let joined = skipped
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "assay: warning: {} path(s) gitignored and excluded from commit: {}",
        skipped.len(),
        joined,
    );
    eprintln!(
        "assay: note: gitignored files were updated in your working tree but stay untracked per your .gitignore. \
         Run `git restore <path>` to discard, or regenerate the lockfile to match your local toolchain."
    );
}

/// Partition `paths` into "stageable now" vs "untracked + gitignored."
///
/// The predicate for skipping is "would `git add` refuse this path?".
/// Tracked paths can always be re-staged (gitignore is irrelevant once
/// a file is in the index). Untracked paths that match a gitignore
/// rule are refused by `git add` and would abort the whole batch.
///
/// Two `git` invocations per path is fine here — the path lists this
/// function receives are bounded by what `copy_back_merged` returns
/// for a single ecosystem's merged ship plan (small).
fn partition_stageable_paths(
    repo: &Path,
    paths: &[PathBuf],
) -> Result<(Vec<PathBuf>, Vec<PathBuf>)> {
    let mut stageable: Vec<PathBuf> = Vec::new();
    let mut ignored: Vec<PathBuf> = Vec::new();
    for path in paths {
        if path_is_untracked_and_gitignored(repo, path)? {
            ignored.push(path.clone());
        } else {
            stageable.push(path.clone());
        }
    }
    Ok((stageable, ignored))
}

fn path_is_untracked_and_gitignored(repo: &Path, path: &Path) -> Result<bool> {
    // Tracked paths can always be re-staged — gitignore rules don't
    // apply once a file is in the index. Check tracking first; if it's
    // tracked we don't even need to ask about gitignore.
    let tracked = std::process::Command::new("git")
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(path)
        .current_dir(repo)
        .output()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    if tracked.status.success() {
        return Ok(false);
    }
    // Untracked — does it match a gitignore rule? `git check-ignore`
    // exits 0 when the path is ignored, 1 when not. Any other exit
    // code (e.g. 128 for "not a git repo") surfaces as a hard error.
    let ignored = std::process::Command::new("git")
        .args(["check-ignore", "--"])
        .arg(path)
        .current_dir(repo)
        .output()
        .map_err(|source| Error::Io {
            path: repo.to_path_buf(),
            source,
        })?;
    match ignored.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(Error::other(format!(
            "git check-ignore failed for `{}`: {}",
            path.display(),
            String::from_utf8_lossy(&ignored.stderr).trim()
        ))),
    }
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
///
/// `.assay/` (assay's own artifact directory) is filtered out of the
/// dirty-tree check — its presence is a self-inflicted dirty state and
/// would otherwise refuse every back-to-back `analyze` → `analyze
/// --apply-local`. Operators who care about scoping `.assay/` out of
/// git can `.gitignore` it; this filter just guarantees assay never
/// trips on its own output.
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
    Ok(stdout
        .lines()
        .find(|line| !porcelain_line_is_assay_artifact(line))
        .map(|s| s.to_string()))
}

/// `git status --porcelain` lines start with a 2-char status code + space +
/// path. Path uses forward slashes regardless of OS. Returns `true` when
/// the path refers to assay's own `.assay/` artifact tree.
fn porcelain_line_is_assay_artifact(line: &str) -> bool {
    // Status code is exactly 2 chars + 1 space; path starts at byte 3.
    // Quoted paths (when the path contains spaces or special chars) have
    // a leading `"` which the simple `starts_with(".assay/")` test
    // wouldn't match — handle both shapes.
    let Some(rest) = line.get(3..) else {
        return false;
    };
    let path = rest.strip_prefix('"').unwrap_or(rest);
    // Renames have the shape `R  old -> new`; the new path is what
    // matters for dirty-tree intent. We check both halves to be safe.
    if let Some((old_path, new_path)) = path.split_once(" -> ") {
        return path_is_under_assay_dir(old_path) || path_is_under_assay_dir(new_path);
    }
    path_is_under_assay_dir(path)
}

fn path_is_under_assay_dir(path: &str) -> bool {
    let trimmed = path.trim_end_matches('"');
    trimmed == ".assay" || trimmed.starts_with(".assay/")
}

fn prepare_apply_local_tree(
    artifact_root: &std::path::Path,
    scan_root: &std::path::Path,
    run_id: &str,
    proposal_id: &str,
) -> Result<PathBuf> {
    // `scan_root` may point at a sub-directory of a git repo (e.g.
    // helm's `src-tauri/` under helm root, or one of several config-
    // declared roots in a Tauri polyglot layout). `git rev-parse
    // --show-toplevel` walks up to the real repo root; `git worktree
    // add` must run there to access the shared .git dir.
    //
    // `.assay/runs/<id>/work/` is anchored at `artifact_root` so all
    // sandboxes for one run live in one tree, even when proposals
    // come from multiple scan_roots. Single-root callers pass
    // artifact_root == scan_root.
    let git_root = git_top_level(scan_root)?;
    let rel_sub_dir = scan_root.canonicalize().ok().and_then(|c| {
        git_root
            .canonicalize()
            .ok()
            .and_then(|g| c.strip_prefix(&g).ok().map(Path::to_path_buf))
    });
    let work_root = artifact_root
        .join(".assay")
        .join("runs")
        .join(run_id)
        .join("work");
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
    // Convert target to absolute. `git worktree add` resolves a
    // relative target against its `current_dir` (which we set to
    // git_root), not against where assay was invoked — without this
    // canonicalization the worktree lands in the wrong place when
    // `--repo` is a sub-dir.
    let target_abs = std::path::absolute(&target).unwrap_or(target.clone());
    let output = std::process::Command::new("git")
        .arg("worktree")
        .arg("add")
        .arg("--detach")
        .arg(&target_abs)
        .arg("HEAD")
        .current_dir(&git_root)
        .output()
        .map_err(|source| Error::Io {
            path: git_root.clone(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "git worktree add failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    // Materialize external path deps (e.g. helm's
    // `wildmason-license = { path = "../../licensing/crate" }`) into
    // the sandbox so cargo's path resolution from inside the worktree
    // lands on real directories. No-op when the repo declares no
    // external path deps.
    let run_root = artifact_root.join(".assay").join("runs").join(run_id);
    crate::external_deps::materialize_external_deps_into_sandbox(
        scan_root,
        &target_abs,
        &run_root,
    )?;

    // When `repo` is a sub-directory, the applier/validator expect to
    // run inside the same sub-dir of the worktree. Otherwise they
    // wouldn't find Cargo.toml / package.json relative to the operator-
    // facing repo argument.
    let final_target = match rel_sub_dir {
        Some(rel) if !rel.as_os_str().is_empty() => target_abs.join(rel),
        _ => target_abs,
    };
    Ok(final_target)
}

/// Resolve the top-level git repo root for `path` via
/// `git rev-parse --show-toplevel`. Errors with a clear message when
/// `path` isn't under any git checkout (the operator can't use
/// `--apply-local` without git for the sandbox machinery).
fn git_top_level(path: &Path) -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .output()
        .map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if !output.status.success() {
        return Err(Error::other(format!(
            "--apply-local requires a git checkout so assay can retain an isolated worktree, \
             but `{}` is not under one (git rev-parse said: {})",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim(),
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(PathBuf::from(stdout.trim()))
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

/// Resolved scope for one `analyze` invocation. Carries the artifact
/// root (where `.assay/` lives + where git operations anchor) plus the
/// list of scan roots (directories where ecosystems detect manifests).
///
/// **Single-root case** (no `--project`, no `[project] roots` in config):
/// `artifact_root` = `scan_roots[0]` = `args.repo`. Single element.
///
/// **`--project <path>`**: `artifact_root` and the sole scan root are
/// derived from the path. May restrict to one ecosystem when path is
/// a manifest file. Config `[project] roots` is ignored in this mode —
/// `--project` is the explicit "single sub-project" entry point.
///
/// **`[project] roots = [...]` in `.assay.toml`** (polyglot Tauri / mixed
/// repos): `artifact_root` = `args.repo`; `scan_roots` = `args.repo`
/// plus each config-declared root (deduplicated). The repo root stays
/// in scan_roots so root-level manifests (`.github/workflows/`) are
/// still discovered.
#[derive(Debug, Clone)]
struct ProjectScope {
    /// Where `.assay/` is written and where git operations anchor.
    artifact_root: PathBuf,
    /// Every directory to scan for ecosystem manifests. Always
    /// non-empty.
    scan_roots: Vec<PathBuf>,
    ecosystem_restriction: Option<EcosystemSelector>,
}

impl ProjectScope {
    fn resolve(args: &AnalyzeArgs, config: &crate::config::AssayConfig) -> Result<Self> {
        if let Some(path) = args.project.as_deref() {
            if !path.exists() {
                return Err(Error::other(format!(
                    "--project path `{}` does not exist",
                    path.display()
                )));
            }
            if path.is_dir() {
                let (artifact_root, scan_root) = anchor_artifact_root_at_git_root(path);
                let mut scan_roots: Vec<PathBuf> = vec![scan_root.clone()];
                // Polyglot auto-detect ALSO applies when --project points
                // at a directory — without this, `assay analyze --project
                // mortar` (Tauri: src-tauri/ + ui/) misses every Cargo
                // and npm manifest because the root has neither at top
                // level. Pre-fix dogfood: 49/52 actionable proposals
                // (94%) silently dropped on mortar. Per-ecosystem gate
                // honored so a single-cargo / single-npm repo doesn't
                // also probe for subdirs (a root workspace covers its
                // members already).
                augment_with_polyglot_subdirs(&mut scan_roots, &scan_root, config);
                return Ok(ProjectScope {
                    artifact_root,
                    scan_roots,
                    ecosystem_restriction: None,
                });
            }
            let (eco, scan_root_initial) =
                infer_project_scope_from_manifest(path).ok_or_else(|| {
                    Error::other(format!(
                        "--project file `{}` is not a recognized manifest. \
                         Supported: Cargo.toml (cargo), .github/workflows/*.yml \
                         (github-actions).",
                        path.display()
                    ))
                })?;
            let (artifact_root, scan_root) = anchor_artifact_root_at_git_root(&scan_root_initial);
            return Ok(ProjectScope {
                artifact_root,
                scan_roots: vec![scan_root],
                ecosystem_restriction: Some(eco),
            });
        }
        // No --project: artifact root = --repo. scan_roots = repo + any
        // config-declared roots (resolved relative to repo). Repo root
        // is ALWAYS scanned so root-level manifests like
        // `.github/workflows/` aren't missed when the config lists
        // subdirectory roots.
        let artifact_root = args.repo.clone();
        let mut scan_roots: Vec<PathBuf> = vec![artifact_root.clone()];
        for cfg_root in &config.project.roots {
            let resolved = if cfg_root.is_absolute() {
                cfg_root.clone()
            } else {
                artifact_root.join(cfg_root)
            };
            if !scan_roots.iter().any(|p| same_path(p, &resolved)) {
                scan_roots.push(resolved);
            }
        }
        augment_with_polyglot_subdirs(&mut scan_roots, &artifact_root, config);
        Ok(ProjectScope {
            artifact_root,
            scan_roots,
            ecosystem_restriction: None,
        })
    }
}

/// Capture the reproducibility context (argv + tool version + host
/// OS/arch) at the top of every analyze run. Falls into the
/// receipt's `run_context` field so a downstream CI consumer can
/// scan one place for "what version on what machine". The dogfood
/// (ci-forge agent) flagged the absence of this top-level block as
/// the main missing piece for reproducibility audits.
fn capture_run_context() -> crate::model::RunContext {
    let cli_args: Vec<String> = std::env::args().collect();
    let mut host = std::collections::BTreeMap::new();
    host.insert("os".to_string(), std::env::consts::OS.to_string());
    host.insert("arch".to_string(), std::env::consts::ARCH.to_string());
    crate::model::RunContext {
        cli_args,
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        host,
    }
}

/// Drop the Windows extended-length path prefix (`\\?\`) that
/// `Path::canonicalize` emits on Windows. The prefix is technically
/// correct but visually noisy in receipts and breadcrumbs — every
/// downstream tool that consumes the path strips it anyway.
fn strip_extended_length_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

/// Convert any backslashes to forward slashes so receipt-emitted
/// paths are consistent across OSes. PathBuf on Windows happily
/// stores forward slashes; the receipt is display-only on the
/// downstream side, so we don't need to preserve native separators
/// for filesystem operations.
fn forward_slash_path(path: PathBuf) -> PathBuf {
    PathBuf::from(path.to_string_lossy().replace('\\', "/"))
}

/// Per-ecosystem remediation hint when `--ecosystem <name>` returns
/// no manifests. Each branch points at the most common reason from
/// the 2026-05-20 dogfood: gha repos that don't have
/// `.github/workflows/`, cargo crates without a lockfile, npm
/// projects without a `package.json`.
fn zero_manifest_hint(eco_name: &str) -> &'static str {
    match eco_name {
        "github-actions" => {
            " (no `.github/workflows/*.yml` present — github-actions runs only against \
             workflow files)"
        }
        "cargo" => {
            " (no `Cargo.toml` at the scan root; pass --project <member> to target a \
             workspace member directly)"
        }
        "npm" => {
            " (no `package.json` at the scan root; pass --project <subdir> if the npm \
             project lives in a subdirectory)"
        }
        _ => "",
    }
}

/// Append polyglot subdirectories (Tauri-style `src-tauri/`/`ui/`,
/// monorepo-style `apps/<name>/`/`packages/<name>/`) to `scan_roots`
/// when the repo root doesn't carry the relevant ecosystem's manifest
/// at top level. No-op when the user supplied `[project] roots = [...]`
/// in `.assay.toml` (explicit config wins). Each addition emits a
/// stderr breadcrumb so the operator can see what was auto-detected.
fn augment_with_polyglot_subdirs(
    scan_roots: &mut Vec<PathBuf>,
    repo_root: &Path,
    config: &crate::config::AssayConfig,
) {
    if !config.project.roots.is_empty() {
        return;
    }
    for extra in detect_polyglot_subdirs(repo_root) {
        if !scan_roots.iter().any(|p| same_path(p, &extra)) {
            // Strip the `\\?\` extended-length prefix that may show
            // up after canonicalize on Windows. The path is correct
            // either way, but the prefix is noise in user-facing
            // breadcrumbs.
            let display = strip_extended_length_prefix(extra.clone());
            eprintln!(
                "[project] auto-detected polyglot scan root: `{}` \
                 (set [project] roots = [...] in .assay.toml to silence)",
                display.display()
            );
            scan_roots.push(extra);
        }
    }
}

/// Probe `repo_root` for sub-projects in conventional Tauri /
/// monorepo locations. Returns each subdirectory that carries a v1
/// ecosystem manifest the root does NOT already cover.
///
/// Per-ecosystem gating: a cargo workspace at root already enumerates
/// its members, so cargo subdirs are skipped. An npm root package.json
/// already enumerates its workspaces, so npm subdirs are skipped.
/// This prevents double-counting workspace members while still
/// catching Tauri layouts (`src-tauri/` Cargo + `ui/` npm with no
/// root manifest) and rust+frontend polyglots (root Cargo workspace
/// + `apps/web/` npm — ci-forge's shape).
///
/// Order is stable across runs.
fn detect_polyglot_subdirs(repo_root: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let root_has_cargo = repo_root.join("Cargo.toml").is_file();
    let root_has_npm = repo_root.join("package.json").is_file();

    // src-tauri/ is the canonical Tauri backend directory; the literal
    // name is hard-coded by the Tauri CLI scaffold and shows up in
    // every Wildmason Tauri app (Bridge, Helm, Mortar, Crucible).
    let cargo_candidates = ["src-tauri"];
    // UI subfolder names — the small set of conventional choices
    // across the Tauri / Vue / Next.js + monorepo ecosystem. Order
    // matches encounter likelihood in Wildmason repos.
    let npm_candidates = ["ui", "frontend", "app", "web", "client"];

    if !root_has_cargo {
        for sub in cargo_candidates {
            let p = repo_root.join(sub);
            if p.join("Cargo.toml").is_file() {
                out.push(p);
            }
        }
    }
    if !root_has_npm {
        for sub in npm_candidates {
            let p = repo_root.join(sub);
            if p.join("package.json").is_file() {
                out.push(p);
            }
        }
        // Monorepo nested probe: `apps/<name>/package.json` and
        // `packages/<name>/package.json`. ci-forge's `apps/web/`
        // (rust workspace at root + Vite frontend nested 2 levels
        // deep) is unreachable from the 1-level scan above. Cargo is
        // omitted from this nested probe because a root workspace
        // already covers its members.
        for nest in ["apps", "packages"] {
            let nest_dir = repo_root.join(nest);
            if !nest_dir.is_dir() {
                continue;
            }
            let entries: Vec<_> = match std::fs::read_dir(&nest_dir) {
                Ok(iter) => iter.flatten().collect(),
                Err(_) => continue,
            };
            let mut nested: Vec<PathBuf> = entries
                .into_iter()
                .map(|e| e.path())
                .filter(|p| p.is_dir() && p.join("package.json").is_file())
                .collect();
            nested.sort();
            for p in nested {
                out.push(p);
            }
        }
    }
    out
}

/// Lexical-or-canonical path equivalence. Used by scan_roots dedupe
/// where two entries might refer to the same directory by different
/// strings (`.` vs absolute, `./src-tauri` vs `src-tauri`, etc.).
fn same_path(a: &Path, b: &Path) -> bool {
    if a == b {
        return true;
    }
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// Path from `base` to `target` when target lives under base. Returns
/// `None` when they're equivalent (no prefix needed) or when target
/// isn't under base. Used by the apply-local commit path to convert
/// scan_root-relative modified paths into artifact_root-relative paths
/// for `git add`.
fn relative_prefix(base: &Path, target: &Path) -> Option<PathBuf> {
    if same_path(base, target) {
        return None;
    }
    // Try lexical first (cheap, handles the common `--repo .` shape).
    if let Ok(stripped) = target.strip_prefix(base) {
        return Some(stripped.to_path_buf());
    }
    // Canonicalize and retry — handles `./src-tauri` vs absolute, etc.
    let base_canon = base.canonicalize().ok()?;
    let target_canon = target.canonicalize().ok()?;
    target_canon
        .strip_prefix(&base_canon)
        .ok()
        .map(Path::to_path_buf)
}

/// Walk up from `start` looking for a `.git` directory or file (worktree
/// pointer). Returns the directory containing it. `None` when `start`
/// is not inside any git checkout.
fn find_enclosing_git_root(start: &Path) -> Option<PathBuf> {
    let mut cursor = if start.is_absolute() {
        Some(start.to_path_buf())
    } else {
        std::env::current_dir().ok().map(|cwd| cwd.join(start))
    }?;
    loop {
        let dot_git = cursor.join(".git");
        // `.git` may be a directory (normal repo) OR a regular file
        // (linked worktrees / submodules); both signal a repo root.
        if dot_git.exists() {
            return Some(cursor);
        }
        if !cursor.pop() {
            return None;
        }
    }
}

/// Resolve `(artifact_root, scan_root)` for `--project <PATH>`. When
/// `scan_root_initial` lives inside a git checkout, `artifact_root`
/// becomes the repo top-level (absolute) and `scan_root` becomes the
/// matching absolute path — so `.assay/runs/...` lands next to the
/// rest of the project's git-managed state and the
/// `scan_root.canonicalize().strip_prefix(artifact_root.canonicalize())`
/// arithmetic in `prepare_apply_local_tree` works unambiguously.
///
/// When `scan_root_initial` is NOT in a git checkout, both fall back
/// to its original (caller-supplied) shape — the single-root standalone
/// behavior.
fn anchor_artifact_root_at_git_root(scan_root_initial: &Path) -> (PathBuf, PathBuf) {
    if let Some(git_root) = find_enclosing_git_root(scan_root_initial) {
        // Canonicalize scan_root so both paths share absolute form and
        // downstream strip_prefix logic doesn't see relative-vs-absolute
        // shape mismatch.
        let scan_root_abs = scan_root_initial
            .canonicalize()
            .unwrap_or_else(|_| scan_root_initial.to_path_buf());
        return (git_root, scan_root_abs);
    }
    (
        scan_root_initial.to_path_buf(),
        scan_root_initial.to_path_buf(),
    )
}

fn infer_project_scope_from_manifest(path: &Path) -> Option<(EcosystemSelector, PathBuf)> {
    let filename = path.file_name()?.to_str()?;
    if filename.eq_ignore_ascii_case("Cargo.toml") {
        let parent = path.parent()?.to_path_buf();
        return Some((EcosystemSelector::Cargo, parent));
    }
    if filename.eq_ignore_ascii_case("package.json") {
        let parent = path.parent()?.to_path_buf();
        return Some((EcosystemSelector::Npm, parent));
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
///
/// The verdict cache is wired in when `!args.no_cache`. Cache entries
/// live under `<artifact_root>/.assay/verdict-cache/` so every
/// (workspace, workflow) pair has a content-addressed verdict file. The
/// cache TTL comes from `args.cache_ttl` (parsed via
/// [`parse_cache_ttl`]).
fn build_validator(args: &AnalyzeArgs, artifact_root: &Path) -> Result<Validator> {
    let base = if let Some(cmd) = args.gate_cmd.as_deref() {
        Validator::with_backend(Box::new(CustomBackend::from_gate_cmd(cmd)))
    } else if let Some(file) = args.gate_file.as_deref() {
        Validator::with_backend(Box::new(CustomBackend::from_gate_file(file)))
    } else {
        let validator_executor = match args.executor {
            ExecutorChoice::Host => ValidatorExecutor::Host,
            ExecutorChoice::Docker => ValidatorExecutor::Docker,
        };
        Validator::auto(&args.repo, validator_executor)?
    };

    if args.no_cache {
        return Ok(base);
    }

    let ttl = parse_cache_ttl(&args.cache_ttl).map_err(|msg| {
        Error::other(format!(
            "--cache-ttl `{}` is not a valid duration: {}. \
             Accepts `<n>s`, `<n>m`, `<n>h`, `<n>d`, or `<n>w`.",
            args.cache_ttl, msg
        ))
    })?;
    let cache_dir = artifact_root.join(".assay").join("verdict-cache");
    let cache = crate::verdict_cache::VerdictCache::new(cache_dir, ttl);
    Ok(base.with_cache(cache))
}

/// Parse a `--cache-ttl` value (e.g. `7d`, `30m`, `2h`, `1w`, `300s`)
/// into a `Duration`. Accepts integer-valued suffixed forms only — no
/// fractions, no compound expressions like `1h30m`. Returns a
/// human-readable error string on failure.
pub fn parse_cache_ttl(s: &str) -> std::result::Result<std::time::Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty value".into());
    }
    let (num_part, unit_part): (&str, &str) = match s.find(|c: char| !c.is_ascii_digit()) {
        Some(idx) => (&s[..idx], &s[idx..]),
        None => (s, "s"),
    };
    if num_part.is_empty() {
        return Err(format!("missing number in `{s}`"));
    }
    let n: u64 = num_part
        .parse()
        .map_err(|_| format!("`{num_part}` is not a non-negative integer"))?;
    let secs = match unit_part.trim() {
        "s" => n,
        "m" => n.saturating_mul(60),
        "h" => n.saturating_mul(60 * 60),
        "d" => n.saturating_mul(60 * 60 * 24),
        "w" => n.saturating_mul(60 * 60 * 24 * 7),
        other => return Err(format!("unknown unit `{other}`")),
    };
    Ok(std::time::Duration::from_secs(secs))
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

/// Populate `proposal.explanation` for each proposal in `proposals`
/// by dispatching to the matching ecosystem's explainer. Called only
/// when `--explain` is set; otherwise proposals retain their default
/// `explanation: None`.
///
/// The dispatch keys on the ecosystem name (matching the strings
/// `ecosystem.name()` returns: `"cargo"`, `"github-actions"`,
/// `"npm"`). Proposals from a future ecosystem without a registered
/// explainer fall through with `None` rather than panic — the
/// reporter handles that gracefully (no rationale line printed).
fn populate_proposal_explanations(proposals: &mut [Proposal], ecosystem_name: &str) {
    use crate::ecosystem::{cargo as cargo_eco, github_actions as gha_eco, npm as npm_eco};
    use crate::model::BumpTier;
    for proposal in proposals.iter_mut() {
        let explanation = match (ecosystem_name, proposal.bump_tier) {
            ("cargo", BumpTier::LockfileOnly) => Some(cargo_eco::explain_lockfile_only_bump(
                &proposal.from,
                &proposal.to,
                None,
            )),
            ("cargo", _) => Some(cargo_eco::explain_unchanged_bump(
                &proposal.from,
                &proposal.to,
            )),
            ("github-actions", _) => Some(gha_eco::explain_action_bump(
                Some(&proposal.from),
                &proposal.to,
            )),
            ("npm", BumpTier::LockfileOnly) => Some(npm_eco::explain_npm_lockfile_only_bump(
                &proposal.from,
                &proposal.to,
                None,
            )),
            ("npm", _) => Some(npm_eco::explain_npm_bump(&proposal.from, &proposal.to)),
            _ => None,
        };
        proposal.explanation = explanation;
    }
}

/// Return the `.assay.toml` ignore list for `ecosystem_name`. When the
/// config has no entry for this ecosystem, returns an empty Vec.
///
/// npm and yarn1 share the npm ecosystem entry (both use the
/// `NpmEcosystem` impl). Other ecosystems get their own section in
/// the config.
fn resolve_ignore_list(
    config: &crate::config::AssayConfig,
    cli_ignores: &[String],
    ecosystem_name: &str,
) -> Vec<String> {
    let mut out: Vec<String> = match ecosystem_name {
        "cargo" => config.ecosystems.cargo.ignore.clone(),
        "github-actions" => config.ecosystems.github_actions.ignore.clone(),
        // npm/yarn1/pnpm aren't represented in the .assay.toml today;
        // a future config rev can add an `npm` section. For now return
        // an empty list (no ignores), matching the no-config default.
        _ => Vec::new(),
    };
    for entry in cli_ignores {
        if let Some((eco, subject)) = parse_cli_ignore(entry)
            && eco == ecosystem_name
            && !out.iter().any(|s| s == subject)
        {
            out.push(subject.to_string());
        }
    }
    out
}

/// Parse a `--ignore <eco>:<subject>` argument into its two halves.
/// Returns `None` for malformed input (no colon, empty halves), which
/// the caller silently drops — clap's value parsing handled the
/// repeat-and-collect, and a typo'd entry shouldn't crash the run.
fn parse_cli_ignore(raw: &str) -> Option<(&str, &str)> {
    let (eco, subject) = raw.split_once(':')?;
    let eco = eco.trim();
    let subject = subject.trim();
    if eco.is_empty() || subject.is_empty() {
        return None;
    }
    Some((eco, subject))
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
            | (EcosystemSelector::Npm, "npm")
    )
}

fn report_text(name: &str, scan_root_rel: Option<&Path>, manifests: &[Manifest]) {
    // Suppress (ecosystem, scan_root) pairs with no manifests — they're
    // dominant in multi-root layouts (cargo in `ui`, npm in `src-tauri`,
    // etc.) and add noise without signal.
    if manifests.is_empty() {
        return;
    }
    match scan_root_rel {
        Some(rel) if !rel.as_os_str().is_empty() => {
            println!(
                "[{name}] {}: {} manifest(s)",
                rel.display(),
                manifests.len()
            );
        }
        _ => println!("[{name}] manifests detected: {}", manifests.len()),
    }
    for manifest in manifests {
        println!("  - {}", manifest.path.display());
    }
    if let Some(warning) = missing_cargo_lock_warning(name, manifests) {
        eprintln!("{warning}");
    }
}

/// Build the warning text shown when a Cargo workspace has `Cargo.toml`
/// but no `Cargo.lock`. Returns `None` when no warning is warranted.
///
/// The proposer compares the committed lockfile against the registry to
/// find available bumps — without one it cannot find any, and the run
/// silently reports "0 proposals." That mode of failure misleads the
/// user into thinking nothing needs upgrading; in reality the analyzer
/// just had no anchor to compare against. Library crates routinely
/// don't commit `Cargo.lock`, so this case is common in OSS targets.
fn missing_cargo_lock_warning(name: &str, manifests: &[Manifest]) -> Option<String> {
    if name != "cargo" {
        return None;
    }
    let has_toml = manifests
        .iter()
        .any(|m| matches!(m.kind, ManifestKind::CargoToml));
    let has_lock = manifests
        .iter()
        .any(|m| matches!(m.kind, ManifestKind::CargoLock));
    if has_toml && !has_lock {
        Some(
            "[cargo] warning: Cargo.lock not found — assay needs a lockfile to detect upgrades. \
             Run `cargo generate-lockfile` once to materialize one (library crates typically \
             don't commit Cargo.lock; the file you generate stays untracked)."
                .to_string(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----- format_red_proposal_section ------------------------------------

    fn red_run(
        id: &str,
        subject: &str,
        from: &str,
        to: &str,
        flavor: &str,
        stderr: &str,
    ) -> ProposalRun {
        use crate::model::{BumpTier, FailureDetail, ProposalKind};
        ProposalRun {
            eco_idx: 0,
            proposal: Proposal {
                id: id.into(),
                ecosystem: "cargo".into(),
                kind: ProposalKind::Version,
                subject: subject.into(),
                from: from.into(),
                to: to.into(),
                initial_classification: Classification::Exact,
                manifest_paths: vec![],
                notes: vec![],
                bump_tier: BumpTier::Breaking,
                affected_consumers: Vec::new(),
                explanation: None,
                cohort: None,
            },
            sandbox: PathBuf::from("/tmp/sandbox"),
            outcome: crate::model::ValidationOutcome {
                proposal_id: id.into(),
                conclusion: "failure".into(),
                ci_forge_run_ids: vec![],
                validated_workflows: vec![],
                classification: Classification::Unsupported,
                notes: vec![],
                failure_details: vec![FailureDetail {
                    workflow: PathBuf::from("<tree:custom>"),
                    backend: "custom".into(),
                    flavor: flavor.into(),
                    stderr_tail: stderr.into(),
                    duration_ms: 1234,
                }],
                cached_workflow_count: 0,
                total_workflow_count: 1,
                member_skipped_workflow_count: 0,
            },
            scan_root: std::path::PathBuf::new(),
        }
    }

    fn green_run(id: &str) -> ProposalRun {
        use crate::model::{BumpTier, ProposalKind};
        ProposalRun {
            eco_idx: 0,
            proposal: Proposal {
                id: id.into(),
                ecosystem: "cargo".into(),
                kind: ProposalKind::Version,
                subject: id.into(),
                from: "1.0.0".into(),
                to: "1.0.1".into(),
                initial_classification: Classification::Exact,
                manifest_paths: vec![],
                notes: vec![],
                bump_tier: BumpTier::LockfileOnly,
                affected_consumers: Vec::new(),
                explanation: None,
                cohort: None,
            },
            sandbox: PathBuf::from("/tmp/sb"),
            outcome: crate::model::ValidationOutcome {
                proposal_id: id.into(),
                conclusion: "success".into(),
                ci_forge_run_ids: vec![],
                validated_workflows: vec![],
                classification: Classification::Exact,
                notes: vec![],
                failure_details: vec![],
                cached_workflow_count: 0,
                total_workflow_count: 0,
                member_skipped_workflow_count: 0,
            },
            scan_root: std::path::PathBuf::new(),
        }
    }

    fn green_run_with_cache_counts(id: &str, cached: usize, total: usize) -> ProposalRun {
        let mut run = green_run(id);
        run.outcome.cached_workflow_count = cached;
        run.outcome.total_workflow_count = total;
        run
    }

    #[test]
    fn aggregate_cache_counts_sums_across_proposals() {
        let runs = vec![
            green_run_with_cache_counts("a", 3, 4),
            green_run_with_cache_counts("b", 1, 2),
            green_run_with_cache_counts("c", 0, 5),
        ];
        let (cached, fresh) = aggregate_cache_counts(&runs);
        assert_eq!(cached, 4);
        // total = 4 + 2 + 5 = 11; fresh = 11 - 4 = 7.
        assert_eq!(fresh, 7);
    }

    #[test]
    fn aggregate_cache_counts_returns_zero_when_no_runs() {
        assert_eq!(aggregate_cache_counts(&[]), (0, 0));
    }

    #[test]
    fn aggregate_cache_counts_handles_all_cached() {
        let runs = vec![
            green_run_with_cache_counts("a", 3, 3),
            green_run_with_cache_counts("b", 2, 2),
        ];
        let (cached, fresh) = aggregate_cache_counts(&runs);
        assert_eq!(cached, 5);
        assert_eq!(fresh, 0);
    }

    #[test]
    fn aggregate_cache_counts_handles_all_fresh() {
        let runs = vec![
            green_run_with_cache_counts("a", 0, 3),
            green_run_with_cache_counts("b", 0, 4),
        ];
        let (cached, fresh) = aggregate_cache_counts(&runs);
        assert_eq!(cached, 0);
        assert_eq!(fresh, 7);
    }

    fn apply_failure_row(
        id: &str,
        subject: &str,
        from: &str,
        to: &str,
        summary: &str,
    ) -> PreValidationFailureRow {
        use crate::model::{BumpTier, ProposalKind};
        PreValidationFailureRow {
            eco_idx: 0,
            proposal: Proposal {
                id: id.into(),
                ecosystem: "cargo".into(),
                kind: ProposalKind::Version,
                subject: subject.into(),
                from: from.into(),
                to: to.into(),
                initial_classification: Classification::Exact,
                manifest_paths: vec![],
                notes: vec![],
                bump_tier: BumpTier::Breaking,
                affected_consumers: Vec::new(),
                explanation: None,
                cohort: None,
            },
            summary: summary.into(),
        }
    }

    // ----- format_consumers_suffix ---------------------------------------

    #[test]
    fn consumers_suffix_empty_for_zero_consumers() {
        assert_eq!(format_consumers_suffix(&[]), "");
    }

    #[test]
    fn consumers_suffix_singular_label_for_one() {
        let s = format_consumers_suffix(&["alpha".to_string()]);
        assert_eq!(s, "  (1 consumer: alpha)");
    }

    #[test]
    fn consumers_suffix_plural_label_and_sorted_alphabetical() {
        let s = format_consumers_suffix(&["c".into(), "a".into(), "b".into()]);
        // Sorted ascending, no truncation.
        assert_eq!(s, "  (3 consumers: a, b, c)");
    }

    #[test]
    fn consumers_suffix_truncates_to_first_four_with_overflow_marker() {
        let consumers: Vec<String> = (1..=7).map(|i| format!("crate-{i:02}")).collect();
        let s = format_consumers_suffix(&consumers);
        // First four alphabetically + "…+3" overflow marker.
        assert_eq!(
            s,
            "  (7 consumers: crate-01, crate-02, crate-03, crate-04, …+3)"
        );
    }

    // ----- partition_stageable_paths (gitignored-lockfile handling) -----

    fn init_repo_with_commit(repo: &std::path::Path) {
        git(repo, ["init"]);
        // user identity for the commit
        git(repo, ["config", "user.email", "test@example.invalid"]);
        git(repo, ["config", "user.name", "test"]);
        std::fs::write(repo.join("README.md"), "x").unwrap();
        git(repo, ["add", "README.md"]);
        git(repo, ["commit", "-m", "init"]);
    }

    #[test]
    fn partition_separates_gitignored_untracked_lockfile_from_tracked_manifest() {
        // Mirrors the real tokio shape: Cargo.lock listed in .gitignore;
        // Cargo.toml is a normal tracked manifest. assay's apply-local
        // copies both back from the sandbox, but `git add Cargo.lock`
        // would fail with "paths are ignored by one of your .gitignore
        // files." The partition step lets the commit proceed on the
        // manifest alone and surface a warning for the lockfile.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        init_repo_with_commit(repo);
        std::fs::write(repo.join(".gitignore"), "Cargo.lock\n").unwrap();
        git(repo, ["add", ".gitignore"]);
        git(repo, ["commit", "-m", "ignore lockfile"]);
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = []\n").unwrap();
        git(repo, ["add", "Cargo.toml"]);
        git(repo, ["commit", "-m", "add manifest"]);
        // Now write a new lockfile (untracked + gitignored) and modify
        // the manifest (tracked, unstaged).
        std::fs::write(repo.join("Cargo.lock"), "version = 3\n").unwrap();
        std::fs::write(repo.join("Cargo.toml"), "[workspace]\nmembers = [\"a\"]\n").unwrap();

        let (stageable, ignored) = partition_stageable_paths(
            repo,
            &[PathBuf::from("Cargo.toml"), PathBuf::from("Cargo.lock")],
        )
        .unwrap();

        assert_eq!(
            stageable,
            vec![PathBuf::from("Cargo.toml")],
            "tracked manifest must remain stageable"
        );
        assert_eq!(
            ignored,
            vec![PathBuf::from("Cargo.lock")],
            "gitignored untracked lockfile must be partitioned out"
        );
    }

    #[test]
    fn partition_keeps_tracked_files_even_if_pattern_would_match_gitignore() {
        // A file that's been tracked since before a gitignore rule was
        // added still gets staged — `git add` ignores .gitignore for
        // already-tracked paths. This is the safety check that prevents
        // over-skipping.
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        init_repo_with_commit(repo);
        // Commit Cargo.lock first, THEN add a gitignore rule for it.
        std::fs::write(repo.join("Cargo.lock"), "version = 3\n").unwrap();
        git(repo, ["add", "Cargo.lock"]);
        git(repo, ["commit", "-m", "track lockfile"]);
        std::fs::write(repo.join(".gitignore"), "Cargo.lock\n").unwrap();
        git(repo, ["add", ".gitignore"]);
        git(repo, ["commit", "-m", "ignore lockfile post-track"]);
        // Modify the tracked lockfile.
        std::fs::write(repo.join("Cargo.lock"), "version = 3\n# bump\n").unwrap();

        let (stageable, ignored) =
            partition_stageable_paths(repo, &[PathBuf::from("Cargo.lock")]).unwrap();

        assert_eq!(
            stageable,
            vec![PathBuf::from("Cargo.lock")],
            "tracked lockfile must remain stageable even though gitignore pattern matches"
        );
        assert!(
            ignored.is_empty(),
            "tracked files must never be partitioned to the ignored set"
        );
    }

    #[test]
    fn partition_keeps_untracked_files_that_are_not_gitignored() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path();
        init_repo_with_commit(repo);
        std::fs::write(repo.join("new.toml"), "x").unwrap();

        let (stageable, ignored) =
            partition_stageable_paths(repo, &[PathBuf::from("new.toml")]).unwrap();

        assert_eq!(stageable, vec![PathBuf::from("new.toml")]);
        assert!(ignored.is_empty());
    }

    // ----- working_tree_dirty_path ignores .assay/ artifacts ------------

    #[test]
    fn porcelain_filter_treats_assay_artifacts_as_clean() {
        // The dirty-tree predicate must NOT trip on assay's own
        // `.assay/runs/...` directory — otherwise back-to-back
        // `analyze` and `analyze --apply-local` against the same repo
        // would always refuse on the (self-inflicted) untracked dir.
        assert!(porcelain_line_is_assay_artifact("?? .assay/"));
        assert!(porcelain_line_is_assay_artifact(
            "?? .assay/runs/assay-12345/run.json"
        ));
        assert!(porcelain_line_is_assay_artifact(" M .assay/index.json"));
        // Quoted form (path with spaces — rare but real).
        assert!(porcelain_line_is_assay_artifact(
            "?? \".assay/runs/assay 12345/log.txt\""
        ));
        // Rename from outside-into / inside-out of .assay/ — either
        // side touching .assay/ should be filtered.
        assert!(porcelain_line_is_assay_artifact(
            "R  src/foo.rs -> .assay/foo.rs"
        ));
        assert!(porcelain_line_is_assay_artifact(
            "R  .assay/foo.rs -> src/foo.rs"
        ));
    }

    #[test]
    fn porcelain_filter_keeps_real_dirty_paths() {
        // Anything outside `.assay/` is a real dirty signal and the
        // predicate must report it.
        assert!(!porcelain_line_is_assay_artifact(" M src/cli.rs"));
        assert!(!porcelain_line_is_assay_artifact("?? new-file.txt"));
        assert!(!porcelain_line_is_assay_artifact(
            "?? \"path with space.txt\""
        ));
        // A `.assay-foo/` (lookalike that isn't actually `.assay/`)
        // must not be filtered — the predicate is strict.
        assert!(!porcelain_line_is_assay_artifact("?? .assay-other/foo"));
        assert!(!porcelain_line_is_assay_artifact("?? .assaytmp"));
    }

    // ----- missing_cargo_lock_warning -----------------------------------

    fn cargo_manifest(kind: ManifestKind, path: &str) -> Manifest {
        Manifest {
            path: PathBuf::from(path),
            kind,
            metadata: std::collections::BTreeMap::new(),
        }
    }

    #[test]
    fn warns_when_cargo_workspace_has_no_lockfile() {
        let manifests = vec![cargo_manifest(ManifestKind::CargoToml, "Cargo.toml")];
        let warning = missing_cargo_lock_warning("cargo", &manifests).expect(
            "Cargo.toml without Cargo.lock must surface a warning so the user isn't \
             misled by a silent zero-proposal result",
        );
        assert!(
            warning.contains("Cargo.lock not found"),
            "warning must name the missing file: {warning}",
        );
        assert!(
            warning.contains("cargo generate-lockfile"),
            "warning must include the remediation command: {warning}",
        );
    }

    #[test]
    fn does_not_warn_when_lockfile_present() {
        let manifests = vec![
            cargo_manifest(ManifestKind::CargoToml, "Cargo.toml"),
            cargo_manifest(ManifestKind::CargoLock, "Cargo.lock"),
        ];
        assert!(missing_cargo_lock_warning("cargo", &manifests).is_none());
    }

    #[test]
    fn does_not_warn_for_non_cargo_ecosystems() {
        // npm/gha have their own lockfile semantics — this warning is
        // cargo-specific. A package.json without package-lock.json is
        // handled by npm's own path.
        let manifests = vec![cargo_manifest(ManifestKind::PackageJson, "package.json")];
        assert!(missing_cargo_lock_warning("npm", &manifests).is_none());
        assert!(missing_cargo_lock_warning("github-actions", &manifests).is_none());
    }

    // ----- parse_cli_ignore + resolve_ignore_list ------------------------

    #[test]
    fn parse_cli_ignore_happy_path() {
        assert_eq!(
            parse_cli_ignore("cargo:reqwest"),
            Some(("cargo", "reqwest"))
        );
        assert_eq!(
            parse_cli_ignore("github-actions:actions/checkout"),
            Some(("github-actions", "actions/checkout"))
        );
    }

    #[test]
    fn parse_cli_ignore_trims_whitespace_around_halves() {
        assert_eq!(
            parse_cli_ignore("  cargo  :  reqwest  "),
            Some(("cargo", "reqwest"))
        );
    }

    #[test]
    fn parse_cli_ignore_rejects_malformed_input() {
        // No colon.
        assert!(parse_cli_ignore("cargo-reqwest").is_none());
        // Empty halves.
        assert!(parse_cli_ignore(":reqwest").is_none());
        assert!(parse_cli_ignore("cargo:").is_none());
        assert!(parse_cli_ignore("  :  ").is_none());
    }

    #[test]
    fn resolve_ignore_list_merges_config_and_cli_for_matching_ecosystem() {
        // Config has reqwest; CLI adds tokio.
        let mut cfg = crate::config::AssayConfig::default();
        cfg.ecosystems.cargo.ignore = vec!["reqwest".into()];
        let cli = vec!["cargo:tokio".to_string()];
        let merged = resolve_ignore_list(&cfg, &cli, "cargo");
        assert_eq!(merged, vec!["reqwest".to_string(), "tokio".to_string()]);
    }

    #[test]
    fn resolve_ignore_list_dedupes_when_cli_repeats_config_entry() {
        let mut cfg = crate::config::AssayConfig::default();
        cfg.ecosystems.cargo.ignore = vec!["reqwest".into()];
        let cli = vec!["cargo:reqwest".to_string()];
        let merged = resolve_ignore_list(&cfg, &cli, "cargo");
        assert_eq!(merged, vec!["reqwest".to_string()]);
    }

    #[test]
    fn resolve_ignore_list_scopes_cli_entries_to_named_ecosystem() {
        // A `--ignore cargo:reqwest` must NOT leak into github-actions.
        let cfg = crate::config::AssayConfig::default();
        let cli = vec!["cargo:reqwest".to_string()];
        assert_eq!(
            resolve_ignore_list(&cfg, &cli, "github-actions"),
            Vec::<String>::new()
        );
        assert_eq!(
            resolve_ignore_list(&cfg, &cli, "cargo"),
            vec!["reqwest".to_string()]
        );
    }

    #[test]
    fn resolve_ignore_list_silently_drops_malformed_cli_entries() {
        let cfg = crate::config::AssayConfig::default();
        // No-colon entry, empty-half entry, plus one valid — only the
        // valid one survives. The malformed ones don't crash the run.
        let cli = vec![
            "cargo-reqwest".to_string(),
            ":reqwest".to_string(),
            "cargo:tokio".to_string(),
        ];
        assert_eq!(
            resolve_ignore_list(&cfg, &cli, "cargo"),
            vec!["tokio".to_string()]
        );
    }

    #[test]
    fn resolve_ignore_list_routes_cli_npm_entries_to_npm_ecosystem() {
        // Regression for the wildmason.dev dogfood finding: --ignore
        // npm:typescript was a silent no-op because the npm proposer
        // didn't honor `ctx.ignored_subjects`. The proposer-side fix
        // lives in npm.rs; this asserts the CLI wiring delivers the
        // subject to the npm ecosystem (and ONLY the npm ecosystem).
        let cfg = crate::config::AssayConfig::default();
        let cli = vec!["npm:typescript".to_string()];
        assert_eq!(
            resolve_ignore_list(&cfg, &cli, "npm"),
            vec!["typescript".to_string()]
        );
        assert_eq!(
            resolve_ignore_list(&cfg, &cli, "cargo"),
            Vec::<String>::new()
        );
        assert_eq!(
            resolve_ignore_list(&cfg, &cli, "github-actions"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn resolve_ignore_list_passes_through_scoped_npm_subject() {
        // `@angular/core` contains a slash and a `@`. The CLI parser
        // takes the FIRST colon as the eco/subject separator, leaving
        // the scoped name intact for the npm proposer's exact-match
        // filter to use.
        let cfg = crate::config::AssayConfig::default();
        let cli = vec!["npm:@angular/core".to_string()];
        assert_eq!(
            resolve_ignore_list(&cfg, &cli, "npm"),
            vec!["@angular/core".to_string()]
        );
    }

    // ----- consumer suffix integration in red section --------------------

    #[test]
    fn red_section_includes_consumer_suffix_when_proposal_has_consumers() {
        let mut run = red_run("cargo-sha2", "sha2", "0.10", "0.11", "REGRESSION", "boom");
        run.proposal.affected_consumers = vec!["helm-core".into(), "helm-cli".into()];
        let out = format_red_proposal_section(&[run], &[]).unwrap();
        assert!(
            out.contains("(2 consumers: helm-cli, helm-core)"),
            "got: {out}"
        );
    }

    #[test]
    fn red_section_omits_consumer_suffix_when_consumers_empty() {
        // GHA proposals or single-crate projects produce no consumers —
        // the suffix must not render an empty "(0 consumers)" or trailing
        // whitespace.
        let run = red_run("cargo-sha2", "sha2", "0.10", "0.11", "REGRESSION", "boom");
        // affected_consumers stays at Vec::new() per red_run().
        let out = format_red_proposal_section(&[run], &[]).unwrap();
        assert!(
            !out.contains("consumer"),
            "no consumer text expected: {out}"
        );
    }

    // ----- Proposal back-compat without affected_consumers ---------------

    #[test]
    fn proposal_back_compat_legacy_receipt_without_affected_consumers() {
        // A receipt written before the affected_consumers field existed
        // must still deserialize cleanly with `#[serde(default)]`.
        let legacy_json = r#"{
            "id": "cargo-x",
            "ecosystem": "cargo",
            "kind": "version",
            "subject": "x",
            "from": "1.0.0",
            "to": "1.0.1",
            "initial_classification": "exact",
            "manifest_paths": [],
            "notes": [],
            "bump_tier": "lockfile-only"
        }"#;
        let proposal: Proposal =
            serde_json::from_str(legacy_json).expect("legacy receipt deserializes");
        assert!(proposal.affected_consumers.is_empty());
    }

    #[test]
    fn red_section_returns_none_when_no_failures() {
        let greens = vec![green_run("a"), green_run("b")];
        let pre_val: Vec<PreValidationFailureRow> = Vec::new();
        assert!(format_red_proposal_section(&greens, &pre_val).is_none());
    }

    #[test]
    fn red_section_renders_validation_failure_with_flavor_and_stderr() {
        let runs = vec![red_run(
            "cargo-sha2-0-11-0",
            "sha2",
            "0.10.9",
            "0.11.0",
            "REGRESSION",
            "error[E0599]: no method named `result` found for struct `Sha2_256`\n   --> src/main.rs:42:18",
        )];
        let pre_val: Vec<PreValidationFailureRow> = Vec::new();
        let out = format_red_proposal_section(&runs, &pre_val).expect("non-empty");
        assert!(out.contains("red proposals (1)"));
        assert!(out.contains("cargo-sha2-0-11-0 sha2 0.10.9 → 0.11.0 [REGRESSION]"));
        assert!(out.contains("last stderr (custom):"));
        assert!(out.contains("E0599"));
    }

    #[test]
    fn red_section_renders_pre_validation_failure_with_apply_tag() {
        let runs: Vec<ProposalRun> = Vec::new();
        let pre_val = vec![apply_failure_row(
            "cargo-reqwest-0-13-3",
            "reqwest",
            "0.12.28",
            "0.13.3",
            "apply failed: cargo update failed: failed to select a version",
        )];
        let out = format_red_proposal_section(&runs, &pre_val).expect("non-empty");
        assert!(out.contains("red proposals (1)"));
        assert!(out.contains("cargo-reqwest-0-13-3 reqwest 0.12.28 → 0.13.3 [APPLY-FAILURE]"));
        assert!(out.contains("failed to select a version"));
    }

    #[test]
    fn red_section_renders_both_validation_and_apply_failures() {
        let runs = vec![red_run(
            "cargo-sha2",
            "sha2",
            "0.10",
            "0.11",
            "REGRESSION",
            "compile error",
        )];
        let pre_val = vec![apply_failure_row(
            "cargo-reqwest",
            "reqwest",
            "0.12",
            "0.13",
            "apply failed",
        )];
        let out = format_red_proposal_section(&runs, &pre_val).expect("non-empty");
        assert!(out.contains("red proposals (2)"), "got: {out}");
        assert!(out.contains("[REGRESSION]"));
        assert!(out.contains("[APPLY-FAILURE]"));
    }

    #[test]
    fn red_section_is_deterministic_alphabetical_by_proposal_id() {
        // Same inputs in two orders should produce byte-identical output.
        let a = red_run("a-id", "a", "1", "2", "REGRESSION", "a stderr");
        let b = red_run("b-id", "b", "1", "2", "REGRESSION", "b stderr");
        let one = format_red_proposal_section(&[a.clone(), b.clone()], &[]).unwrap();
        let two = format_red_proposal_section(&[b, a], &[]).unwrap();
        assert_eq!(one, two);
        // And the alphabetical order should be observable.
        let a_pos = one.find("a-id").unwrap();
        let b_pos = one.find("b-id").unwrap();
        assert!(a_pos < b_pos, "alphabetical order violated: {one}");
    }

    #[test]
    fn red_section_truncates_long_stderr_with_elision_marker() {
        // 25-line stderr → only last 12 lines should appear, with a
        // marker noting 13 earlier lines were elided.
        let mut stderr = String::new();
        for i in 0..25 {
            stderr.push_str(&format!("stderr line {i}\n"));
        }
        let runs = vec![red_run("cargo-x", "x", "1", "2", "REGRESSION", &stderr)];
        let out = format_red_proposal_section(&runs, &[]).unwrap();
        // First 13 lines must be elided.
        assert!(out.contains("[... 13 earlier line(s) elided"));
        // First line that should appear is line 13.
        assert!(out.contains("stderr line 13"));
        // First line that must NOT appear inline (just in the marker) is line 0.
        assert!(
            !out.contains("      stderr line 0\n"),
            "early lines should be elided: {out}"
        );
    }

    #[test]
    fn red_section_skips_stderr_block_when_tail_is_empty_or_whitespace() {
        // No stderr captured at all → the flavor line still renders,
        // but no "last stderr" block.
        let runs = vec![red_run("cargo-y", "y", "1", "2", "TIMEOUT", "   \n\n\t  ")];
        let out = format_red_proposal_section(&runs, &[]).unwrap();
        assert!(out.contains("[TIMEOUT]"));
        assert!(
            !out.contains("last stderr"),
            "whitespace-only stderr should not produce a header: {out}"
        );
    }

    #[test]
    fn red_section_ignores_green_and_unvalidated_runs() {
        use crate::model::{BumpTier, ProposalKind};
        // A run with "unvalidated" conclusion isn't a failure for
        // reporting purposes — it's a no-validator-available case,
        // separately surfaced in the counts line.
        let unvalidated = ProposalRun {
            eco_idx: 0,
            proposal: Proposal {
                id: "cargo-z".into(),
                ecosystem: "cargo".into(),
                kind: ProposalKind::Version,
                subject: "z".into(),
                from: "1".into(),
                to: "2".into(),
                initial_classification: Classification::Exact,
                manifest_paths: vec![],
                notes: vec![],
                bump_tier: BumpTier::LockfileOnly,
                affected_consumers: Vec::new(),
                explanation: None,
                cohort: None,
            },
            sandbox: PathBuf::from("/tmp/sb"),
            outcome: crate::model::ValidationOutcome {
                proposal_id: "cargo-z".into(),
                conclusion: "unvalidated".into(),
                ci_forge_run_ids: vec![],
                validated_workflows: vec![],
                classification: Classification::Stubbed,
                notes: vec![],
                failure_details: vec![],
                cached_workflow_count: 0,
                total_workflow_count: 0,
                member_skipped_workflow_count: 0,
            },
            scan_root: std::path::PathBuf::new(),
        };
        let runs = vec![green_run("a"), unvalidated];
        assert!(format_red_proposal_section(&runs, &[]).is_none());
    }

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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
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

        let tree =
            prepare_apply_local_tree(repo, repo, "assay-test-run", "Cargo Serde/1.0.215").unwrap();

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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
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
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("directory project resolves");
        assert_eq!(scope.artifact_root, tmp.path());
        assert_eq!(scope.scan_roots, vec![tmp.path().to_path_buf()]);
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
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("Cargo.toml resolves");
        assert_eq!(scope.artifact_root, tmp.path());
        assert_eq!(scope.scan_roots, vec![tmp.path().to_path_buf()]);
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
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("workflow yaml resolves");
        assert_eq!(scope.artifact_root, tmp.path());
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
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("composite action resolves");
        assert_eq!(scope.artifact_root, tmp.path());
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
        let config = crate::config::AssayConfig::default();
        let err =
            ProjectScope::resolve(&args, &config).expect_err("unrecognized manifest must fail");
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
        let config = crate::config::AssayConfig::default();
        let err = ProjectScope::resolve(&args, &config).expect_err("missing path must fail");
        assert!(err.to_string().contains("does not exist"));
    }

    #[test]
    fn project_scope_defaults_to_single_repo_root_when_no_project_and_no_config_roots() {
        let tmp = tempfile::tempdir().unwrap();
        let args = AnalyzeArgs {
            repo: tmp.path().to_path_buf(),
            project: None,
            ..default_test_args()
        };
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("default resolves");
        assert_eq!(scope.artifact_root, tmp.path());
        assert_eq!(scope.scan_roots, vec![tmp.path().to_path_buf()]);
        assert!(scope.ecosystem_restriction.is_none());
    }

    #[test]
    fn project_scope_appends_config_roots_resolved_against_repo() {
        // Tauri-style polyglot: config declares two sub-project roots.
        // Repo root stays in scan_roots so `.github/workflows/` is
        // still discovered alongside the per-sub-project manifests.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("src-tauri")).unwrap();
        std::fs::create_dir_all(tmp.path().join("ui")).unwrap();
        let args = AnalyzeArgs {
            repo: tmp.path().to_path_buf(),
            project: None,
            ..default_test_args()
        };
        let mut config = crate::config::AssayConfig::default();
        config.project.roots = vec![PathBuf::from("src-tauri"), PathBuf::from("ui")];
        let scope = ProjectScope::resolve(&args, &config).expect("multi-root resolves");
        assert_eq!(scope.artifact_root, tmp.path());
        assert_eq!(
            scope.scan_roots,
            vec![
                tmp.path().to_path_buf(),
                tmp.path().join("src-tauri"),
                tmp.path().join("ui"),
            ],
        );
        assert!(scope.ecosystem_restriction.is_none());
    }

    #[test]
    fn project_scope_dedupes_config_roots_that_match_repo() {
        // Operator declares `.` as a root — same as repo root. Dedupe.
        let tmp = tempfile::tempdir().unwrap();
        let args = AnalyzeArgs {
            repo: tmp.path().to_path_buf(),
            project: None,
            ..default_test_args()
        };
        let mut config = crate::config::AssayConfig::default();
        config.project.roots = vec![PathBuf::from(".")];
        let scope = ProjectScope::resolve(&args, &config).expect("dedupe resolves");
        assert_eq!(scope.scan_roots.len(), 1, "got: {:?}", scope.scan_roots);
    }

    #[test]
    fn project_scope_project_flag_overrides_config_roots() {
        // `--project` is the explicit "single sub-project" mode. Config
        // roots are NOT applied — operator gave a precise scope.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("only-this");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(tmp.path().join("src-tauri")).unwrap();
        let args = AnalyzeArgs {
            repo: tmp.path().to_path_buf(),
            project: Some(target.clone()),
            ..default_test_args()
        };
        let mut config = crate::config::AssayConfig::default();
        config.project.roots = vec![PathBuf::from("src-tauri")];
        let scope = ProjectScope::resolve(&args, &config).expect("project flag wins");
        assert_eq!(scope.artifact_root, target);
        assert_eq!(scope.scan_roots, vec![target]);
    }

    #[test]
    fn apply_mode_from_args_picks_validate_when_flag_set() {
        let args = AnalyzeArgs {
            validate: true,
            ..default_test_args()
        };
        assert_eq!(ApplyMode::from_args(&args), ApplyMode::Validate);
        assert!(ApplyMode::Validate.runs_validator());
        assert!(!ApplyMode::Validate.mutates_host());
    }

    #[test]
    fn apply_mode_helpers_match_documented_matrix() {
        // DryRun: skip validator, no mutation.
        assert!(!ApplyMode::DryRun.runs_validator());
        assert!(!ApplyMode::DryRun.mutates_host());
        // Validate: run validator, no mutation.
        assert!(ApplyMode::Validate.runs_validator());
        assert!(!ApplyMode::Validate.mutates_host());
        // ApplyLocal: run validator + mutate (commit).
        assert!(ApplyMode::ApplyLocal.runs_validator());
        assert!(ApplyMode::ApplyLocal.mutates_host());
        // ApplyPr: run validator + mutate (push + PR).
        assert!(ApplyMode::ApplyPr.runs_validator());
        assert!(ApplyMode::ApplyPr.mutates_host());
    }

    #[test]
    fn polyglot_auto_detect_adds_known_tauri_subdirs() {
        // Repo with no top-level manifest but a Tauri-shaped layout
        // (src-tauri/Cargo.toml + ui/package.json) should auto-add
        // both as scan_roots when no explicit `[project] roots` is set.
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path();
        std::fs::create_dir_all(repo_root.join("src-tauri")).unwrap();
        std::fs::write(
            repo_root.join("src-tauri").join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.0.1\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(repo_root.join("ui")).unwrap();
        std::fs::write(
            repo_root.join("ui").join("package.json"),
            r#"{"name":"x","version":"0.0.1"}"#,
        )
        .unwrap();
        let args = AnalyzeArgs {
            repo: repo_root.to_path_buf(),
            ..default_test_args()
        };
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("scope resolves");
        // Repo root is always present + auto-detected src-tauri + ui.
        assert_eq!(scope.scan_roots.len(), 3);
        assert!(scope.scan_roots.contains(&repo_root.to_path_buf()));
        assert!(scope.scan_roots.contains(&repo_root.join("src-tauri")));
        assert!(scope.scan_roots.contains(&repo_root.join("ui")));
    }

    #[test]
    fn polyglot_auto_detect_gates_per_ecosystem() {
        // Cargo workspace at root with a `ui/package.json` (ci-forge
        // shape): cargo subdir probe is suppressed (root workspace
        // covers its members) but the npm subdir IS still promoted so
        // the Vite/React frontend gets scanned alongside the rust
        // workspace. Inverse holds when root has `package.json` but no
        // `Cargo.toml` (npm monorepo + bundled rust tool).
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path();
        std::fs::write(
            repo_root.join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.0.1\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(repo_root.join("src-tauri")).unwrap();
        std::fs::write(
            repo_root.join("src-tauri").join("Cargo.toml"),
            "[package]\nname = \"y\"\nversion = \"0.0.1\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(repo_root.join("ui")).unwrap();
        std::fs::write(
            repo_root.join("ui").join("package.json"),
            r#"{"name":"x","version":"0.0.1"}"#,
        )
        .unwrap();
        let args = AnalyzeArgs {
            repo: repo_root.to_path_buf(),
            ..default_test_args()
        };
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("scope resolves");
        // Repo root + `ui/` (cargo subdir suppressed because root has
        // Cargo.toml).
        assert_eq!(scope.scan_roots.len(), 2);
        assert!(scope.scan_roots.contains(&repo_root.to_path_buf()));
        assert!(scope.scan_roots.contains(&repo_root.join("ui")));
        assert!(!scope.scan_roots.contains(&repo_root.join("src-tauri")));
    }

    #[test]
    fn polyglot_auto_detect_finds_nested_apps_subdir() {
        // ci-forge shape: rust workspace at root + frontend nested
        // two levels deep at `apps/web/package.json`. The 1-level
        // probe wouldn't find this; the `apps/*` / `packages/*`
        // monorepo nested probe is what makes it reachable.
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path();
        std::fs::write(
            repo_root.join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = []\n",
        )
        .unwrap();
        std::fs::create_dir_all(repo_root.join("apps").join("web")).unwrap();
        std::fs::write(
            repo_root.join("apps").join("web").join("package.json"),
            r#"{"name":"web","version":"0.0.1"}"#,
        )
        .unwrap();
        let args = AnalyzeArgs {
            repo: repo_root.to_path_buf(),
            ..default_test_args()
        };
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("scope resolves");
        assert_eq!(scope.scan_roots.len(), 2);
        assert!(
            scope
                .scan_roots
                .contains(&repo_root.join("apps").join("web"))
        );
    }

    #[test]
    fn polyglot_auto_detect_runs_for_project_dir_invocation() {
        // Regression for the 2026-05-20 dogfood finding: `--project
        // mortar` (Tauri layout) was returning 0 cargo / 0 npm
        // proposals because polyglot detection only fired on the
        // no-project path. The fix runs polyglot in the --project
        // <dir> branch too, so plain `assay analyze --project mortar`
        // sees `src-tauri/` AND `ui/` automatically.
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path();
        std::fs::create_dir_all(repo_root.join("src-tauri")).unwrap();
        std::fs::write(
            repo_root.join("src-tauri").join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.0.1\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(repo_root.join("ui")).unwrap();
        std::fs::write(
            repo_root.join("ui").join("package.json"),
            r#"{"name":"x","version":"0.0.1"}"#,
        )
        .unwrap();
        let args = AnalyzeArgs {
            project: Some(repo_root.to_path_buf()),
            repo: repo_root.to_path_buf(),
            ..default_test_args()
        };
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("scope resolves");
        assert!(scope.scan_roots.contains(&repo_root.join("src-tauri")));
        assert!(scope.scan_roots.contains(&repo_root.join("ui")));
    }

    #[test]
    fn polyglot_auto_detect_skipped_when_config_roots_present() {
        // When the operator HAS set `[project] roots = [...]` explicitly
        // we trust that config completely — no further auto-detection.
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path();
        std::fs::create_dir_all(repo_root.join("src-tauri")).unwrap();
        std::fs::write(
            repo_root.join("src-tauri").join("Cargo.toml"),
            "[package]\nname = \"x\"\nversion = \"0.0.1\"\nedition = \"2021\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(repo_root.join("ui")).unwrap();
        std::fs::write(
            repo_root.join("ui").join("package.json"),
            r#"{"name":"x","version":"0.0.1"}"#,
        )
        .unwrap();
        let args = AnalyzeArgs {
            repo: repo_root.to_path_buf(),
            ..default_test_args()
        };
        let mut config = crate::config::AssayConfig::default();
        // Explicit roots — only `src-tauri/`, NOT `ui/`. Auto-detect
        // must not add `ui/` to the scan_roots even though it exists.
        config.project.roots = vec![PathBuf::from("src-tauri")];
        let scope = ProjectScope::resolve(&args, &config).expect("scope resolves");
        assert_eq!(scope.scan_roots.len(), 2);
        assert!(scope.scan_roots.contains(&repo_root.to_path_buf()));
        assert!(scope.scan_roots.contains(&repo_root.join("src-tauri")));
        assert!(!scope.scan_roots.contains(&repo_root.join("ui")));
    }

    #[test]
    fn project_scope_anchors_artifact_root_at_enclosing_git_root() {
        // When `--project <sub-dir>` points inside a git repo, the
        // artifact_root must climb to the repo top-level so
        // `.assay/runs/...` lands beside the rest of the project's
        // git-managed state, not buried inside the sub-project (see
        // dogfood-tour-2026-05-19 finding N).
        let tmp = tempfile::tempdir().unwrap();
        let repo_root = tmp.path().canonicalize().unwrap();
        // Create the .git marker (a regular file pointer is sufficient
        // — find_enclosing_git_root treats `.git` as "any kind of file
        // or directory exists").
        std::fs::write(repo_root.join(".git"), "gitdir: not-real").unwrap();
        let sub_dir = repo_root.join("ui");
        std::fs::create_dir_all(&sub_dir).unwrap();
        let args = AnalyzeArgs {
            repo: repo_root.clone(),
            project: Some(sub_dir.clone()),
            ..default_test_args()
        };
        let config = crate::config::AssayConfig::default();
        let scope = ProjectScope::resolve(&args, &config).expect("scope resolves");
        // artifact_root climbs to repo_root; scan_root stays at the
        // canonicalized sub_dir.
        assert_eq!(scope.artifact_root, repo_root);
        assert_eq!(scope.scan_roots, vec![sub_dir.canonicalize().unwrap()]);
    }

    /// Default AnalyzeArgs for tests that only care about a few fields.
    fn default_test_args() -> AnalyzeArgs {
        AnalyzeArgs {
            repo: ".".into(),
            ecosystem: None,
            apply_local: false,
            apply_pr: false,
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
        }
    }

    #[test]
    fn parse_cache_ttl_accepts_supported_units() {
        use std::time::Duration;
        assert_eq!(parse_cache_ttl("90s"), Ok(Duration::from_secs(90)));
        assert_eq!(parse_cache_ttl("30m"), Ok(Duration::from_secs(30 * 60)));
        assert_eq!(parse_cache_ttl("2h"), Ok(Duration::from_secs(2 * 60 * 60)));
        assert_eq!(parse_cache_ttl("7d"), Ok(Duration::from_secs(7 * 86400)));
        assert_eq!(parse_cache_ttl("1w"), Ok(Duration::from_secs(7 * 86400)));
    }

    #[test]
    fn parse_cache_ttl_rejects_empty_and_garbage() {
        assert!(parse_cache_ttl("").is_err());
        assert!(parse_cache_ttl("abc").is_err());
        assert!(parse_cache_ttl("1y").is_err(), "year unit not supported");
        assert!(
            parse_cache_ttl("1h30m").is_err(),
            "compound durations not supported"
        );
        assert!(parse_cache_ttl("-30s").is_err(), "negative values rejected");
    }

    #[test]
    fn parse_cache_ttl_bare_number_treated_as_seconds() {
        // `300` (no suffix) is parsed as seconds — keeps cache_ttl=300
        // round-trippable with the verdict_cache module's internal repr.
        assert_eq!(
            parse_cache_ttl("300"),
            Ok(std::time::Duration::from_secs(300))
        );
    }

    #[test]
    fn parse_cli_accepts_no_cache_flag() {
        let cli = parse_cli(["assay", "analyze", "--no-cache"]);
        let Command::Analyze(args) = cli.command;
        assert!(args.no_cache);
    }

    #[test]
    fn parse_cli_accepts_cache_ttl_flag() {
        let cli = parse_cli(["assay", "analyze", "--cache-ttl", "2h"]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(args.cache_ttl, "2h");
    }

    #[test]
    fn parse_cli_defaults_cache_ttl_to_seven_days() {
        let cli = parse_cli(["assay", "analyze"]);
        let Command::Analyze(args) = cli.command;
        assert_eq!(args.cache_ttl, "7d");
        assert!(!args.no_cache);
    }

    #[test]
    fn parse_cli_accepts_explain_flag() {
        let cli = parse_cli(["assay", "analyze", "--explain"]);
        let Command::Analyze(args) = cli.command;
        assert!(args.explain);
    }

    #[test]
    fn parse_cli_explain_defaults_to_false() {
        let cli = parse_cli(["assay", "analyze"]);
        let Command::Analyze(args) = cli.command;
        assert!(!args.explain);
    }

    #[test]
    fn populate_explanations_fills_cargo_proposals() {
        use crate::model::{BumpTier, ProposalKind};
        let mut proposals = vec![Proposal {
            id: "cargo-serde-1-0-228".into(),
            ecosystem: "cargo".into(),
            kind: ProposalKind::Version,
            subject: "serde".into(),
            from: "1.0.100".into(),
            to: "1.0.228".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: vec![],
            explanation: None,
            cohort: None,
        }];
        populate_proposal_explanations(&mut proposals, "cargo");
        let exp = proposals[0]
            .explanation
            .as_ref()
            .expect("--explain should attach a BumpExplanation");
        assert_eq!(exp.rule, "cargo:caret-major-1-plus");
        assert_eq!(exp.decision, "compatible");
    }

    #[test]
    fn populate_explanations_fills_gha_proposals() {
        use crate::model::{BumpTier, ProposalKind};
        let mut proposals = vec![Proposal {
            id: "gha-actions-checkout-v4".into(),
            ecosystem: "github-actions".into(),
            kind: ProposalKind::ActionPin,
            subject: "actions/checkout".into(),
            from: "v3.5.2".into(),
            to: "v4.0.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Breaking,
            affected_consumers: vec![],
            explanation: None,
            cohort: None,
        }];
        populate_proposal_explanations(&mut proposals, "github-actions");
        let exp = proposals[0].explanation.as_ref().unwrap();
        assert_eq!(exp.rule, "gha:major-bump");
        assert_eq!(exp.decision, "breaking");
    }

    #[test]
    fn populate_explanations_uses_lockfile_only_explainer_for_lockfile_tier() {
        use crate::model::{BumpTier, ProposalKind};
        let mut proposals = vec![Proposal {
            id: "cargo-clap-4-5-1".into(),
            ecosystem: "cargo".into(),
            kind: ProposalKind::Version,
            subject: "clap".into(),
            from: "4.5.0".into(),
            to: "4.5.1".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::LockfileOnly,
            affected_consumers: vec![],
            explanation: None,
            cohort: None,
        }];
        populate_proposal_explanations(&mut proposals, "cargo");
        let exp = proposals[0].explanation.as_ref().unwrap();
        assert_eq!(exp.rule, "cargo:lockfile-within-constraint");
        assert_eq!(exp.decision, "lockfile-only");
    }

    #[test]
    fn populate_explanations_leaves_unknown_ecosystem_untouched() {
        use crate::model::{BumpTier, ProposalKind};
        let mut proposals = vec![Proposal {
            id: "fictional-x-1".into(),
            ecosystem: "fictional".into(),
            kind: ProposalKind::Version,
            subject: "x".into(),
            from: "1.0.0".into(),
            to: "1.0.1".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: vec![],
            explanation: None,
            cohort: None,
        }];
        populate_proposal_explanations(&mut proposals, "fictional");
        assert!(proposals[0].explanation.is_none());
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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
        };
        let validator = build_validator(&args, &args.repo).expect("gate-cmd should always build");
        // CustomBackend reports `needs_workflow_file() == false`, so the
        // validator runs the gate command once against the tree using a
        // synthetic workflow path. With `make test` (the gate) failing on
        // an empty tempdir, we expect a real failure conclusion — what
        // we're verifying here is that the backend was actually invoked,
        // not the no-workflows "unvalidated" stub that the previous
        // implementation returned.
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
                    affected_consumers: Vec::new(),
                    explanation: None,
                    cohort: None,
                },
                tmp.path(),
                &[],
            )
            .unwrap();
        assert_ne!(
            outcome.conclusion, "unvalidated",
            "CustomBackend must run even when no workflows exist; got {outcome:?}",
        );
        assert_eq!(outcome.validated_workflows.len(), 1);
        let displayed = outcome.validated_workflows[0].display().to_string();
        assert!(
            displayed.starts_with("<tree:"),
            "synthetic workflow path expected, got {displayed}",
        );
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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
        };
        // Just needs to not error during construction.
        build_validator(&args, &args.repo).expect("gate-file should always build");
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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
        };
        // forge may or may not be on PATH; what matters is that the
        // empty dir gives no manifest and no workflows. On a dev box
        // where forge is missing the auto-selector errors immediately;
        // when forge IS on PATH the auto-selector falls to the
        // BuildTestBackend::infer step which also returns None.
        // If for some reason a backend was selectable on this host
        // (unlikely in an empty tempdir), that's fine — the test
        // proves construction works either way.
        if let Err(err) = build_validator(&args, &args.repo) {
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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
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

    /// Builds a `Validator` whose backend is a never-invoked CustomBackend.
    /// Used by `perform_apply_local_commit` tests where the merge step
    /// either doesn't fire (size-1 set, red-count short-circuit) or is
    /// declared redundant by the ecosystem (cargo all-LockfileOnly).
    fn test_validator_unused() -> crate::validator::Validator {
        crate::validator::Validator::with_backend(Box::new(crate::validator::CustomBackend::new(
            vec!["__assay_test_never_invoked__".into()],
        )))
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
            affected_consumers: Vec::new(),
            explanation: None,
            cohort: None,
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
            failure_details: Vec::new(),
            cached_workflow_count: 0,
            total_workflow_count: 0,
            member_skipped_workflow_count: 0,
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
            scan_root: repo.to_path_buf(),
        }];
        let mut provenance = crate::model::Provenance::default();

        let validator = test_validator_unused();
        let summary = perform_apply_local_commit(
            repo,
            &registry,
            &mut completed_runs,
            0,
            &mut provenance,
            &validator,
            "assay-test-run",
        )
        .expect("apply-local commit should succeed");

        match summary {
            CommitSummary::Committed {
                bump_count,
                paths,
                subject,
                merged_drops,
            } => {
                assert_eq!(bump_count, 1);
                assert_eq!(paths, vec![PathBuf::from("Cargo.lock")]);
                assert!(
                    subject.starts_with("chore(deps): bump serde from 1.0.200 to 1.0.215"),
                    "subject should describe the single bump: {subject}"
                );
                assert!(
                    merged_drops.is_empty(),
                    "single-proposal apply has no drops"
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
                scan_root: std::path::PathBuf::new(),
            },
            ProposalRun {
                eco_idx: 0,
                proposal: crate::model::Proposal {
                    id: "cargo-tokio-1-x".into(),
                    ..sample_cargo_proposal_for_apply()
                },
                sandbox: sandbox_tmp.path().to_path_buf(),
                outcome: sample_outcome("failure"),
                scan_root: std::path::PathBuf::new(),
            },
        ];
        let mut provenance = crate::model::Provenance::default();

        let validator = test_validator_unused();
        let summary = perform_apply_local_commit(
            repo,
            &registry,
            &mut completed_runs,
            0,
            &mut provenance,
            &validator,
            "assay-test-run",
        )
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
        // Labels the test claims exist on the repo. Defaults to empty
        // (no labels exist) so older tests don't need to be aware of the
        // label filter at all.
        existing_labels: Vec<String>,
        // Collaborator usernames the test claims exist on the repo.
        // Same default rationale as existing_labels.
        existing_collaborators: Vec<String>,
        // Sink for label-create attempts so tests can assert what the
        // publisher tried to provision.
        created_labels: std::sync::Mutex<Vec<String>>,
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

        fn list_labels(
            &self,
            _owner: &str,
            _repo: &str,
        ) -> std::result::Result<Vec<String>, crate::publisher::BackendError> {
            Ok(self.existing_labels.clone())
        }

        fn list_collaborators(
            &self,
            _owner: &str,
            _repo: &str,
        ) -> std::result::Result<Vec<String>, crate::publisher::BackendError> {
            Ok(self.existing_collaborators.clone())
        }

        fn create_label(
            &self,
            _owner: &str,
            _repo: &str,
            name: &str,
        ) -> std::result::Result<(), crate::publisher::BackendError> {
            // Append to the mock's labels so subsequent list_labels would
            // include it; mirrors the live behavior. Records the create
            // attempt in `created_labels` so tests can assert.
            self.created_labels.lock().unwrap().push(name.to_string());
            Ok(())
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
            scan_root: std::path::PathBuf::new(),
        }];
        let mut provenance = crate::model::Provenance::default();
        let backend = MockPrBackend {
            opened: std::sync::Mutex::new(Vec::new()),
            metadata: crate::publisher::BranchMetadata {
                name: "assay/cargo/serde-1-0-215-placeholder".into(),
                is_default: false,
                is_protected: false,
            },
            existing_labels: Vec::new(),
            existing_collaborators: Vec::new(),
            created_labels: std::sync::Mutex::new(Vec::new()),
        };

        let validator = test_validator_unused();
        let summary = perform_apply_pr(
            &repo,
            &registry,
            &mut completed_runs,
            0,
            &mut provenance,
            &backend,
            "origin",
            "assay-test-run-pushed",
            &validator,
            &[],
            &[],
            false,
        )
        .expect("apply-pr should succeed");

        match summary {
            ApplyPrSummary::Published {
                url,
                branch,
                bump_count,
                merged_drops,
            } => {
                assert_eq!(bump_count, 1);
                assert!(branch.starts_with("assay/cargo/serde-"));
                assert!(url.contains("/pull/"));
                assert!(
                    merged_drops.is_empty(),
                    "single-proposal apply has no drops"
                );
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
            scan_root: std::path::PathBuf::new(),
        }];
        let mut provenance = crate::model::Provenance::default();
        let backend = MockPrBackend {
            opened: std::sync::Mutex::new(Vec::new()),
            metadata: crate::publisher::BranchMetadata {
                name: "x".into(),
                is_default: false,
                is_protected: false,
            },
            existing_labels: Vec::new(),
            existing_collaborators: Vec::new(),
            created_labels: std::sync::Mutex::new(Vec::new()),
        };

        let validator = test_validator_unused();
        let summary = perform_apply_pr(
            &repo,
            &registry,
            &mut completed_runs,
            0,
            &mut provenance,
            &backend,
            "origin",
            "assay-test-run-refused",
            &validator,
            &[],
            &[],
            false,
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
            scan_root: std::path::PathBuf::new(),
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
            existing_labels: Vec::new(),
            existing_collaborators: Vec::new(),
            created_labels: std::sync::Mutex::new(Vec::new()),
        };

        let validator = test_validator_unused();
        let err = perform_apply_pr(
            &repo,
            &registry,
            &mut completed_runs,
            0,
            &mut provenance,
            &backend,
            "origin",
            "assay-test-run-protected",
            &validator,
            &[],
            &[],
            false,
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

    // ----- format_worktree_add_failure ------------------------------------

    #[test]
    fn worktree_add_failure_passes_through_unrelated_errors() {
        let msg = format_worktree_add_failure(
            "assay/cargo/serde-1-0-215",
            "fatal: could not switch to directory",
        );
        assert!(msg.contains("could not switch to directory"));
        assert!(
            !msg.contains("delete the branch"),
            "no remediation hint when stderr doesn't mention 'already exists'"
        );
    }

    #[test]
    fn worktree_add_failure_appends_remediation_when_branch_already_exists() {
        let msg = format_worktree_add_failure(
            "assay/multi/3-abc",
            "fatal: a branch named 'assay/multi/3-abc' already exists",
        );
        assert!(msg.contains("already exists"));
        assert!(
            msg.contains("git branch -D assay/multi/3-abc"),
            "should include the exact branch-delete recipe: {msg}"
        );
        assert!(
            msg.contains("git push <remote> --delete assay/multi/3-abc"),
            "should include the remote-cleanup recipe: {msg}"
        );
    }

    // ----- cleanup_local_apply_state / PartialApplyState ------------------

    /// Set up a real git repo with one commit, then add a worktree on
    /// a new branch. Returns (repo_tempdir, repo_path, branch, worktree_path).
    fn setup_repo_with_worktree(
        branch: &str,
    ) -> (
        tempfile::TempDir,
        std::path::PathBuf,
        String,
        std::path::PathBuf,
    ) {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().to_path_buf();
        init_git_repo(&repo);
        std::fs::write(repo.join("README.md"), "test\n").unwrap();
        git(&repo, ["add", "README.md"]);
        git(&repo, ["commit", "-m", "init"]);
        let worktree = repo.join(".assay-test-worktree");
        let status = std::process::Command::new("git")
            .args(["worktree", "add", "-b", branch])
            .arg(&worktree)
            .arg("HEAD")
            .current_dir(&repo)
            .status()
            .expect("git worktree add must execute");
        assert!(status.success(), "git worktree add must succeed");
        assert!(worktree.exists(), "worktree dir should exist after add");
        (tmp, repo, branch.to_string(), worktree)
    }

    fn local_branch_exists(repo: &std::path::Path, branch: &str) -> bool {
        let out = std::process::Command::new("git")
            .args(["rev-parse", "--verify", "--quiet"])
            .arg(format!("refs/heads/{branch}"))
            .current_dir(repo)
            .status()
            .expect("git rev-parse must execute");
        out.success()
    }

    #[test]
    fn cleanup_removes_worktree_and_local_branch() {
        let (_tmp, repo, branch, worktree) = setup_repo_with_worktree("assay/test-cleanup-1");
        assert!(
            local_branch_exists(&repo, &branch),
            "branch should exist pre-cleanup"
        );
        cleanup_local_apply_state(&repo, Some(&worktree), Some(&branch));
        assert!(!worktree.exists(), "worktree dir should be removed");
        assert!(
            !local_branch_exists(&repo, &branch),
            "local branch should be removed"
        );
    }

    #[test]
    fn cleanup_with_no_state_is_noop() {
        // No worktree, no branch — should not panic, should not error.
        let tmp = tempfile::tempdir().unwrap();
        init_git_repo(tmp.path());
        cleanup_local_apply_state(tmp.path(), None, None);
    }

    #[test]
    fn partial_apply_state_drop_runs_cleanup_when_not_dismissed() {
        let (_tmp, repo, branch, worktree) = setup_repo_with_worktree("assay/test-cleanup-drop");
        {
            let mut partial = PartialApplyState::new(repo.clone());
            partial.track_local(worktree.clone(), branch.clone());
            // partial drops at the end of this block without dismiss
        }
        assert!(!worktree.exists(), "Drop should have removed the worktree");
        assert!(
            !local_branch_exists(&repo, &branch),
            "Drop should have removed the local branch"
        );
    }

    #[test]
    fn partial_apply_state_dismiss_preserves_local_state() {
        let (_tmp, repo, branch, worktree) = setup_repo_with_worktree("assay/test-cleanup-dismiss");
        {
            let mut partial = PartialApplyState::new(repo.clone());
            partial.track_local(worktree.clone(), branch.clone());
            partial.dismiss();
            // Drop runs at end of dismiss but success=true so no-op.
        }
        assert!(
            worktree.exists(),
            "dismiss should have preserved the worktree (audit trail)"
        );
        assert!(
            local_branch_exists(&repo, &branch),
            "dismiss should have preserved the local branch"
        );
    }

    #[test]
    fn partial_apply_state_dismiss_quietly_still_cleans_up() {
        let (_tmp, repo, branch, worktree) = setup_repo_with_worktree("assay/test-cleanup-quiet");
        {
            let mut partial = PartialApplyState::new(repo.clone());
            partial.track_local(worktree.clone(), branch.clone());
            partial.dismiss_quietly();
        }
        assert!(
            !worktree.exists(),
            "dismiss_quietly should still clean up the worktree"
        );
        assert!(
            !local_branch_exists(&repo, &branch),
            "dismiss_quietly should still clean up the local branch"
        );
    }

    // ----- ensure_labels_exist --------------------------------------------

    /// Backend stub that returns a static label list (or an error).
    struct LabelListBackend {
        labels: std::result::Result<Vec<String>, crate::publisher::BackendError>,
        // `ensure_labels_exist` will call `create_label` for every label
        // not present in `labels`. This field lets the test configure
        // whether those creates succeed or fail.
        create_result: std::result::Result<(), crate::publisher::BackendError>,
        // Records every label name `create_label` was invoked with so
        // tests can assert what the publisher tried to provision.
        created: std::sync::Mutex<Vec<String>>,
    }

    impl crate::publisher::PullRequestBackend for LabelListBackend {
        fn fetch_branch_metadata(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> std::result::Result<crate::publisher::BranchMetadata, crate::publisher::BackendError>
        {
            unreachable!("ensure_labels_exist must not call fetch_branch_metadata")
        }
        fn open_pull_request(
            &self,
            _: &crate::publisher::PullRequestRequest,
        ) -> std::result::Result<
            crate::publisher::PullRequestResponse,
            crate::publisher::BackendError,
        > {
            unreachable!("ensure_labels_exist must not call open_pull_request")
        }
        fn list_labels(
            &self,
            _: &str,
            _: &str,
        ) -> std::result::Result<Vec<String>, crate::publisher::BackendError> {
            match &self.labels {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(match e {
                    crate::publisher::BackendError::Network(s) => {
                        crate::publisher::BackendError::Network(s.clone())
                    }
                    crate::publisher::BackendError::Auth(s) => {
                        crate::publisher::BackendError::Auth(s.clone())
                    }
                    crate::publisher::BackendError::NotConfigured(s) => {
                        crate::publisher::BackendError::NotConfigured(s.clone())
                    }
                    crate::publisher::BackendError::Rejected(s) => {
                        crate::publisher::BackendError::Rejected(s.clone())
                    }
                }),
            }
        }
        fn list_collaborators(
            &self,
            _: &str,
            _: &str,
        ) -> std::result::Result<Vec<String>, crate::publisher::BackendError> {
            // Not used by ensure_labels tests; the matching filter_reviewers
            // tests use CollaboratorListBackend below.
            unreachable!("ensure_labels tests must not call list_collaborators")
        }
        fn create_label(
            &self,
            _: &str,
            _: &str,
            name: &str,
        ) -> std::result::Result<(), crate::publisher::BackendError> {
            match &self.create_result {
                Ok(()) => {
                    self.created.lock().unwrap().push(name.to_string());
                    Ok(())
                }
                Err(e) => Err(match e {
                    crate::publisher::BackendError::Network(s) => {
                        crate::publisher::BackendError::Network(s.clone())
                    }
                    crate::publisher::BackendError::Auth(s) => {
                        crate::publisher::BackendError::Auth(s.clone())
                    }
                    crate::publisher::BackendError::NotConfigured(s) => {
                        crate::publisher::BackendError::NotConfigured(s.clone())
                    }
                    crate::publisher::BackendError::Rejected(s) => {
                        crate::publisher::BackendError::Rejected(s.clone())
                    }
                }),
            }
        }
    }

    #[test]
    fn ensure_labels_returns_empty_when_no_labels_requested() {
        let backend = LabelListBackend {
            labels: Ok(vec!["assay".into()]),
            create_result: Ok(()),
            created: std::sync::Mutex::new(Vec::new()),
        };
        let out = ensure_labels_exist(&backend, "o", "r", &[]);
        assert!(out.is_empty());
        assert!(
            backend.created.lock().unwrap().is_empty(),
            "no labels requested -> no creates attempted"
        );
    }

    #[test]
    fn ensure_labels_keeps_existing_without_attempting_create() {
        let backend = LabelListBackend {
            labels: Ok(vec!["assay".into(), "bug".into()]),
            create_result: Ok(()),
            created: std::sync::Mutex::new(Vec::new()),
        };
        let out = ensure_labels_exist(&backend, "o", "r", &["assay".into(), "bug".into()]);
        assert_eq!(out, vec!["assay".to_string(), "bug".to_string()]);
        assert!(
            backend.created.lock().unwrap().is_empty(),
            "all labels already exist; nothing should be created"
        );
    }

    #[test]
    fn ensure_labels_auto_creates_missing_when_create_succeeds() {
        let backend = LabelListBackend {
            labels: Ok(vec!["assay".into()]),
            create_result: Ok(()),
            created: std::sync::Mutex::new(Vec::new()),
        };
        let out = ensure_labels_exist(
            &backend,
            "o",
            "r",
            &["assay".into(), "dependencies".into(), "automerge".into()],
        );
        assert_eq!(
            out,
            vec![
                "assay".to_string(),
                "dependencies".to_string(),
                "automerge".to_string(),
            ],
            "kept order: existing first then auto-created"
        );
        assert_eq!(
            *backend.created.lock().unwrap(),
            vec!["dependencies".to_string(), "automerge".to_string()],
            "only the missing labels should be created"
        );
    }

    #[test]
    fn ensure_labels_drops_labels_whose_create_fails() {
        let backend = LabelListBackend {
            labels: Ok(vec!["assay".into()]),
            create_result: Err(crate::publisher::BackendError::Rejected(
                "no permission to create labels".into(),
            )),
            created: std::sync::Mutex::new(Vec::new()),
        };
        let out = ensure_labels_exist(&backend, "o", "r", &["assay".into(), "dependencies".into()]);
        assert_eq!(
            out,
            vec!["assay".to_string()],
            "existing label survives; missing+create-fail label dropped"
        );
        assert!(
            backend.created.lock().unwrap().is_empty(),
            "no labels recorded as created when create_label returned Err"
        );
    }

    #[test]
    fn ensure_labels_drops_all_when_list_labels_errors() {
        let backend = LabelListBackend {
            labels: Err(crate::publisher::BackendError::Network("503".into())),
            // Create would succeed if asked, but list_labels failure
            // short-circuits before we even know what's missing.
            create_result: Ok(()),
            created: std::sync::Mutex::new(Vec::new()),
        };
        let out = ensure_labels_exist(&backend, "o", "r", &["assay".into()]);
        assert!(
            out.is_empty(),
            "on list_labels error the publisher drops all labels for forward progress"
        );
        assert!(
            backend.created.lock().unwrap().is_empty(),
            "no creates should be attempted when we couldn't list existing labels"
        );
    }

    // ----- check_insteadof_rewrite ---------------------------------------

    #[test]
    fn insteadof_check_passes_when_key_absent() {
        assert!(check_insteadof_rewrite(None).is_ok());
    }

    #[test]
    fn insteadof_check_passes_when_key_value_is_empty() {
        assert!(check_insteadof_rewrite(Some("")).is_ok());
        assert!(check_insteadof_rewrite(Some("   \n")).is_ok());
    }

    #[test]
    fn insteadof_check_refuses_with_remediation_when_key_set_to_clean_github_url() {
        let err = check_insteadof_rewrite(Some("https://github.com/"))
            .expect_err("broken rewrite must be refused");
        assert!(
            err.contains("git config --global --unset"),
            "remediation should suggest unset: {err}"
        );
        assert!(
            err.contains("--force"),
            "remediation should mention --force workaround: {err}"
        );
        assert!(
            err.contains(BROKEN_INSTEADOF_KEY),
            "remediation should name the exact broken key: {err}"
        );
    }

    #[test]
    fn insteadof_check_handles_multi_valued_config_with_trailing_newline() {
        // `git config --get-all` separates multiple values with newlines.
        let value = "https://github.com/\nhttps://github.com/somewhereelse/\n";
        let err = check_insteadof_rewrite(Some(value))
            .expect_err("any non-empty value of the broken key should fail");
        assert!(err.contains("https://github.com/"));
    }

    // ----- filter_reviewers_to_collaborators ------------------------------

    /// Backend stub that returns a configurable collaborator list (or
    /// an error). `list_labels`/etc. panic — these tests don't touch
    /// label or PR-open paths.
    struct CollaboratorListBackend {
        collaborators: std::result::Result<Vec<String>, crate::publisher::BackendError>,
    }

    impl crate::publisher::PullRequestBackend for CollaboratorListBackend {
        fn fetch_branch_metadata(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> std::result::Result<crate::publisher::BranchMetadata, crate::publisher::BackendError>
        {
            unreachable!("filter_reviewers tests must not call fetch_branch_metadata")
        }
        fn open_pull_request(
            &self,
            _: &crate::publisher::PullRequestRequest,
        ) -> std::result::Result<
            crate::publisher::PullRequestResponse,
            crate::publisher::BackendError,
        > {
            unreachable!("filter_reviewers tests must not call open_pull_request")
        }
        fn list_labels(
            &self,
            _: &str,
            _: &str,
        ) -> std::result::Result<Vec<String>, crate::publisher::BackendError> {
            unreachable!("filter_reviewers tests must not call list_labels")
        }
        fn list_collaborators(
            &self,
            _: &str,
            _: &str,
        ) -> std::result::Result<Vec<String>, crate::publisher::BackendError> {
            match &self.collaborators {
                Ok(v) => Ok(v.clone()),
                Err(e) => Err(match e {
                    crate::publisher::BackendError::Network(s) => {
                        crate::publisher::BackendError::Network(s.clone())
                    }
                    crate::publisher::BackendError::Auth(s) => {
                        crate::publisher::BackendError::Auth(s.clone())
                    }
                    crate::publisher::BackendError::NotConfigured(s) => {
                        crate::publisher::BackendError::NotConfigured(s.clone())
                    }
                    crate::publisher::BackendError::Rejected(s) => {
                        crate::publisher::BackendError::Rejected(s.clone())
                    }
                }),
            }
        }
        fn create_label(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> std::result::Result<(), crate::publisher::BackendError> {
            unreachable!("filter_reviewers tests must not call create_label")
        }
    }

    #[test]
    fn filter_reviewers_returns_empty_when_none_requested() {
        let backend = CollaboratorListBackend {
            collaborators: Ok(vec!["alice".into()]),
        };
        let out = filter_reviewers_to_collaborators(&backend, "o", "r", &[]);
        assert!(out.is_empty());
    }

    #[test]
    fn filter_reviewers_drops_non_collaborator_users() {
        let backend = CollaboratorListBackend {
            collaborators: Ok(vec!["alice".into(), "bob".into()]),
        };
        let out = filter_reviewers_to_collaborators(
            &backend,
            "o",
            "r",
            &["alice".into(), "carol".into(), "bob".into()],
        );
        assert_eq!(
            out,
            vec!["alice".to_string(), "bob".to_string()],
            "should keep collaborators, drop non-collaborators"
        );
    }

    #[test]
    fn filter_reviewers_passes_team_reviewers_through_without_collab_check() {
        // Teams are `org/team` — they go to a different GitHub endpoint
        // and the assignability rules differ. The filter must NOT drop
        // them on collaborator absence. The mock's list_collaborators
        // shouldn't even be consulted when all reviewers are teams,
        // but if it is, returning empty must still let the team pass.
        let backend = CollaboratorListBackend {
            collaborators: Ok(Vec::new()),
        };
        let out = filter_reviewers_to_collaborators(&backend, "o", "r", &["wildmason/core".into()]);
        assert_eq!(out, vec!["wildmason/core".to_string()]);
    }

    #[test]
    fn filter_reviewers_mixed_keeps_teams_and_extant_users() {
        let backend = CollaboratorListBackend {
            collaborators: Ok(vec!["alice".into()]),
        };
        let out = filter_reviewers_to_collaborators(
            &backend,
            "o",
            "r",
            &[
                "wildmason/security".into(),
                "alice".into(),
                "ghost-user".into(),
            ],
        );
        assert_eq!(
            out,
            vec!["wildmason/security".to_string(), "alice".to_string()]
        );
    }

    #[test]
    fn filter_reviewers_on_list_error_drops_users_keeps_teams() {
        // Mirrors the label-filter fallback: on `list_collaborators`
        // error, drop user-level reviewers (we can't verify them safely)
        // but pass team reviewers through (they don't depend on the
        // collaborator check).
        let backend = CollaboratorListBackend {
            collaborators: Err(crate::publisher::BackendError::Network("503".into())),
        };
        let out = filter_reviewers_to_collaborators(
            &backend,
            "o",
            "r",
            &["alice".into(), "wildmason/core".into()],
        );
        assert_eq!(
            out,
            vec!["wildmason/core".to_string()],
            "user reviewers dropped on error, team reviewers preserved"
        );
    }

    // ----- preflight_apply_pr_gh_auth -------------------------------------

    fn make_gh_fixture(tmp: &std::path::Path, stdout: &str, exit_code: i32) -> std::path::PathBuf {
        if cfg!(windows) {
            let p = tmp.join("gh.cmd");
            std::fs::write(
                &p,
                format!("@echo off\necho {stdout}\nexit /b {exit_code}\n"),
            )
            .unwrap();
            p
        } else {
            let p = tmp.join("gh");
            std::fs::write(
                &p,
                format!("#!/bin/sh\nprintf '%s\\n' '{stdout}'\nexit {exit_code}\n"),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&p).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&p, perms).unwrap();
            }
            p
        }
    }

    #[test]
    fn preflight_apply_pr_gh_auth_succeeds_with_repo_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = make_gh_fixture(tmp.path(), "Token scopes: 'repo', 'workflow'", 0);
        let backend = GhCliBackend::new(gh);
        preflight_apply_pr_gh_auth(&backend).expect("repo-scoped fixture should pass preflight");
    }

    #[test]
    fn preflight_apply_pr_gh_auth_fails_when_gh_exits_nonzero() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = make_gh_fixture(tmp.path(), "not logged in", 1);
        let backend = GhCliBackend::new(gh);
        let err = preflight_apply_pr_gh_auth(&backend)
            .expect_err("unauthenticated fixture should fail preflight");
        let msg = err.to_string();
        assert!(
            msg.contains("apply-pr") || msg.contains("--apply-pr"),
            "error should mention apply-pr context: {msg}"
        );
        assert!(
            msg.contains("gh auth login") || msg.contains("--force"),
            "error should include a remediation hint: {msg}"
        );
    }

    #[test]
    fn preflight_apply_pr_gh_auth_fails_when_repo_scope_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let gh = make_gh_fixture(tmp.path(), "Token scopes: 'gist'", 0);
        let backend = GhCliBackend::new(gh);
        let err = preflight_apply_pr_gh_auth(&backend)
            .expect_err("missing repo scope should fail preflight");
        let msg = err.to_string();
        assert!(
            msg.contains("apply-pr") || msg.contains("--apply-pr"),
            "error should mention apply-pr context: {msg}"
        );
        assert!(
            msg.contains("repo"),
            "error should reference the missing repo scope: {msg}"
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
                    scan_root: repo.to_path_buf(),
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
                    scan_root: repo.to_path_buf(),
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
                    scan_root: repo.to_path_buf(),
                },
            ];
            let mut provenance = crate::model::Provenance::default();
            let validator = test_validator_unused();
            perform_apply_local_commit(
                repo,
                &registry,
                &mut completed_runs,
                0,
                &mut provenance,
                &validator,
                "assay-test-run",
            )
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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
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
            validate: false,
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
            quiet: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
        };
        let cargo = crate::ecosystem::cargo::CargoEcosystem;
        let gha = crate::ecosystem::github_actions::GitHubActionsEcosystem;
        assert!(ecosystem_enabled(&args, &cargo));
        assert!(!ecosystem_enabled(&args, &gha));
    }
}
