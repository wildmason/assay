//! CLI surface for `assay`.
//!
//! Module map:
//!
//! - [`args`] — clap-derived flag types and the [`ApplyMode`] enum
//!   derived from them. The public stability promise covers the
//!   types re-exported here (`Cli`, `Command`, `AnalyzeArgs`).
//! - This file (`cli/mod.rs`) — entry-point glue (`run`, `dispatch`,
//!   `parse_cli`) plus the orchestration code that will continue
//!   being broken out into focused submodules as the refactor
//!   progresses.

pub mod args;
mod apply_local;
mod apply_pr;
mod config_resolve;
mod git_ops;
mod paths;
mod polyglot;
mod project_scope;
mod reporting;
mod run_state;
mod text_report;
mod time_utils;
mod work_unit;

pub use args::*;
pub use config_resolve::parse_cache_ttl;

use apply_local::perform_apply_local_commit;
use apply_pr::{perform_apply_pr, preflight_apply_pr_gh_auth, preflight_apply_pr_insteadof};
use config_resolve::{
    build_validator, ecosystem_enabled, populate_proposal_explanations, resolve_ignore_list,
    workflow_filter_from_args, zero_manifest_hint,
};
#[cfg(test)]
use config_resolve::parse_cli_ignore;
#[cfg(test)]
use text_report::missing_cargo_lock_warning;
use git_ops::working_tree_dirty_path;
#[cfg(test)]
use git_ops::prepare_apply_local_tree;
#[cfg(test)]
use apply_pr::{
    BROKEN_INSTEADOF_KEY, PartialApplyState, check_insteadof_rewrite, cleanup_local_apply_state,
    ensure_labels_exist, filter_reviewers_to_collaborators, format_worktree_add_failure,
};
#[cfg(test)]
use git_ops::{partition_stageable_paths, porcelain_line_is_assay_artifact};
use paths::{forward_slash_path, relative_prefix, strip_extended_length_prefix};
use project_scope::{ProjectScope, capture_run_context};
use reporting::{
    aggregate_cache_counts, aggregate_member_skipped_count, build_failure_clusters,
    format_failure_clusters_section, format_red_proposal_section, print_discovered_section,
    ship_counts, tier_counts,
};
#[cfg(test)]
use reporting::format_consumers_suffix;
use run_state::{
    ApplyPrSummary, CommitSummary, PreValidationFailureRow, ProposalRun, WorkUnit, WorkerOutcome,
};
use text_report::report_text;
use time_utils::{generate_run_id, iso8601_now};
use work_unit::{build_work_units, emit_run_started_event, process_proposal_unit};

use std::path::PathBuf;
use std::process::ExitCode;

use crate::ecosystem::{EcosystemContext, default_registry};
#[cfg(test)]
use crate::ecosystem::DependencyEcosystem;
use crate::error::{Error, Result};
use crate::model::{
    AssayRunReceipt, Classification, Proposal, Provenance, ProvenanceRecord, RepositoryRef,
    RunSummary,
};
#[cfg(test)]
use crate::model::{Manifest, ManifestKind};
use crate::publisher::gh_cli::GhCliBackend;
use crate::receipt::write_run_receipt;
use crate::worker_pool::{Semaphore, WorkerContext, WorkerPool};

use clap::Parser;
use std::sync::{Arc, Mutex};


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


fn analyze_command(args: AnalyzeArgs) -> Result<()> {
    let mut args = args;
    // Parse `--dep <name>@<version>` upfront so a malformed spec fails
    // before any IO. `None` means "run the discovery proposer normally"
    // (the prior behavior); `Some((name, version))` short-circuits each
    // ecosystem's discovery in favor of a synthetic single-proposal path.
    let dep_target: Option<(String, String)> = match args.dep.as_deref() {
        Some(spec) => Some(parse_dep_spec(spec).map_err(Error::other)?),
        None => None,
    };
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
                    sha_pin_proposals: !args.no_sha_pin_proposals,
                };
                let mut proposals = if let Some((dep_name, dep_version)) = &dep_target {
                    // `--dep` bypasses the discovery proposer in favor of a
                    // synthesized single-proposal path: the ecosystem reads
                    // the dep's current pin from manifest/lockfile state
                    // and builds one Proposal with `from = current,
                    // to = <operator-supplied>`. Ecosystems that don't
                    // support `--dep` (currently github-actions, whose
                    // `<subject>@<ref>` shape isn't a version) inherit the
                    // default `Ok(None)` and contribute nothing here.
                    match ecosystem.synthesize_dep_proposal(
                        dep_name,
                        dep_version,
                        &manifests,
                        scan_root,
                        &context,
                    )? {
                        Some(p) => vec![p],
                        None => Vec::new(),
                    }
                } else {
                    ecosystem.propose_updates(&manifests, scan_root, &context)?
                };
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

    // Build the event sink up-front so RunStarted can fire before
    // the worker pool spins. The sink is a no-op for Text/Json
    // formats, so pipeline code can always call emit() without
    // branching on output format.
    let ndjson_sink = crate::events::NdjsonStdoutSink::new();
    let noop_sink = crate::events::NoopEventSink;
    let event_sink_ref: &dyn crate::events::EventSink =
        if matches!(args.format, OutputFormat::Ndjson) {
            &ndjson_sink
        } else {
            &noop_sink
        };
    if matches!(args.format, OutputFormat::Ndjson) {
        emit_run_started_event(
            event_sink_ref,
            &run_id,
            &started_at,
            &args,
            &registry,
            &all_proposals,
        );
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

        let units: Vec<WorkUnit> = build_work_units(&all_proposals, &registry);

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
            event_sink: event_sink_ref,
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
                    || matches!(
                        outcome,
                        WorkerOutcome::CohortCompleted { outcome, .. } if outcome.conclusion != "success"
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
                WorkerOutcome::CohortCompleted {
                    eco_idx,
                    members,
                    sandbox,
                    outcome,
                    provenance: pr_records,
                    scan_root,
                } => {
                    // The shared outcome attributes to EVERY member.
                    // One per-member ProposalRun is pushed, all
                    // sharing the same sandbox path — the merger's
                    // shared-sandbox detection skips the redundant
                    // re-merge for cohort groups.
                    provenance.records.extend(pr_records);
                    let n = members.len();
                    match outcome.conclusion.as_str() {
                        "success" => proposals_passed += n,
                        "unvalidated" => proposals_unvalidated += n,
                        _ => proposals_failed += n,
                    }
                    for member in members {
                        completed_runs.push(ProposalRun {
                            eco_idx,
                            proposal: member,
                            sandbox: sandbox.clone(),
                            outcome: outcome.clone(),
                            scan_root: scan_root.clone(),
                        });
                    }
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

    // Compute root-cause clusters across the failed proposals so the
    // NDJSON `run_completed` event and the text report can both
    // surface "N proposals share this failure". cluster_failures
    // drops singletons by design.
    let failure_clusters = build_failure_clusters(&completed_runs);

    if matches!(args.format, OutputFormat::Ndjson) {
        event_sink_ref.emit(crate::events::Event::RunCompleted {
            summary: crate::events::EventSummary {
                proposals_total: receipt.summary.proposals_total,
                proposals_passed: receipt.summary.proposals_passed,
                proposals_failed: receipt.summary.proposals_failed,
                proposals_unvalidated: receipt.summary.proposals_unvalidated,
                proposals_shipped: receipt.summary.proposals_shipped,
            },
            run_json_path: run_json_path.display().to_string(),
            finished_at: receipt.finished_at.clone(),
            failure_clusters: failure_clusters.clone(),
        });
    }

    // `--dep` mode and no proposal produced means the dep wasn't declared
    // in any enabled ecosystem at this repo. Surface a single clear
    // explanation to stderr so the operator doesn't read "0 proposal(s)"
    // and assume the dep already passes — it just wasn't found anywhere
    // worth checking. Ecosystem-level "already at target" notices fired
    // earlier from synthesize_dep_proposal stderr lines.
    if let Some((dep_name, dep_version)) = &dep_target
        && all_proposals.is_empty()
    {
        eprintln!(
            "[dep] {dep_name}@{dep_version}: not declared in any enabled ecosystem at this repo, \
             or already pinned at the requested version. Nothing to validate.",
        );
    }

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
            // 1.6.0: surface root-cause clusters at the end of the
            // run when two or more proposals failed for the same
            // reason. Singletons are excluded by `cluster_failures`.
            if let Some(cluster_section) = format_failure_clusters_section(&failure_clusters) {
                print!("{cluster_section}");
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
                    failure_context: Some(crate::failure_parser::parse(
                        stderr,
                        crate::failure_parser::EcosystemHint::Auto,
                    )),
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

    // ----- build_work_units (cohort-aware grouping) ----------------------

    fn sample_proposal_for_unit(id: &str, subject: &str, cohort: Option<&str>) -> Proposal {
        use crate::model::{BumpTier, ProposalKind};
        Proposal {
            id: id.into(),
            ecosystem: "npm".into(),
            kind: ProposalKind::Version,
            subject: subject.into(),
            from: "1.0.0".into(),
            to: "2.0.0".into(),
            initial_classification: Classification::Exact,
            manifest_paths: vec![],
            notes: vec![],
            bump_tier: BumpTier::Compatible,
            affected_consumers: vec![],
            explanation: None,
            cohort: cohort.map(str::to_string),
        }
    }

    fn npm_eco_idx_in(registry: &[Box<dyn DependencyEcosystem>]) -> usize {
        registry
            .iter()
            .position(|e| e.name() == "npm")
            .expect("default_registry should include npm")
    }

    #[test]
    fn build_work_units_collapses_multi_member_cohort_into_one_unit() {
        let registry = default_registry();
        let npm_idx = npm_eco_idx_in(&registry);
        let scan_root = PathBuf::from("/repo");
        let all_proposals = vec![
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-1", "@angular/core", Some("angular-framework")),
            ),
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-2", "@angular/common", Some("angular-framework")),
            ),
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-3", "@angular/router", Some("angular-framework")),
            ),
        ];
        let units = build_work_units(&all_proposals, &registry);
        assert_eq!(
            units.len(),
            1,
            "three lockstep members should collapse into ONE work unit"
        );
        let unit = &units[0];
        // Primary is the proposal with the lowest id (deterministic).
        assert_eq!(unit.proposal.id, "npm-1");
        assert_eq!(unit.lockstep_members.len(), 2);
        let sibling_ids: Vec<&str> = unit
            .lockstep_members
            .iter()
            .map(|p| p.id.as_str())
            .collect();
        assert_eq!(sibling_ids, vec!["npm-2", "npm-3"]);
    }

    #[test]
    fn build_work_units_keeps_non_cohort_proposals_individual() {
        let registry = default_registry();
        let npm_idx = npm_eco_idx_in(&registry);
        let scan_root = PathBuf::from("/repo");
        let all_proposals = vec![
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-ts", "typescript", None),
            ),
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-lo", "lodash", None),
            ),
        ];
        let units = build_work_units(&all_proposals, &registry);
        assert_eq!(units.len(), 2);
        for unit in &units {
            assert!(
                unit.lockstep_members.is_empty(),
                "non-cohort proposals must not carry lockstep_members"
            );
        }
    }

    #[test]
    fn build_work_units_singleton_cohort_stays_individual() {
        let registry = default_registry();
        let npm_idx = npm_eco_idx_in(&registry);
        let scan_root = PathBuf::from("/repo");
        let all_proposals = vec![(
            npm_idx,
            scan_root.clone(),
            sample_proposal_for_unit("npm-1", "@angular/core", Some("angular-framework")),
        )];
        let units = build_work_units(&all_proposals, &registry);
        assert_eq!(units.len(), 1);
        assert!(
            units[0].lockstep_members.is_empty(),
            "singleton cohort has no lockstep partner — must be individual"
        );
    }

    #[test]
    fn build_work_units_isolates_different_scan_roots() {
        // Same cohort id in two different scan_roots (Tauri-style
        // polyglot: ui/ and admin/) must NOT collapse — each scan
        // root is its own apply target and gets its own work unit.
        let registry = default_registry();
        let npm_idx = npm_eco_idx_in(&registry);
        let scan_ui = PathBuf::from("/repo/ui");
        let scan_admin = PathBuf::from("/repo/admin");
        let all_proposals = vec![
            (
                npm_idx,
                scan_ui.clone(),
                sample_proposal_for_unit("npm-ui-1", "@angular/core", Some("angular-framework")),
            ),
            (
                npm_idx,
                scan_ui.clone(),
                sample_proposal_for_unit("npm-ui-2", "@angular/common", Some("angular-framework")),
            ),
            (
                npm_idx,
                scan_admin.clone(),
                sample_proposal_for_unit("npm-ad-1", "@angular/core", Some("angular-framework")),
            ),
            (
                npm_idx,
                scan_admin.clone(),
                sample_proposal_for_unit("npm-ad-2", "@angular/common", Some("angular-framework")),
            ),
        ];
        let units = build_work_units(&all_proposals, &registry);
        assert_eq!(units.len(), 2, "two scan_roots → two cohort units");
        for unit in &units {
            assert_eq!(unit.lockstep_members.len(), 1, "two-member cohort per root");
        }
    }

    #[test]
    fn build_work_units_isolates_different_cohorts_in_same_scan_root() {
        let registry = default_registry();
        let npm_idx = npm_eco_idx_in(&registry);
        let scan_root = PathBuf::from("/repo");
        let all_proposals = vec![
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-1", "@angular/core", Some("angular-framework")),
            ),
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-2", "@angular/common", Some("angular-framework")),
            ),
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-3", "@tiptap/core", Some("tiptap")),
            ),
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-4", "@tiptap/starter-kit", Some("tiptap")),
            ),
            (
                npm_idx,
                scan_root.clone(),
                sample_proposal_for_unit("npm-ts", "typescript", None),
            ),
        ];
        let units = build_work_units(&all_proposals, &registry);
        // Expect 3 units: angular cohort (2 members → 1 unit),
        // tiptap cohort (2 members → 1 unit), typescript (solo).
        assert_eq!(units.len(), 3);
        let lockstep_sizes: Vec<usize> =
            units.iter().map(|u| 1 + u.lockstep_members.len()).collect();
        let mut sizes_sorted = lockstep_sizes.clone();
        sizes_sorted.sort();
        assert_eq!(sizes_sorted, vec![1, 2, 2]);
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
    fn build_failure_clusters_groups_runs_with_shared_root_cause() {
        // Two proposals failing with the same rustc error → one
        // cluster covering both. A third proposal failing for a
        // distinct reason stays out (singletons dropped).
        let shared_stderr =
            "error[E0277]: the trait `Foo` is not implemented\n  --> src/a.rs:1:1\n";
        let runs = vec![
            red_run("p-a", "x", "1.0", "2.0", "REGRESSION", shared_stderr),
            red_run("p-b", "y", "1.0", "2.0", "REGRESSION", shared_stderr),
            red_run(
                "p-c",
                "z",
                "1.0",
                "2.0",
                "REGRESSION",
                "error[E0308]: mismatched types\n  --> src/c.rs:99:1\n",
            ),
        ];
        let clusters = build_failure_clusters(&runs);
        assert_eq!(clusters.len(), 1, "expected one cluster; got {clusters:?}");
        assert_eq!(clusters[0].proposal_ids, vec!["p-a", "p-b"]);
    }

    #[test]
    fn build_failure_clusters_returns_empty_when_no_shared_failures() {
        // Three distinct failures → no clusters (singletons dropped).
        let runs = vec![
            red_run("p-a", "x", "1", "2", "REGRESSION", "error[E0277]: a"),
            red_run("p-b", "y", "1", "2", "REGRESSION", "error[E0308]: b"),
            red_run("p-c", "z", "1", "2", "REGRESSION", "error[E0599]: c"),
        ];
        let clusters = build_failure_clusters(&runs);
        assert!(clusters.is_empty());
    }

    #[test]
    fn build_failure_clusters_skips_passing_and_unvalidated_runs() {
        let runs = vec![
            green_run("p-green-1"),
            green_run("p-green-2"),
            red_run("p-red", "x", "1", "2", "REGRESSION", "error[E0277]: alone"),
        ];
        let clusters = build_failure_clusters(&runs);
        // One red, no shared fingerprints → no clusters.
        assert!(clusters.is_empty());
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
        // 1.6.0: raw stderr lives under "raw log (...)" — the
        // structured failure context renders above it. The E0599
        // code shows up in both renderings.
        assert!(out.contains("raw log (custom):"));
        assert!(out.contains("E0599"));
        // The structured context line lifts the rule name +
        // summary so the operator sees the parsed error inline.
        assert!(
            out.contains("[cargo:rustc-error]"),
            "expected structured rule line; got: {out}"
        );
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
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
            no_sha_pin_proposals: false,
            offline: false,
            refresh_cache: false,
            ignore: Vec::new(),
            no_cache: false,
            cache_ttl: "7d".into(),
            explain: false,
            member_gate: false,
            dep: None,
        };
        let cargo = crate::ecosystem::cargo::CargoEcosystem;
        let gha = crate::ecosystem::github_actions::GitHubActionsEcosystem;
        assert!(ecosystem_enabled(&args, &cargo));
        assert!(!ecosystem_enabled(&args, &gha));
    }
}
