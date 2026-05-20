//! Worker fan-out: turn the flat proposal stream into work units
//! (with cohort lockstep collapsed), drive each unit through
//! sandbox-prep → apply → gate → validate, and emit progress events.
//!
//! The orchestrator (`mod.rs::analyze_command`) hands this module a
//! list of `(ecosystem_idx, scan_root, proposal)` triples. We:
//!
//! 1. Group by `(eco_idx, scan_root, cohort_id)` — multi-member
//!    cohort buckets collapse into a single [`WorkUnit`] whose
//!    worker applies every sibling to one sandbox.
//! 2. Run each unit through the per-proposal lifecycle in
//!    [`process_proposal_unit`].
//! 3. Stream NDJSON events ([`emit_run_started_event`],
//!    `ProposalValidating`, `ProposalCompleted`, `CohortValidating`,
//!    `CohortCompleted`) so GUIs / sidecars can render live status.

use std::path::{Path, PathBuf};

use crate::ecosystem::DependencyEcosystem;
use crate::model::{Classification, Proposal, ProvenanceRecord};
use crate::validator::Validator;
use crate::worker_pool::WorkerContext;

use super::args::AnalyzeArgs;
use super::config_resolve::ecosystem_enabled;
use super::git_ops::prepare_apply_local_tree;
use super::paths::{forward_slash_path, strip_extended_length_prefix};
use super::run_state::{WorkUnit, WorkerOutcome};

/// Group `all_proposals` into work units honoring cohort lockstep.
///
/// Within each `(eco_idx, scan_root, cohort_id)` triple where the
/// cohort has ≥2 members, ALL members merge into a single
/// `WorkUnit` whose worker will apply them atomically to one
/// sandbox and validate the combined state. Other proposals (no
/// cohort, or singleton cohorts) get one `WorkUnit` each — existing
/// behavior unchanged.
///
/// Determinism: cohort members are sorted by proposal id so the
/// "primary" (`unit.proposal`) is stable across re-runs; sibling
/// order is also stable. The output unit list is in deterministic
/// scan order.
pub(super) fn build_work_units(
    all_proposals: &[(usize, PathBuf, Proposal)],
    registry: &[Box<dyn DependencyEcosystem>],
) -> Vec<WorkUnit> {
    use std::collections::BTreeMap;

    // Bucket by (eco_idx, scan_root, cohort) — non-cohort entries
    // get a unique synthetic bucket key so they remain individual
    // work units.
    type Key = (usize, PathBuf, Option<String>);
    let mut buckets: BTreeMap<Key, Vec<(usize, &Proposal)>> = BTreeMap::new();
    for (idx, (eco_idx, scan_root, proposal)) in all_proposals.iter().enumerate() {
        let cohort = proposal.cohort.clone();
        let key = if cohort.is_some() {
            (*eco_idx, scan_root.clone(), cohort)
        } else {
            // Synthetic per-proposal bucket key so each non-cohort
            // proposal stays in its own unit. Use the proposal index
            // to guarantee uniqueness; the cohort slot carries a
            // synthesized "__solo:<idx>" marker that no real cohort
            // id can collide with (real cohort ids match
            // `[a-z][a-z0-9-]+`).
            (*eco_idx, scan_root.clone(), Some(format!("__solo:{idx}")))
        };
        buckets.entry(key).or_default().push((idx, proposal));
    }

    let mut units: Vec<WorkUnit> = Vec::new();
    for ((eco_idx, scan_root, cohort_slot), mut entries) in buckets {
        // Stable order: sort by proposal id so primary selection is
        // deterministic. (Buckets are already BTreeMap-ordered;
        // entries within a bucket may have been pushed in any
        // order.)
        entries.sort_by(|a, b| a.1.id.cmp(&b.1.id));
        let is_solo_bucket = cohort_slot
            .as_deref()
            .is_some_and(|s| s.starts_with("__solo:"));
        if is_solo_bucket || entries.len() < 2 {
            for (_, proposal) in entries {
                units.push(WorkUnit {
                    eco_idx,
                    ecosystem_name: registry[eco_idx].name(),
                    proposal: proposal.clone(),
                    lockstep_members: Vec::new(),
                    scan_root: scan_root.clone(),
                });
            }
        } else {
            // Multi-member real cohort: first is primary, rest are
            // lockstep_members. The worker applies all atomically.
            let mut iter = entries.into_iter();
            let primary = iter.next().unwrap().1.clone();
            let siblings: Vec<Proposal> = iter.map(|(_, p)| p.clone()).collect();
            units.push(WorkUnit {
                eco_idx,
                ecosystem_name: registry[eco_idx].name(),
                proposal: primary,
                lockstep_members: siblings,
                scan_root: scan_root.clone(),
            });
        }
    }
    units
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
pub(super) fn process_proposal_unit(
    unit: WorkUnit,
    validator: &Validator,
    registry: &[Box<dyn DependencyEcosystem>],
    artifact_root: &Path,
    run_id: &str,
    ctx: &WorkerContext<'_>,
) -> WorkerOutcome {
    let mut records: Vec<ProvenanceRecord> = Vec::new();
    let ecosystem = registry[unit.eco_idx].as_ref();
    // Emit the work-starting event so the GUI flips the row(s)
    // from `pending` to `in_progress`. Cohort lockstep groups
    // emit `CohortValidating` with the full member list; single-
    // proposal units emit `ProposalValidating`. The `Completed`
    // counterpart fires at the bottom of this function with
    // duration_ms so the GUI can render elapsed times.
    let worker_started = std::time::Instant::now();
    if unit.lockstep_members.is_empty() {
        ctx.event_sink
            .emit(crate::events::Event::ProposalValidating {
                id: unit.proposal.id.clone(),
                subject: unit.proposal.subject.clone(),
            });
    } else {
        let cohort_id = unit.proposal.cohort.clone().unwrap_or_default();
        let display = cohort_display_name(&cohort_id);
        let member_ids: Vec<String> = std::iter::once(unit.proposal.id.clone())
            .chain(unit.lockstep_members.iter().map(|p| p.id.clone()))
            .collect();
        ctx.event_sink.emit(crate::events::Event::CohortValidating {
            cohort: cohort_id,
            display,
            member_ids,
        });
    }

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

    // Cohort lockstep: apply primary + every sibling to the SAME
    // sandbox. Single-proposal units (the common case) flow through
    // the `apply_proposal` path; multi-member cohort units use
    // `apply_merged` so the per-bump state is composed atomically.
    let apply_result = if unit.lockstep_members.is_empty() {
        ecosystem.apply_proposal(&unit.proposal, &apply_tree)
    } else {
        let mut all: Vec<&Proposal> = Vec::with_capacity(1 + unit.lockstep_members.len());
        all.push(&unit.proposal);
        for sibling in &unit.lockstep_members {
            all.push(sibling);
        }
        ecosystem.apply_merged(&all, &apply_tree)
    };
    if let Err(err) = apply_result {
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
        // For cohort lockstep failures, surface a PreValidationFailure
        // for EACH member so the reporter accounts for them all.
        // The simple variant only carries one `proposal`; we keep the
        // primary in this slot and append additional records for each
        // sibling so the receipt has full provenance.
        if !unit.lockstep_members.is_empty() {
            for sibling in &unit.lockstep_members {
                records.push(ProvenanceRecord {
                    tool: "assay".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    stage: format!("applier.{}", ecosystem.name()),
                    subject: sibling.id.clone(),
                    status: Classification::Unsupported,
                    summary: format!("cohort-lockstep apply failed: {err}"),
                    artifact_path: None,
                    details: None,
                });
            }
        }
        return WorkerOutcome::PreValidationFailure {
            eco_idx: unit.eco_idx,
            proposal: unit.proposal,
            provenance: records,
            summary,
        };
    }
    if unit.lockstep_members.is_empty() {
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
    } else {
        let member_ids: Vec<String> = std::iter::once(unit.proposal.id.clone())
            .chain(unit.lockstep_members.iter().map(|p| p.id.clone()))
            .collect();
        records.push(ProvenanceRecord {
            tool: "assay".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            stage: format!("applier.{}.cohort-lockstep", ecosystem.name()),
            subject: format!(
                "{} + {} sibling(s)",
                unit.proposal.subject,
                unit.lockstep_members.len()
            ),
            status: Classification::Exact,
            summary: format!(
                "applied {} cohort member(s) atomically to sandbox worktree",
                1 + unit.lockstep_members.len()
            ),
            artifact_path: None,
            details: Some(serde_json::json!({
                "sandbox": apply_tree,
                "cohort": unit.proposal.cohort,
                "members": member_ids,
            })),
        });
    }

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
    let duration_ms = u64::try_from(worker_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if unit.lockstep_members.is_empty() {
        ctx.event_sink
            .emit(crate::events::Event::ProposalCompleted {
                id: unit.proposal.id.clone(),
                subject: unit.proposal.subject.clone(),
                conclusion: outcome.conclusion.clone(),
                duration_ms,
            });
        WorkerOutcome::Completed {
            eco_idx: unit.eco_idx,
            proposal: unit.proposal,
            sandbox: apply_tree,
            outcome,
            provenance: records,
            scan_root,
        }
    } else {
        // Same outcome attaches to every cohort member. The
        // aggregator expands this into N `ProposalRun`s — one per
        // member, all sharing the same sandbox so the merger's
        // shared-sandbox check skips the redundant re-merge step.
        let mut members: Vec<Proposal> = Vec::with_capacity(1 + unit.lockstep_members.len());
        members.push(unit.proposal);
        members.extend(unit.lockstep_members);
        let cohort_id = members[0].cohort.clone().unwrap_or_default();
        let member_ids: Vec<String> = members.iter().map(|p| p.id.clone()).collect();
        ctx.event_sink.emit(crate::events::Event::CohortCompleted {
            cohort: cohort_id,
            conclusion: outcome.conclusion.clone(),
            member_ids,
            duration_ms,
        });
        WorkerOutcome::CohortCompleted {
            eco_idx: unit.eco_idx,
            members,
            sandbox: apply_tree,
            outcome,
            provenance: records,
            scan_root,
        }
    }
}

/// Emit the `RunStarted` NDJSON event with the full proposal
/// inventory + cohort groupings. The GUI uses this to render the
/// pending list before any validation begins, including the visual
/// affordance grouping cohort members under one container. Called
/// only when `args.format == Ndjson`; otherwise the sink would be
/// a no-op anyway, but skipping the construction avoids the
/// per-proposal cloning when the data is destined for `/dev/null`.
pub(super) fn emit_run_started_event(
    sink: &dyn crate::events::EventSink,
    run_id: &str,
    started_at: &str,
    args: &AnalyzeArgs,
    registry: &[Box<dyn DependencyEcosystem>],
    all_proposals: &[(usize, std::path::PathBuf, Proposal)],
) {
    use std::collections::BTreeMap;

    let ecosystems: Vec<String> = registry
        .iter()
        .filter(|eco| ecosystem_enabled(args, eco.as_ref()))
        .map(|eco| eco.name().to_string())
        .collect();

    let proposals: Vec<crate::events::EventProposal> = all_proposals
        .iter()
        .map(|(_, _, p)| crate::events::EventProposal {
            id: p.id.clone(),
            subject: p.subject.clone(),
            from: p.from.clone(),
            to: p.to.clone(),
            tier: p.bump_tier.as_str().to_string(),
            ecosystem: p.ecosystem.clone(),
            cohort: p.cohort.clone(),
        })
        .collect();

    // Cohort groupings: bucket proposals by cohort id, keep only
    // multi-member buckets (singleton-cohort proposals don't form
    // a lockstep unit).
    let mut by_cohort: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (_, _, p) in all_proposals {
        if let Some(c) = p.cohort.as_deref() {
            by_cohort
                .entry(c.to_string())
                .or_default()
                .push(p.id.clone());
        }
    }
    let cohorts: Vec<crate::events::EventCohort> = by_cohort
        .into_iter()
        .filter(|(_, members)| members.len() >= 2)
        .map(|(id, member_ids)| crate::events::EventCohort {
            display: cohort_display_name(&id),
            id,
            member_ids,
        })
        .collect();

    let repository = args
        .repo
        .canonicalize()
        .map(strip_extended_length_prefix)
        .map(forward_slash_path)
        .unwrap_or_else(|_| args.repo.clone())
        .display()
        .to_string();

    sink.emit(crate::events::Event::RunStarted {
        run_id: run_id.to_string(),
        started_at: started_at.to_string(),
        repository,
        ecosystems,
        proposals,
        cohorts,
    });
}

/// Map a cohort id to its display name by consulting both ecosystem
/// cohort registries. Returns the id itself when not found (rare —
/// only happens if someone constructs a proposal with a cohort id
/// outside the known registry). The dual-registry lookup is fine
/// because cohort ids are namespaced by ecosystem-flavor convention
/// (npm uses `@scope`-style/`-framework` suffixes; cargo uses bare
/// crate-family names) and don't collide in practice.
pub(super) fn cohort_display_name(cohort_id: &str) -> String {
    if let Some(c) = crate::ecosystem::npm_cohorts::KNOWN_COHORTS
        .iter()
        .find(|c| c.id == cohort_id)
    {
        return c.display.to_string();
    }
    if let Some(c) = crate::ecosystem::cargo_cohorts::KNOWN_COHORTS
        .iter()
        .find(|c| c.id == cohort_id)
    {
        return c.display.to_string();
    }
    cohort_id.to_string()
}
