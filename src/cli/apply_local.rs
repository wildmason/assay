//! `--apply-local` post-validation commit phase.
//!
//! Once the worker pool finishes validating every proposal, this
//! module's [`perform_apply_local_commit`] decides whether to ship
//! anything to the host repo:
//!
//! - any red proposal → refuse (preserves the atomic
//!   "all-individually-green" precondition of `--apply-local`);
//! - all green → run the multi-proposal merge applier per ecosystem
//!   (collapsing partial-conflict surprises into a deterministic
//!   ship plan), then copy back and create one atomic commit on
//!   the current branch.
//!
//! [`build_ship_plan_from_runs`] is the borrow-shape wrapper around
//! [`crate::apply_merger::build_ship_plan`] and is re-used by
//! [`super::apply_pr`].

use std::path::{Path, PathBuf};

use crate::ecosystem::DependencyEcosystem;
use crate::error::{Error, Result};
use crate::model::{Classification, Proposal, Provenance, ProvenanceRecord};
use crate::sanitize::sanitize_commit_subject;
use crate::validator::Validator;

use super::git_ops::{emit_gitignored_skip_warning, git_add_paths, git_commit};
use super::paths::relative_prefix;
use super::run_state::{CommitSummary, MergedDropInfo, ProposalRun};

/// Run the post-validation commit phase for `--apply-local`.
///
/// Per plan §C.6.a: validate all proposals first, then if every proposal
/// validated green, sort by proposal ID (Conc-9), copy-back each from
/// its sandbox to the host tree, and create one atomic commit. If any
/// proposal didn't validate green (failure, unvalidated, or pre-apply
/// failure), refuse to commit — the user can re-run after fixing the
/// failing proposals.
pub(super) fn perform_apply_local_commit(
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
pub(super) fn build_commit_body(
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
/// ecosystem ship plan. Thin wrapper so the orchestrator/apply pipelines
/// hold the borrow shape (constructing the &[RunRef] view) and
/// apply_merger owns the merge algorithm.
pub(super) fn build_ship_plan_from_runs(
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
